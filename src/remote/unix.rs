//! Remote thin-client launcher over SSH command stdio.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::Deserialize;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const BRIDGE_ACCEPT_POLL: Duration = Duration::from_millis(50);
const BRIDGE_SOCKET_PERMISSION_MODE: u32 = 0o600;
const REMOTE_SERVER_SHUTDOWN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const REMOTE_SERVER_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);
// The FULL build version (channel-suffixed for mx/preview builds) — every parity check
// here must use this, not CARGO_PKG_VERSION: the remote binary reports the suffixed
// version, so a bare comparison made suffixed builds reject their own installs.
const CURRENT_VERSION: &str = crate::build_info::FULL_VERSION;
const CURRENT_PROTOCOL: u32 = crate::protocol::PROTOCOL_VERSION;
const UPDATE_MANIFEST_URL: &str = "https://herdr.dev/latest.json";
const REMOTE_BINARY_ENV_VAR: &str = "HERDR_REMOTE_BINARY";
// When set to "1", an override binary (`HERDR_REMOTE_BINARY`) with no sibling `.minisig` is refused
// instead of seeded with a warning — for operators who want every seeded binary signature-verified.
const REMOTE_BINARY_REQUIRE_SIG_ENV_VAR: &str = "HERDR_REMOTE_BINARY_REQUIRE_SIGNATURE";
const REMOTE_BRIDGE_PROBE_ENV_VAR: &str = "HERDR_REMOTE_BRIDGE_PROBE";
pub(crate) const REATTACH_COMMAND_ENV_VAR: &str = "HERDR_REATTACH_COMMAND";
pub(crate) const MAIN_DISPLAY_NAME_ENV_VAR: &str = "HERDR_MAIN_DISPLAY_NAME";
pub(crate) const MAIN_REMOTE_TARGET_ENV_VAR: &str = "HERDR_MAIN_REMOTE_TARGET";

pub(crate) const REMOTE_KEYBINDINGS_ENV_VAR: &str = "HERDR_REMOTE_KEYBINDINGS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteKeybindings {
    Local,
    Server,
}

impl RemoteKeybindings {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "local" => Ok(Self::Local),
            "server" => Ok(Self::Server),
            _ => Err("--remote-keybindings must be 'local' or 'server'".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Server => "server",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteLaunch {
    pub(crate) target: String,
    pub(crate) keybindings: RemoteKeybindings,
    pub(crate) live_handoff: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteBridgeKind {
    Client,
    Api,
}

impl RemoteBridgeKind {
    fn subcommand(self) -> &'static str {
        match self {
            Self::Client => "remote-client-bridge",
            Self::Api => "remote-api-bridge",
        }
    }

    fn path_label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Api => "api",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteBridgePaths {
    client_socket: PathBuf,
    api_socket: PathBuf,
}

pub(crate) struct RemoteBridge {
    client_socket: PathBuf,
    api_socket: PathBuf,
    _client_bridge: Option<SshStdioBridge>,
    _api_bridge: Option<SshStdioBridge>,
}

impl RemoteBridge {
    pub(crate) fn client_socket_path(&self) -> &Path {
        &self.client_socket
    }

    pub(crate) fn api_socket_path(&self) -> &Path {
        &self.api_socket
    }

    #[cfg(test)]
    pub(crate) fn from_socket_paths_for_test(client_socket: PathBuf, api_socket: PathBuf) -> Self {
        Self {
            client_socket,
            api_socket,
            _client_bridge: None,
            _api_bridge: None,
        }
    }
}

pub(crate) fn extract_remote_args(
    args: &[String],
) -> Result<(Vec<String>, Option<RemoteLaunch>), String> {
    let mut cleaned = Vec::with_capacity(args.len());
    if let Some(program) = args.first() {
        cleaned.push(program.clone());
    }

    let mut remote_target = None;
    let mut keybindings = RemoteKeybindings::Local;
    let mut keybindings_seen = false;
    let mut live_handoff = false;
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--handoff" {
            live_handoff = true;
            index += 1;
            continue;
        }
        if arg == "--remote" {
            if remote_target.is_some() {
                return Err("--remote can only be specified once".to_string());
            }
            let Some(value) = args.get(index + 1) else {
                return Err("missing value for --remote".to_string());
            };
            remote_target = Some(validate_remote_target(value)?.to_owned());
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--remote=") {
            if remote_target.is_some() {
                return Err("--remote can only be specified once".to_string());
            }
            remote_target = Some(validate_remote_target(value)?.to_owned());
            index += 1;
            continue;
        }
        if arg == "--remote-keybindings" {
            if keybindings_seen {
                return Err("--remote-keybindings can only be specified once".to_string());
            }
            let Some(value) = args.get(index + 1) else {
                return Err("missing value for --remote-keybindings".to_string());
            };
            keybindings = RemoteKeybindings::parse(value)?;
            keybindings_seen = true;
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--remote-keybindings=") {
            if keybindings_seen {
                return Err("--remote-keybindings can only be specified once".to_string());
            }
            keybindings = RemoteKeybindings::parse(value)?;
            keybindings_seen = true;
            index += 1;
            continue;
        }

        cleaned.push(arg.clone());
        index += 1;
    }

    let remote = remote_target.map(|target| RemoteLaunch {
        target,
        keybindings,
        live_handoff,
    });
    if remote.is_none() && keybindings_seen {
        return Err("--remote-keybindings requires --remote".to_string());
    }
    if remote.is_none() && live_handoff {
        cleaned.push("--handoff".to_string());
    }

    Ok((cleaned, remote))
}

fn validate_remote_target(target: &str) -> Result<&str, String> {
    if target.is_empty() {
        return Err("missing value for --remote".to_string());
    }
    if target.starts_with('-') {
        return Err("--remote target must not start with '-'".to_string());
    }
    Ok(target)
}

pub(crate) fn run_remote(remote: RemoteLaunch) -> io::Result<()> {
    let session_name = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_string());
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "herdr".to_string());
    let reattach_command = reattach_command(
        &program,
        &remote.target,
        &session_name,
        remote.keybindings,
        remote.live_handoff,
    );
    // The CLI `--remote <host>` path is always a bare destination (leading-`-` is rejected by
    // `validate_remote_target`), so there are no extra ssh options to carry.
    let ssh_target = SshTarget::bare(&remote.target);
    // CLI path: echo each provisioning stage to stderr so a slow seed reads as progress.
    let progress = |stage: RemoteProvisionStage| eprintln!("herdr: {}", stage.label());
    let prepared_remote = prepare_remote_herdr(
        &ssh_target,
        remote.live_handoff,
        false, // add-remote reuses a version-matching binary; only the "update" button forces
        RemotePrepPolicy::Interactive,
        &progress,
    )?;
    progress(RemoteProvisionStage::StartingServer);
    ensure_remote_server_ready(
        &ssh_target,
        &prepared_remote.remote_herdr,
        prepared_remote.installed_or_replaced,
        remote.live_handoff,
        RemotePrepPolicy::Interactive,
    )?;

    progress(RemoteProvisionStage::Attaching);
    let bridge = start_ssh_remote_bridge_with_prepared(
        &ssh_target,
        &session_name,
        prepared_remote.remote_herdr,
    )?;

    run_client_process(
        bridge.client_socket_path(),
        bridge.api_socket_path(),
        &reattach_command,
        remote.keybindings,
        &remote.target,
    )
}

/// A resolved ssh connection: the destination plus any user-supplied ssh options that must
/// precede it (e.g. `-L`, `-J`, `-p`, `-o`). The destination alone is the dedup / socket-path /
/// display key; the options are emitted on every ssh invocation so port-forwards and jump hosts
/// from a full ssh add-remote spec actually take effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshTarget {
    destination: String,
    options: Vec<String>,
}

impl SshTarget {
    pub(crate) fn new(destination: impl Into<String>, options: Vec<String>) -> Self {
        Self {
            destination: destination.into(),
            options,
        }
    }

    /// A bare destination with no extra ssh options (the `herdr --remote <host>` CLI path).
    pub(crate) fn bare(destination: impl Into<String>) -> Self {
        Self::new(destination, Vec::new())
    }

    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }

    /// Build `ssh <options...> -T <destination> <remote_command>`. `-T` (disable pseudo-tty) is
    /// inserted before the destination unless the user already supplied it; the herdr payload is
    /// always the trailing positional so it runs on the remote rather than being parsed as an
    /// ssh option.
    fn command(&self, remote_command: &str) -> Command {
        let mut command = Command::new("ssh");
        // Bound the connect phase so an unreachable host fails fast instead of stalling for the OS
        // TCP timeout. Skip if the user already pinned a ConnectTimeout in their own options.
        if !self
            .options
            .iter()
            .any(|opt| opt.contains("ConnectTimeout"))
        {
            command.arg("-o").arg("ConnectTimeout=10");
        }
        // herdr's ssh sessions are pure exec/stdio channels and never need the port forwards
        // the user's ssh_config sets up for interactive use. Inheriting LocalForward/
        // RemoteForward breaks every probe and bridge when the forward port is already held —
        // typically by the user's own interactive session to the same host, or by herdr's own
        // bridge to a sibling host forwarding the same port ("ssh works by hand, but
        // add-remote sticks at connecting") — with `bind: Address already in use`. Clear them
        // the way scp does, unless the user explicitly asked this herdr connection to forward.
        let user_forwards = self.options.iter().any(|opt| {
            opt.contains("ClearAllForwardings")
                || opt.starts_with("-L")
                || opt.starts_with("-R")
                || opt.starts_with("-D")
        });
        if !user_forwards {
            command.arg("-o").arg("ClearAllForwardings=yes");
        }
        command.args(&self.options);
        if !self.options.iter().any(|opt| opt == "-T") {
            command.arg("-T");
        }
        command.arg(&self.destination);
        command.arg(remote_command);
        command
    }
}

/// How `prepare_remote_herdr` / `ensure_remote_server_ready` resolve the install + restart
/// decisions on a remote host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemotePrepPolicy {
    /// `herdr --remote` from a shell: prompt on a TTY, refuse without one.
    Interactive,
    /// The in-client add-remote worker: never read stdin (the TUI owns it in raw mode, so any
    /// `read_line` would hang invisibly). Auto-approve installing herdr on a fresh host, prefer
    /// live-handoff for an out-of-date running server, and refuse to silently hard-stop a remote
    /// server that cannot hand off — unless `restart_incompatible` is set, which means the user
    /// explicitly approved stopping an incompatible no-handoff server (issue #12, macmini).
    NonInteractive { restart_incompatible: bool },
}

/// Typed signal (wrapped in an `io::Error`) that a non-interactive attach hit an incompatible
/// remote server that cannot live-handoff. The client downcasts this to show a y/N restart prompt
/// instead of a dead-end error, then retries with `restart_incompatible = true`.
#[derive(Debug, Clone)]
pub(crate) struct RestartConfirmNeeded {
    pub(crate) destination: String,
    pub(crate) version: Option<String>,
    pub(crate) protocol: Option<u32>,
}

impl std::fmt::Display for RestartConfirmNeeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} runs an older herdr (v{} protocol {}) that can't live-handoff. Restart it with the updated herdr? This interrupts its running panes.",
            self.destination,
            version_label(self.version.as_deref()),
            protocol_label(self.protocol)
        )
    }
}

impl std::error::Error for RestartConfirmNeeded {}

/// If `err` carries a [`RestartConfirmNeeded`] signal, borrow it.
pub(crate) fn restart_confirm_needed(err: &io::Error) -> Option<&RestartConfirmNeeded> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<RestartConfirmNeeded>())
}

/// Coarse step of preparing a remote host for attach, surfaced to the user while add-remote runs.
/// The in-client dialog turns each stage into a live progress line (so seeding/installing a fresh
/// machine reads as forward motion, not a hung "connecting…"); the `herdr --remote` CLI prints the
/// same labels to stderr. Ordered by typical occurrence. See issue #32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteProvisionStage {
    Connecting,
    DetectingPlatform,
    AlreadyInstalled,
    Seeding { source: String },
    Installing,
    Verifying,
    StartingServer,
    Attaching,
}

impl RemoteProvisionStage {
    /// Present-tense status text for the add-remote progress line / CLI stderr.
    pub(crate) fn label(&self) -> String {
        match self {
            RemoteProvisionStage::Connecting => "connecting to remote…".to_string(),
            RemoteProvisionStage::DetectingPlatform => "detecting remote platform…".to_string(),
            RemoteProvisionStage::AlreadyInstalled => {
                "herdr already installed — attaching…".to_string()
            }
            RemoteProvisionStage::Seeding { source } => {
                format!("provisioning herdr from {source}…")
            }
            RemoteProvisionStage::Installing => "installing herdr on the remote…".to_string(),
            RemoteProvisionStage::Verifying => "verifying the installed binary…".to_string(),
            RemoteProvisionStage::StartingServer => "starting the remote server…".to_string(),
            RemoteProvisionStage::Attaching => "attaching to the remote server…".to_string(),
        }
    }
}

/// Sink for [`RemoteProvisionStage`] updates emitted during `prepare_remote_herdr` /
/// `start_ssh_remote_bridge`. Called synchronously on whatever thread drives the prep, so it needs
/// no `Send`/`Sync` bound; the client wraps it to forward stages onto the UI event channel while
/// resetting its idle timeout (issue #32).
pub(crate) type ProgressSink<'a> = dyn Fn(RemoteProvisionStage) + 'a;

/// A [`ProgressSink`] that drops every stage — for paths with no UI to update (silent reconnect).
pub(crate) fn ignore_progress(_: RemoteProvisionStage) {}

pub(crate) fn start_ssh_remote_bridge(
    target: SshTarget,
    restart_incompatible: bool,
    force_reinstall: bool,
    session_name: Option<&str>,
    progress: &ProgressSink,
) -> io::Result<RemoteBridge> {
    let session_name = session_name.unwrap_or(crate::session::DEFAULT_SESSION_NAME);
    // Client-driven attach: never block on stdin, and prefer live-handoff so an out-of-date
    // remote server is upgraded without killing its panes.
    let policy = RemotePrepPolicy::NonInteractive {
        restart_incompatible,
    };
    let prepared_remote = prepare_remote_herdr(&target, true, force_reinstall, policy, progress)?;
    progress(RemoteProvisionStage::StartingServer);
    ensure_remote_server_ready(
        &target,
        &prepared_remote.remote_herdr,
        prepared_remote.installed_or_replaced,
        true,
        policy,
    )?;
    progress(RemoteProvisionStage::Attaching);
    start_ssh_remote_bridge_with_prepared(&target, session_name, prepared_remote.remote_herdr)
}

fn start_ssh_remote_bridge_with_prepared(
    target: &SshTarget,
    session_name: &str,
    remote_herdr: RemoteHerdr,
) -> io::Result<RemoteBridge> {
    let paths = remote_bridge_socket_paths(target.destination(), session_name);
    let client_bridge = SshStdioBridge::start(
        target.clone(),
        remote_herdr.clone(),
        paths.client_socket.clone(),
        session_name.to_string(),
        RemoteBridgeKind::Client,
    )?;
    let api_bridge = SshStdioBridge::start(
        target.clone(),
        remote_herdr,
        paths.api_socket.clone(),
        session_name.to_string(),
        RemoteBridgeKind::Api,
    )?;

    Ok(RemoteBridge {
        client_socket: paths.client_socket,
        api_socket: paths.api_socket,
        _client_bridge: Some(client_bridge),
        _api_bridge: Some(api_bridge),
    })
}

pub(crate) fn run_remote_client_bridge() -> io::Result<()> {
    if remote_bridge_probe_requested() {
        return Ok(());
    }

    ensure_remote_server_running()?;

    let socket_path = crate::server::socket_paths::client_socket_path();
    bridge_stdio_to_socket(&socket_path, "client")
}

pub(crate) fn run_remote_api_bridge() -> io::Result<()> {
    if remote_bridge_probe_requested() {
        return Ok(());
    }

    ensure_remote_server_running()?;

    let socket_path = crate::api::socket_path();
    bridge_stdio_to_socket(&socket_path, "API")
}

fn remote_bridge_probe_requested() -> bool {
    std::env::var_os(REMOTE_BRIDGE_PROBE_ENV_VAR).is_some()
}

fn bridge_stdio_to_socket(socket_path: &Path, label: &str) -> io::Result<()> {
    let stream = UnixStream::connect(socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr {label} socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;

    let mut stdout = io::stdout().lock();
    let mut socket_to_stdout = stream.try_clone()?;
    let mut stdin_to_socket = stream;

    let _upload = thread::spawn(move || {
        let mut stdin = io::stdin();
        let _ = copy_flush(&mut stdin, &mut stdin_to_socket);
        let _ = stdin_to_socket.shutdown(std::net::Shutdown::Write);
    });

    copy_flush(&mut socket_to_stdout, &mut stdout).map(|_| ())
}

fn ensure_remote_server_running() -> io::Result<()> {
    let socket_path = crate::server::socket_paths::client_socket_path();
    if crate::server::autodetect::is_server_listening() {
        let status = crate::api::read_runtime_status_at(
            &crate::api::socket_path(),
            Duration::from_millis(500),
        )?
        .ok_or_else(|| io::Error::other("remote server status API is unavailable"))?;
        if status.protocol == Some(CURRENT_PROTOCOL) {
            return Ok(());
        }
        return Err(io::Error::other(format!(
            "remote herdr server is running with protocol {}, but this bridge needs protocol {CURRENT_PROTOCOL}; rerun `herdr --remote` from an interactive terminal to approve stopping it",
            protocol_label(status.protocol)
        )));
    }

    crate::server::autodetect::spawn_server_daemon()?;
    crate::server::autodetect::wait_for_server_socket(&socket_path, Duration::from_secs(5))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemotePlatform {
    os: &'static str,
    arch: &'static str,
}

impl RemotePlatform {
    fn from_uname(os: &str, arch: &str) -> Option<Self> {
        let os = match os.trim() {
            "Linux" => "linux",
            "Darwin" => "macos",
            _ => return None,
        };
        let arch = match arch.trim() {
            "x86_64" | "amd64" => "x86_64",
            "aarch64" | "arm64" => "aarch64",
            _ => return None,
        };
        Some(Self { os, arch })
    }

    fn local() -> Self {
        let os = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unknown"
        };

        let arch = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "unknown"
        };

        Self { os, arch }
    }

    fn asset_key(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

#[derive(Debug, Clone)]
struct RemoteHerdr {
    install_suffix: String,
    shell_path: String,
    platform: RemotePlatform,
}

impl RemoteHerdr {
    fn for_platform(platform: RemotePlatform) -> Self {
        Self::for_install_suffix(platform, ".local/bin/herdr".to_string())
    }

    fn for_install_suffix(platform: RemotePlatform, install_suffix: String) -> Self {
        let shell_path = format!("\"$HOME/{install_suffix}\"");
        Self {
            install_suffix,
            shell_path,
            platform,
        }
    }

    fn with_shell_path(mut self, shell_path: String) -> Self {
        self.shell_path = shell_path;
        self
    }
}

#[derive(Deserialize)]
struct RemoteUpdateManifest {
    version: String,
    protocol: Option<u32>,
    assets: BTreeMap<String, RemoteAsset>,
    #[serde(default, deserialize_with = "deserialize_remote_manifest_releases")]
    releases: BTreeMap<String, RemoteReleaseMetadata>,
}

#[derive(Deserialize)]
struct RemoteReleaseMetadata {
    protocol: Option<u32>,
    #[serde(default)]
    assets: BTreeMap<String, RemoteAsset>,
}

/// One published asset in the herdr.dev manifest: a download URL plus the integrity material
/// used to verify it before it is seeded to (and executed on) a remote host. Accepts either a
/// bare URL string or an object `{url, sha256, sig}`, matching `update.rs::AssetRef`.
#[derive(Clone)]
struct RemoteAsset {
    url: String,
    sha256: Option<String>,
    sig: Option<String>,
}

impl RemoteAsset {
    /// URL of the detached minisign signature: the manifest's explicit `sig`, or the conventional
    /// `<asset>.minisig` sidecar.
    fn sig_url(&self) -> String {
        self.sig
            .clone()
            .unwrap_or_else(|| format!("{}.minisig", self.url))
    }
}

impl<'de> Deserialize<'de> for RemoteAsset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(url) if !url.trim().is_empty() => Ok(Self {
                url: url.trim().to_string(),
                sha256: None,
                sig: None,
            }),
            serde_json::Value::Object(mut object) => {
                let url = object
                    .remove("url")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .ok_or_else(|| serde::de::Error::custom("asset object is missing url"))?;
                if url.trim().is_empty() {
                    return Err(serde::de::Error::custom("asset url must not be empty"));
                }
                let sha256 = object
                    .remove("sha256")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .filter(|value| !value.trim().is_empty());
                let sig = object
                    .remove("sig")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .filter(|value| !value.trim().is_empty());
                Ok(Self {
                    url: url.trim().to_string(),
                    sha256,
                    sig,
                })
            }
            _ => Err(serde::de::Error::custom(
                "asset must be a URL string or object with url",
            )),
        }
    }
}

fn deserialize_remote_manifest_releases<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, RemoteReleaseMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Object(object)) => object
            .into_iter()
            .filter_map(|(version, release)| {
                serde_json::from_value::<RemoteReleaseMetadata>(release)
                    .ok()
                    .map(|metadata| (version, metadata))
            })
            .collect(),
        _ => BTreeMap::new(),
    })
}

impl RemoteUpdateManifest {
    fn release_for_version(&self, version: &str) -> Option<RemoteManifestReleaseRef<'_>> {
        if self.version.trim_start_matches('v') == version {
            return Some(RemoteManifestReleaseRef {
                protocol: self.protocol,
                assets: &self.assets,
            });
        }

        self.releases.get(version).and_then(|release| {
            (!release.assets.is_empty()).then_some(RemoteManifestReleaseRef {
                protocol: release.protocol,
                assets: &release.assets,
            })
        })
    }
}

#[derive(Clone, Copy)]
struct RemoteManifestReleaseRef<'a> {
    protocol: Option<u32>,
    assets: &'a BTreeMap<String, RemoteAsset>,
}

struct InstallSource {
    path: PathBuf,
    temporary_dir: Option<PathBuf>,
}

struct PreparedRemoteHerdr {
    remote_herdr: RemoteHerdr,
    installed_or_replaced: bool,
}

impl InstallSource {
    fn persistent(path: PathBuf) -> Self {
        Self {
            path,
            temporary_dir: None,
        }
    }

    fn temporary(path: PathBuf, temporary_dir: PathBuf) -> Self {
        Self {
            path,
            temporary_dir: Some(temporary_dir),
        }
    }

    fn cleanup(&self) {
        if let Some(dir) = &self.temporary_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn prepare_remote_herdr(
    target: &SshTarget,
    live_handoff_enabled: bool,
    force_reinstall: bool,
    policy: RemotePrepPolicy,
    progress: &ProgressSink,
) -> io::Result<PreparedRemoteHerdr> {
    progress(RemoteProvisionStage::Connecting);
    progress(RemoteProvisionStage::DetectingPlatform);
    let platform = detect_remote_platform(target)?;
    let remote_herdr = RemoteHerdr::for_platform(platform);
    let override_binary = remote_binary_override_path()?;
    let path_remote_herdr = remote_binary_on_path_any(target, &remote_herdr)?;
    let exe_name_remote_herdr = remote_herdr_from_current_exe_name(&remote_herdr.platform);

    // #61: a FORCED update (the host-menu "update") always reseeds the current build, even when the
    // remote reports the same version+protocol. A dev rebuild at the SAME version string but a newer
    // commit is otherwise treated as "already installed" — `version_line_matches_current` compares
    // only the package version and accepts ANY commit suffix — so the update silently no-ops. Forcing
    // skips that match-and-skip the same way an explicit `override_binary` already does.
    if override_binary.is_none() && !force_reinstall {
        if let Some(path_remote_herdr) = path_remote_herdr
            .as_ref()
            .filter(|candidate| remote_binary_matches(target, candidate).unwrap_or(false))
        {
            progress(RemoteProvisionStage::AlreadyInstalled);
            return Ok(PreparedRemoteHerdr {
                remote_herdr: path_remote_herdr.clone(),
                installed_or_replaced: false,
            });
        }
        if let Some(exe_name_remote_herdr) = exe_name_remote_herdr
            .as_ref()
            .filter(|candidate| remote_binary_matches(target, candidate).unwrap_or(false))
        {
            progress(RemoteProvisionStage::AlreadyInstalled);
            return Ok(PreparedRemoteHerdr {
                remote_herdr: exe_name_remote_herdr.clone(),
                installed_or_replaced: false,
            });
        }
        if remote_binary_matches(target, &remote_herdr)? {
            progress(RemoteProvisionStage::AlreadyInstalled);
            return Ok(PreparedRemoteHerdr {
                remote_herdr,
                installed_or_replaced: false,
            });
        }
    }

    if let Some(status_probe_herdr) = path_remote_herdr.as_ref().or_else(|| {
        remote_binary_exists(target, &remote_herdr)
            .ok()
            .and_then(|exists| exists.then_some(&remote_herdr))
    }) {
        confirm_remote_install_with_running_server(
            target,
            status_probe_herdr,
            live_handoff_enabled,
            policy,
        )?;
    }
    let source_description =
        install_source_description(&remote_herdr.platform, override_binary.as_deref());
    confirm_remote_install(
        target.destination(),
        &remote_herdr,
        &source_description,
        policy,
    )?;
    progress(RemoteProvisionStage::Seeding {
        source: source_description.clone(),
    });
    let source = resolve_install_source(&remote_herdr.platform, override_binary)?;
    progress(RemoteProvisionStage::Installing);
    let install_result = install_remote_herdr(target, &remote_herdr, &source.path);
    source.cleanup();
    install_result?;

    progress(RemoteProvisionStage::Verifying);
    match check_remote_binary(target, &remote_herdr)? {
        RemoteBinaryCheck::Compatible => {}
        other => {
            return Err(io::Error::other(
                other.install_failure_message(&remote_herdr.shell_path),
            ))
        }
    }
    warn_if_remote_bin_not_on_path(target)?;

    Ok(PreparedRemoteHerdr {
        remote_herdr,
        installed_or_replaced: true,
    })
}

fn detect_remote_platform(target: &SshTarget) -> io::Result<RemotePlatform> {
    let output = ssh_output(target, "uname -s; uname -m")?;
    if !output.status.success() {
        return Err(command_failed("remote platform detection failed", &output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let os = lines.next().unwrap_or_default();
    let arch = lines.next().unwrap_or_default();
    RemotePlatform::from_uname(os, arch).ok_or_else(|| {
        io::Error::other(format!(
            "unsupported remote platform: {} {}",
            os.trim(),
            arch.trim()
        ))
    })
}

fn remote_binary_on_path_any(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
) -> io::Result<Option<RemoteHerdr>> {
    let output = ssh_output(target, remote_path_probe_any_command())?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(remote_herdr_from_path_probe_any(remote_herdr, &stdout))
}

fn remote_path_probe_any_command() -> &'static str {
    r#"path=$(command -v herdr) || exit 1
test -n "$path" || exit 1
printf '%s\n' "$path"
"#
}

#[cfg(test)]
fn remote_herdr_from_path_probe(remote_herdr: &RemoteHerdr, stdout: &str) -> Option<RemoteHerdr> {
    let mut lines = stdout.lines();
    let path = lines.next()?;
    let version = lines.next()?.trim();
    let status = lines.next()?;
    let protocol = parse_client_status_json(status)?.protocol;
    if !path.starts_with('/')
        || !crate::version::version_line_matches_current(version)
        || protocol != CURRENT_PROTOCOL
    {
        return None;
    }

    Some(remote_herdr.clone().with_shell_path(shell_quote(path)))
}

fn remote_herdr_from_path_probe_any(
    remote_herdr: &RemoteHerdr,
    stdout: &str,
) -> Option<RemoteHerdr> {
    let mut lines = stdout.lines();
    let path = lines.next()?;
    if !path.starts_with('/') {
        return None;
    }
    Some(remote_herdr.clone().with_shell_path(shell_quote(path)))
}

fn remote_herdr_from_current_exe_name(platform: &RemotePlatform) -> Option<RemoteHerdr> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_str()?;
    remote_herdr_from_exe_name(platform.clone(), name)
}

fn remote_herdr_from_exe_name(platform: RemotePlatform, name: &str) -> Option<RemoteHerdr> {
    if name == "herdr"
        || name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return None;
    }

    Some(RemoteHerdr::for_install_suffix(
        platform,
        format!(".local/bin/{name}"),
    ))
}

fn remote_binary_matches(target: &SshTarget, remote_herdr: &RemoteHerdr) -> io::Result<bool> {
    let command = remote_binary_match_command(remote_herdr);
    let output = ssh_output(target, &command)?;
    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let version = lines.next().unwrap_or_default().trim();
    let status = lines.next().unwrap_or_default();
    Ok(crate::version::version_line_matches_current(version)
        && parse_client_status_json(status)
            .map(|status| status.protocol == CURRENT_PROTOCOL)
            .unwrap_or(false))
}

fn remote_binary_match_command(remote_herdr: &RemoteHerdr) -> String {
    format!(
        "test -x {0} && {0} --version && {0} status client --json && {1}=1 {0} remote-client-bridge && {1}=1 {0} remote-api-bridge",
        remote_herdr.shell_path, REMOTE_BRIDGE_PROBE_ENV_VAR
    )
}

/// Why a freshly-installed remote herdr is not usable by this client. Unlike the boolean
/// `remote_binary_matches`, this distinguishes the failure so the user gets a truthful, actionable
/// message instead of the old catch-all "did not report version" (which lied when the version
/// actually matched but the protocol/bridge support did not — see issue #12, dev2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteBinaryCheck {
    Compatible,
    NotExecutable,
    /// Ran, but reported a different herdr version than this client.
    VersionMismatch {
        reported: String,
    },
    /// Version matched, but the wire protocol differs (e.g. an older same-version release asset).
    ProtocolMismatch {
        reported: Option<u32>,
    },
    /// Version + protocol look right, but the binary lacks the remote-bridge subcommands.
    MissingBridgeSupport,
    /// Probe output could not be understood (binary did not respond to --version/status).
    Unintelligible,
}

/// A diagnostic probe that reports each capability on its own marker line (instead of the
/// short-circuiting `&&` chain in `remote_binary_match_command`), so we can tell *which* check
/// failed. The script always exits 0 and emits exactly one terminal marker per stage.
fn remote_binary_diagnose_command(remote_herdr: &RemoteHerdr) -> String {
    format!(
        "P={0}\n\
         if ! test -x \"$P\"; then echo HERDR_PROBE_NOT_EXECUTABLE; exit 0; fi\n\
         v=$(\"$P\" --version 2>/dev/null) || {{ echo HERDR_PROBE_NO_VERSION; exit 0; }}\n\
         echo \"HERDR_PROBE_VERSION $v\"\n\
         s=$(\"$P\" status client --json 2>/dev/null) || {{ echo HERDR_PROBE_NO_STATUS; exit 0; }}\n\
         echo \"HERDR_PROBE_STATUS $s\"\n\
         if {1}=1 \"$P\" remote-client-bridge >/dev/null 2>&1 && {1}=1 \"$P\" remote-api-bridge >/dev/null 2>&1; then echo HERDR_PROBE_BRIDGE_OK; else echo HERDR_PROBE_BRIDGE_MISSING; fi\n",
        remote_herdr.shell_path, REMOTE_BRIDGE_PROBE_ENV_VAR
    )
}

fn interpret_remote_binary_probe(stdout: &str) -> RemoteBinaryCheck {
    let mut version = None;
    let mut status = None;
    let mut bridge_ok = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line == "HERDR_PROBE_NOT_EXECUTABLE" {
            return RemoteBinaryCheck::NotExecutable;
        } else if line == "HERDR_PROBE_NO_VERSION" || line == "HERDR_PROBE_NO_STATUS" {
            return RemoteBinaryCheck::Unintelligible;
        } else if let Some(rest) = line.strip_prefix("HERDR_PROBE_VERSION ") {
            version = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("HERDR_PROBE_STATUS ") {
            status = Some(rest.trim().to_string());
        } else if line == "HERDR_PROBE_BRIDGE_OK" {
            bridge_ok = Some(true);
        } else if line == "HERDR_PROBE_BRIDGE_MISSING" {
            bridge_ok = Some(false);
        }
    }

    let Some(version) = version else {
        return RemoteBinaryCheck::Unintelligible;
    };
    if !crate::version::version_line_matches_current(&version) {
        return RemoteBinaryCheck::VersionMismatch { reported: version };
    }
    let protocol = status
        .as_deref()
        .and_then(parse_client_status_json)
        .map(|status| status.protocol);
    if protocol != Some(CURRENT_PROTOCOL) {
        return RemoteBinaryCheck::ProtocolMismatch { reported: protocol };
    }
    if bridge_ok != Some(true) {
        return RemoteBinaryCheck::MissingBridgeSupport;
    }
    RemoteBinaryCheck::Compatible
}

impl RemoteBinaryCheck {
    /// Message for the case where we just installed a binary but it is not usable. Points the user
    /// at `HERDR_REMOTE_BINARY` for the common cross-platform / dev-build cause.
    fn install_failure_message(&self, shell_path: &str) -> String {
        let seed = format!(
            "Build herdr for the remote platform and set {REMOTE_BINARY_ENV_VAR}=<path>, or install a matching herdr on the remote host manually."
        );
        match self {
            RemoteBinaryCheck::Compatible => {
                format!("remote herdr at {shell_path} is compatible")
            }
            RemoteBinaryCheck::NotExecutable => format!(
                "installed remote herdr at {shell_path}, but it is not executable on the remote host (most likely a wrong-architecture binary). {seed}"
            ),
            RemoteBinaryCheck::VersionMismatch { reported } => format!(
                "installed remote herdr at {shell_path}, but it reports `{reported}`, not version {CURRENT_VERSION}. {seed}"
            ),
            RemoteBinaryCheck::ProtocolMismatch { reported } => format!(
                "installed remote herdr at {shell_path} runs protocol {}, but this client needs protocol {CURRENT_PROTOCOL}. The version matched, so this is an older {CURRENT_VERSION} build (e.g. the published release asset for the remote platform predates protocol {CURRENT_PROTOCOL}). {seed}",
                protocol_label(*reported)
            ),
            RemoteBinaryCheck::MissingBridgeSupport => format!(
                "installed remote herdr at {shell_path} does not support the remote-bridge subcommands this client needs (an older {CURRENT_VERSION} build). {seed}"
            ),
            RemoteBinaryCheck::Unintelligible => format!(
                "installed remote herdr at {shell_path}, but it did not respond to --version/status probes. {seed}"
            ),
        }
    }
}

/// Diagnose the installed remote binary, distinguishing version/protocol/bridge failures. Used on
/// the post-install error path; the hot path still uses the cheaper boolean `remote_binary_matches`.
fn check_remote_binary(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
) -> io::Result<RemoteBinaryCheck> {
    let output = ssh_output(target, &remote_binary_diagnose_command(remote_herdr))?;
    if !output.status.success() {
        return Ok(RemoteBinaryCheck::Unintelligible);
    }
    Ok(interpret_remote_binary_probe(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn remote_binary_exists(target: &SshTarget, remote_herdr: &RemoteHerdr) -> io::Result<bool> {
    let command = format!("test -x {}", remote_herdr.shell_path);
    Ok(ssh_output(target, &command)?.status.success())
}

fn remote_binary_override_path() -> io::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(REMOTE_BINARY_ENV_VAR) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{REMOTE_BINARY_ENV_VAR} must not be empty"),
        ));
    }

    let path = PathBuf::from(value);
    let metadata = fs::metadata(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to inspect {REMOTE_BINARY_ENV_VAR} path {}: {err}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{REMOTE_BINARY_ENV_VAR} path is not a file: {}",
                path.display()
            ),
        ));
    }

    Ok(Some(path))
}

/// Which non-override source `prepare_remote_herdr` seeds the remote from. Tiers are
/// tried in order: the running executable itself, then a sibling-platform binary
/// carried inside this multi-platform build (issue #28), then a release download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonOverrideSeed {
    /// The running executable itself (same platform, from-source build).
    LocalExe,
    /// A sibling-platform binary carried inside this multi-platform build.
    Bundle,
    /// Download the matching release asset (the pre-#28 fallback).
    Download,
}

fn install_source_description(platform: &RemotePlatform, override_binary: Option<&Path>) -> String {
    if let Some(path) = override_binary {
        return install_source_description_for(platform, Some(path), NonOverrideSeed::Download);
    }
    install_source_description_for(platform, None, classify_seed_source(platform))
}

fn install_source_description_for(
    platform: &RemotePlatform,
    override_binary: Option<&Path>,
    seed: NonOverrideSeed,
) -> String {
    if let Some(path) = override_binary {
        return format!("{REMOTE_BINARY_ENV_VAR} ({})", path.display());
    }

    match seed {
        NonOverrideSeed::LocalExe => "the current local herdr binary".to_string(),
        NonOverrideSeed::Bundle => format!(
            "the {} fat bundle repacked from this multi-platform build",
            platform.asset_key()
        ),
        NonOverrideSeed::Download => format!(
            "the {CURRENT_VERSION} release asset for {}",
            platform.asset_key()
        ),
    }
}

/// Decide, from cheap pre-checks, which non-override source to seed from. Pure so the
/// tier order (local exe > carried bundle > download) is unit-testable.
fn choose_seed_source(has_local_exe_seed: bool, has_bundled_match: bool) -> NonOverrideSeed {
    if has_local_exe_seed {
        NonOverrideSeed::LocalExe
    } else if has_bundled_match {
        NonOverrideSeed::Bundle
    } else {
        NonOverrideSeed::Download
    }
}

fn classify_seed_source(platform: &RemotePlatform) -> NonOverrideSeed {
    choose_seed_source(
        local_binary_can_seed_remote(platform),
        self_bundle_seeds_platform(platform),
    )
}

/// #44: can this herdr build seed `platform` WITHOUT falling back to an internet download? True when
/// a `HERDR_REMOTE_BINARY` override is set, OR when the seed source is the local exe / a carried
/// bundle. The one-click "update" worker calls this BEFORE attempting an install so an unbuildable
/// platform fails with a truthful message instead of silently downloading a release asset.
fn can_seed_remote_without_download(platform: &RemotePlatform) -> bool {
    if matches!(remote_binary_override_path(), Ok(Some(_))) {
        return true;
    }
    !matches!(classify_seed_source(platform), NonOverrideSeed::Download)
}

/// #44: one-click "update" pre-flight. Detects the remote's platform over SSH and, when this build
/// cannot seed it without an internet download, returns `Err(<truthful message>)` so the update
/// worker can abort BEFORE `start_ssh_remote_bridge` would fall back to `download_release_asset`.
/// `Ok(())` means the install can proceed from a local/bundled/override binary. Keeps the private
/// `RemotePlatform` internal to this module.
pub(crate) fn preflight_remote_update_seed(target: &SshTarget) -> Result<(), String> {
    let platform = detect_remote_platform(target).map_err(|err| err.to_string())?;
    if can_seed_remote_without_download(&platform) {
        Ok(())
    } else {
        Err(format!(
            "this herdr build has no binary for {}; build/seed it instead of downloading",
            platform.asset_key()
        ))
    }
}

fn resolve_install_source(
    platform: &RemotePlatform,
    override_binary: Option<PathBuf>,
) -> io::Result<InstallSource> {
    if let Some(path) = override_binary {
        verify_override_binary(&path)?;
        return Ok(InstallSource::persistent(path));
    }

    match classify_seed_source(platform) {
        // The running executable and a bundle carried inside it are this trusted process's own
        // bytes (bundle entries are SHA-256-checked on extract); only the download tier crosses an
        // untrusted boundary and verifies sha256 + signature.
        NonOverrideSeed::LocalExe => Ok(InstallSource::persistent(std::env::current_exe()?)),
        NonOverrideSeed::Bundle => extract_bundle_install_source(platform),
        NonOverrideSeed::Download => download_release_asset(platform),
    }
}

/// Verify an operator-provided override binary (`HERDR_REMOTE_BINARY`). If a sibling
/// `<path>.minisig` exists it MUST verify (fail closed). If absent, the operator explicitly chose
/// this path, so by default we proceed with a warning rather than block a from-source or air-gapped
/// workflow — unless `HERDR_REMOTE_BINARY_REQUIRE_SIGNATURE=1`, in which case a missing sidecar is a
/// hard failure so every seeded binary is signature-verified.
fn verify_override_binary(path: &Path) -> io::Result<()> {
    let mut sig_os = path.as_os_str().to_owned();
    sig_os.push(".minisig");
    let sig_path = PathBuf::from(sig_os);
    match fs::read(&sig_path) {
        Ok(signature) => crate::signing::verify_signature(path, &signature),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if matches!(
                std::env::var(REMOTE_BINARY_REQUIRE_SIG_ENV_VAR).as_deref(),
                Ok("1")
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "{REMOTE_BINARY_ENV_VAR} binary {} has no sibling .minisig and \
                         {REMOTE_BINARY_REQUIRE_SIG_ENV_VAR}=1; refusing to seed an unverified binary",
                        path.display()
                    ),
                ));
            }
            tracing::warn!(
                path = %path.display(),
                "{REMOTE_BINARY_ENV_VAR} binary has no sibling .minisig; seeding it unverified (operator-provided)"
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn local_binary_can_seed_remote(platform: &RemotePlatform) -> bool {
    if *platform != RemotePlatform::local() {
        return false;
    }

    // Channel builds (mx/preview) have no downloadable asset at their exact version, so
    // the running executable is the only same-platform seed source — even when it is
    // package-manager managed (brew/mise install the very fat binary the release shipped).
    if crate::build_info::channel() != "stable" {
        return std::env::current_exe().is_ok();
    }

    std::env::current_exe()
        .map(|path| !crate::update::is_package_manager_managed_exe_path(&path))
        .unwrap_or(false)
}

/// Does this build's appended payload carry a usable binary for `platform`? Pure
/// matching logic: exact version (and commit, when both are known) plus an entry for
/// the remote os/arch. Kept separate from the I/O wrapper so it is unit-testable.
fn bundle_seeds_platform(
    index: &crate::bundle::BundleIndex,
    platform: &RemotePlatform,
    expected_version: &str,
    expected_commit: Option<&str>,
) -> bool {
    if index.herdr_version != expected_version {
        return false;
    }
    // When both sides know their build commit, require an exact match so a stale
    // bundle from a different commit is never silently seeded (exact version parity).
    if let (Some(bundle_commit), Some(expected)) = (index.build_commit.as_deref(), expected_commit)
    {
        if bundle_commit != expected {
            return false;
        }
    }
    index.entry_for(platform.os, platform.arch).is_some()
}

/// I/O wrapper around [`bundle_seeds_platform`] for the running binary. Any read or
/// parse problem is treated as "no usable bundle" so add-remote falls back cleanly.
fn self_bundle_seeds_platform(platform: &RemotePlatform) -> bool {
    match crate::bundle::read_self_index() {
        Ok(Some(index)) => bundle_seeds_platform(
            &index,
            platform,
            CURRENT_VERSION,
            option_env!("HERDR_BUILD_COMMIT"),
        ),
        _ => false,
    }
}

/// Re-target this fat build for `platform` into a private temp file: the carried
/// `platform` binary becomes the native image and every other platform (including this
/// host's own image, compressed in) rides along, so the seeded remote can itself seed
/// cross-platform offline — mac → linux → another mac works without downloads.
/// Falls back to the download path if the entry is unexpectedly absent.
fn extract_bundle_install_source(platform: &RemotePlatform) -> io::Result<InstallSource> {
    let exe = std::env::current_exe()?;
    let Some(index) = crate::bundle::read_self_index()? else {
        return download_release_asset(platform);
    };
    let Some(entry) = index.entry_for(platform.os, platform.arch) else {
        return download_release_asset(platform);
    };
    let bytes =
        crate::bundle::repack_for_entry(&exe, &index, entry, crate::bundle::local_os_arch())?;

    let asset_key = platform.asset_key();
    let dir = private_download_dir(&asset_key)?;
    let path = dir.join("herdr.bundled");
    if let Err(err) = fs::write(&path, &bytes) {
        let _ = fs::remove_dir_all(&dir);
        return Err(err);
    }
    Ok(InstallSource::temporary(path, dir))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteServerStatus {
    Running {
        version: Option<String>,
        protocol: Option<u32>,
        live_handoff: bool,
    },
    NotRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteServerRestartReason {
    ProtocolMismatch,
    BinaryUpdated,
    VersionMismatch,
}

fn ensure_remote_server_ready(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
    remote_binary_changed: bool,
    live_handoff_enabled: bool,
    policy: RemotePrepPolicy,
) -> io::Result<()> {
    let status = remote_server_status(target, remote_herdr)?;
    let RemoteServerStatus::Running {
        version,
        protocol,
        live_handoff,
    } = status
    else {
        return Ok(());
    };

    let Some(reason) =
        remote_server_restart_reason(version.as_deref(), protocol, remote_binary_changed)
    else {
        return Ok(());
    };

    // Non-interactive (client) attach: decide without prompting and never hard-stop.
    if let RemotePrepPolicy::NonInteractive {
        restart_incompatible,
    } = policy
    {
        match non_interactive_server_action(reason, live_handoff_enabled, live_handoff) {
            NonInteractiveServerAction::AttachExisting => return Ok(()),
            NonInteractiveServerAction::LiveHandoff => {
                return match live_handoff_remote_server(target, remote_herdr) {
                    Ok(()) => Ok(()),
                    // A failed handoff for a protocol mismatch leaves us unable to attach; surface
                    // it rather than killing panes. For a compatible server, fall back to attaching.
                    Err(err) if reason == RemoteServerRestartReason::ProtocolMismatch => Err(err),
                    Err(err) => {
                        // NonInteractive = in-client TUI worker: log, don't eprintln onto the
                        // raw-mode screen (issue #32 follow-up).
                        tracing::warn!(
                            "remote live handoff failed: {err}; attaching to the running server."
                        );
                        Ok(())
                    }
                };
            }
            NonInteractiveServerAction::ProtocolStuck => {
                // The remote runs an incompatible server that can't live-handoff. Stopping it would
                // interrupt its panes, so we never do that silently — unless the user explicitly
                // approved it via the add-remote y/N (issue #12, macmini). Otherwise we surface a
                // typed signal the client turns into that prompt.
                if restart_incompatible {
                    stop_remote_server(target, remote_herdr)?;
                    return Ok(());
                }
                return Err(io::Error::other(RestartConfirmNeeded {
                    destination: target.destination().to_string(),
                    version: version.clone(),
                    protocol,
                }));
            }
        }
    }

    if live_handoff_enabled
        && live_handoff
        && confirm_remote_server_handoff(
            target.destination(),
            version.as_deref(),
            protocol,
            reason,
        )?
    {
        match live_handoff_remote_server(target, remote_herdr) {
            Ok(()) => return Ok(()),
            Err(err) => {
                eprintln!("remote live handoff failed: {err}");
                eprintln!("falling back to remote server restart.");
            }
        }
    }

    if confirm_remote_server_stop(target.destination(), version.as_deref(), protocol, reason)? {
        stop_remote_server(target, remote_herdr)?;
    }
    Ok(())
}

fn remote_server_restart_reason(
    version: Option<&str>,
    protocol: Option<u32>,
    remote_binary_changed: bool,
) -> Option<RemoteServerRestartReason> {
    if protocol != Some(CURRENT_PROTOCOL) {
        return Some(RemoteServerRestartReason::ProtocolMismatch);
    }
    if remote_binary_changed {
        return Some(RemoteServerRestartReason::BinaryUpdated);
    }
    if version != Some(CURRENT_VERSION) {
        return Some(RemoteServerRestartReason::VersionMismatch);
    }
    None
}

/// What a non-interactive (client-driven) attach should do with an out-of-date running remote
/// server, given the restart reason and whether live-handoff is possible. It never hard-stops:
/// a protocol mismatch that cannot hand off is reported as an error rather than killing panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonInteractiveServerAction {
    /// Attach to the running server unchanged (protocol is compatible).
    AttachExisting,
    /// Live-handoff to the prepared server (preserves panes), then attach.
    LiveHandoff,
    /// Cannot attach: protocol mismatch and live-handoff is unavailable.
    ProtocolStuck,
}

fn non_interactive_server_action(
    reason: RemoteServerRestartReason,
    live_handoff_enabled: bool,
    live_handoff_supported: bool,
) -> NonInteractiveServerAction {
    let can_handoff = live_handoff_enabled && live_handoff_supported;
    match reason {
        RemoteServerRestartReason::ProtocolMismatch => {
            if can_handoff {
                NonInteractiveServerAction::LiveHandoff
            } else {
                NonInteractiveServerAction::ProtocolStuck
            }
        }
        // Protocol is compatible: prefer a pane-preserving handoff to pick up the new binary, but
        // attaching to the running server is always a safe fallback (no hard restart).
        RemoteServerRestartReason::BinaryUpdated | RemoteServerRestartReason::VersionMismatch => {
            if can_handoff {
                NonInteractiveServerAction::LiveHandoff
            } else {
                NonInteractiveServerAction::AttachExisting
            }
        }
    }
}

fn confirm_remote_install_with_running_server(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
    live_handoff_enabled: bool,
    policy: RemotePrepPolicy,
) -> io::Result<()> {
    // Non-interactive (client) attach auto-approves replacing the binary; the running server is
    // reconciled later in `ensure_remote_server_ready` (live-handoff when possible).
    if matches!(policy, RemotePrepPolicy::NonInteractive { .. }) {
        return Ok(());
    }
    let dest = target.destination();
    let status = match remote_server_status(target, remote_herdr) {
        Ok(status) => status,
        Err(err) => {
            if !io::stdin().is_terminal() {
                return Err(io::Error::other(format!(
                    "could not inspect the running remote herdr server on {dest} before installing: {err}; run from an interactive terminal to approve updating the remote binary"
                )));
            }
            eprintln!(
                "could not inspect the running remote herdr server on {dest} before installing: {err}"
            );
            eprint!("continue installing the remote herdr binary? [Y/n] ");
            io::stderr().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_ascii_lowercase();
            if answer == "n" || answer == "no" {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "remote herdr install cancelled",
                ));
            }
            return Ok(());
        }
    };
    let RemoteServerStatus::Running {
        version,
        protocol,
        live_handoff,
    } = status
    else {
        return Ok(());
    };
    if live_handoff_enabled && live_handoff {
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        return Err(io::Error::other(format!(
            "remote herdr server on {dest} is running v{} protocol {}; run from an interactive terminal to approve updating the remote binary",
            version_label(version.as_deref()),
            protocol_label(protocol)
        )));
    }

    eprintln!("remote herdr server on {dest} is currently running:");
    eprintln!(
        "  server: v{} protocol {}",
        version_label(version.as_deref()),
        protocol_label(protocol)
    );
    eprintln!(
        "this attach will not preserve running panes unless you pass --handoff and the remote server supports live handoff."
    );
    eprintln!();
    eprint!("continue installing the remote herdr binary? [Y/n] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer == "n" || answer == "no" {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote herdr install cancelled",
        ));
    }

    Ok(())
}

fn remote_server_status(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
) -> io::Result<RemoteServerStatus> {
    let command = format!("{} status server --json", remote_herdr.shell_path);
    let output = ssh_output(target, &command)?;
    if !output.status.success() {
        return Err(command_failed("remote server status failed", &output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_remote_server_status_json(stdout.trim())
}

#[derive(Debug, Deserialize)]
struct RemoteClientStatusJson {
    protocol: u32,
}

#[derive(Debug, Deserialize)]
struct RemoteServerStatusJson {
    running: bool,
    version: Option<String>,
    protocol: Option<u32>,
    capabilities: Option<RemoteServerCapabilitiesJson>,
}

#[derive(Debug, Deserialize)]
struct RemoteServerCapabilitiesJson {
    live_handoff: bool,
}

fn parse_client_status_json(status: &str) -> Option<RemoteClientStatusJson> {
    serde_json::from_str(status).ok()
}

fn parse_remote_server_status_json(status: &str) -> io::Result<RemoteServerStatus> {
    let parsed: RemoteServerStatusJson = serde_json::from_str(status).map_err(|err| {
        io::Error::other(format!(
            "could not parse remote server status JSON from `{status}`: {err}"
        ))
    })?;
    if !parsed.running {
        return Ok(RemoteServerStatus::NotRunning);
    }

    Ok(RemoteServerStatus::Running {
        version: parsed.version,
        protocol: parsed.protocol,
        live_handoff: parsed
            .capabilities
            .is_some_and(|capabilities| capabilities.live_handoff),
    })
}

fn confirm_remote_server_stop(
    target: &str,
    version: Option<&str>,
    protocol: Option<u32>,
    reason: RemoteServerRestartReason,
) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        if reason == RemoteServerRestartReason::ProtocolMismatch {
            return Err(io::Error::other(format!(
                "remote herdr server on {target} is running with protocol {}, but this client needs protocol {CURRENT_PROTOCOL}; run from an interactive terminal to approve stopping it",
                protocol_label(protocol)
            )));
        }

        eprintln!(
            "remote herdr server on {target} is still running v{}; it will use v{CURRENT_VERSION} after it restarts.",
            version_label(version)
        );
        return Ok(false);
    }

    eprintln!("remote herdr server on {target} is currently running:");
    eprintln!(
        "  server: v{} protocol {}",
        version_label(version),
        protocol_label(protocol)
    );
    eprintln!("  prepared binary: v{CURRENT_VERSION} protocol {CURRENT_PROTOCOL}");
    eprintln!();

    match reason {
        RemoteServerRestartReason::ProtocolMismatch => {
            eprintln!(
                "the remote server protocol does not match this client. the remote server must be stopped before attaching."
            );
        }
        RemoteServerRestartReason::BinaryUpdated => {
            eprintln!(
                "the remote herdr binary was installed or replaced. restart the remote server so it uses the prepared binary."
            );
        }
        RemoteServerRestartReason::VersionMismatch => {
            eprintln!(
                "the remote server is still running a different herdr version. restart it so it uses the prepared binary."
            );
        }
    }

    let prompt = if reason == RemoteServerRestartReason::ProtocolMismatch {
        "stop the remote server and continue attaching? [Y/n] "
    } else {
        "restart the remote server now? [Y/n] "
    };
    eprint!("{prompt}");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer == "n" || answer == "no" {
        if reason == RemoteServerRestartReason::ProtocolMismatch {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "remote herdr server stop cancelled",
            ));
        }
        return Ok(false);
    }

    Ok(true)
}

fn confirm_remote_server_handoff(
    target: &str,
    version: Option<&str>,
    protocol: Option<u32>,
    reason: RemoteServerRestartReason,
) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        if reason == RemoteServerRestartReason::ProtocolMismatch {
            return Err(io::Error::other(format!(
                "remote herdr server on {target} is running with protocol {}, but this client needs protocol {CURRENT_PROTOCOL}; run from an interactive terminal to approve live handoff or stopping it",
                protocol_label(protocol)
            )));
        }

        eprintln!(
            "remote herdr server on {target} is still running v{}; it will use v{CURRENT_VERSION} after it restarts.",
            version_label(version)
        );
        return Ok(false);
    }

    eprintln!("remote herdr server on {target} is currently running:");
    eprintln!(
        "  server: v{} protocol {}",
        version_label(version),
        protocol_label(protocol)
    );
    eprintln!("  prepared binary: v{CURRENT_VERSION} protocol {CURRENT_PROTOCOL}");
    eprintln!();

    match reason {
        RemoteServerRestartReason::ProtocolMismatch => {
            eprintln!(
                "the remote server protocol does not match this client. herdr will try to hand off live pane processes to the prepared remote server before the old server exits."
            );
        }
        RemoteServerRestartReason::BinaryUpdated => {
            eprintln!(
                "the remote herdr binary was installed or replaced. herdr will try to hand off live pane processes to the prepared remote server."
            );
        }
        RemoteServerRestartReason::VersionMismatch => {
            eprintln!(
                "the remote server is still running a different herdr version. herdr will try to hand off live pane processes to the prepared remote server."
            );
        }
    }

    eprint!("live-handoff remote panes to the prepared server? [Y/n] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer != "n" && answer != "no")
}

fn live_handoff_remote_server(target: &SshTarget, remote_herdr: &RemoteHerdr) -> io::Result<()> {
    let command = format!(
        "{} server live-handoff --import-exe {} --expected-protocol {CURRENT_PROTOCOL} --expected-version {CURRENT_VERSION}",
        remote_herdr.shell_path,
        remote_herdr.shell_path
    );
    let output = ssh_output(target, &command)?;
    if !output.status.success() {
        return Err(command_failed("remote server live handoff failed", &output));
    }

    eprintln!(
        "handed off the remote herdr server on {}; reconnecting to the prepared server.",
        target.destination()
    );
    Ok(())
}

fn stop_remote_server(target: &SshTarget, remote_herdr: &RemoteHerdr) -> io::Result<()> {
    let command = format!("{} server stop", remote_herdr.shell_path);
    let output = ssh_output(target, &command)?;
    if !output.status.success() {
        return Err(command_failed("remote server stop failed", &output));
    }

    wait_for_remote_server_shutdown(target, remote_herdr)?;
    eprintln!(
        "stopped the remote herdr server on {}; it will restart when the remote client bridge attaches.",
        target.destination()
    );
    Ok(())
}

fn wait_for_remote_server_shutdown(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
) -> io::Result<()> {
    let deadline = Instant::now() + REMOTE_SERVER_SHUTDOWN_CONFIRM_TIMEOUT;
    loop {
        if remote_server_status(target, remote_herdr)? == RemoteServerStatus::NotRunning {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "shutdown was requested, but the old remote herdr server on {} is still responding after {} seconds",
                    target.destination(),
                    REMOTE_SERVER_SHUTDOWN_CONFIRM_TIMEOUT.as_secs()
                ),
            ));
        }
        thread::sleep(REMOTE_SERVER_SHUTDOWN_POLL_INTERVAL);
    }
}

fn version_label(version: Option<&str>) -> &str {
    version.unwrap_or("unknown")
}

fn protocol_label(protocol: Option<u32>) -> String {
    protocol
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn warn_if_remote_bin_not_on_path(target: &SshTarget) -> io::Result<()> {
    let output = ssh_output(
        target,
        "case \":$PATH:\" in *\":$HOME/.local/bin:\"*) exit 0 ;; *) exit 1 ;; esac",
    )?;
    if !output.status.success() {
        // tracing (log file), not eprintln: this runs inside the raw-mode add-remote TUI worker, so
        // printing to stderr would scroll the screen. add-remote uses the absolute install path
        // regardless, so this is purely advisory.
        tracing::warn!(
            "installed remote binary to ~/.local/bin/herdr, but ~/.local/bin is not in the remote PATH"
        );
    }
    Ok(())
}

fn download_release_asset(platform: &RemotePlatform) -> io::Result<InstallSource> {
    // Channel builds are never published to the herdr.dev manifest, so a download could
    // only ever fetch a foreign (stable upstream) binary. Fail fast with the real fix
    // instead of installing a binary that would immediately fail the version probe.
    let channel = crate::build_info::channel();
    if channel != "stable" {
        return Err(io::Error::other(format!(
            "this {channel}-channel build ({CURRENT_VERSION}) cannot seed remotes from the herdr.dev release manifest; use a fat (multi-platform) build of this version, set {REMOTE_BINARY_ENV_VAR}=<path to a {} binary>, or install the matching herdr on the remote host manually",
            platform.asset_key()
        )));
    }

    let manifest_output = Command::new("curl")
        .args([
            "-sfL",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "20",
            UPDATE_MANIFEST_URL,
        ])
        .output()
        .map_err(|err| io::Error::new(err.kind(), format!("curl failed: {err}")))?;
    if !manifest_output.status.success() {
        return Err(command_failed(
            "failed to fetch update manifest",
            &manifest_output,
        ));
    }

    // Authenticate the manifest before trusting the URLs/versions it dictates for a binary that is
    // about to be executed on a remote host. Verify a detached minisign signature over the manifest
    // bytes against the embedded release key, then parse.
    let sig_url = format!("{UPDATE_MANIFEST_URL}.minisig");
    let sig_output = Command::new("curl")
        .args([
            "-sfL",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "20",
            &sig_url,
        ])
        .output()
        .map_err(|err| io::Error::new(err.kind(), format!("curl failed: {err}")))?;
    if !sig_output.status.success() {
        return Err(io::Error::other(format!(
            "failed to fetch manifest signature from {sig_url}"
        )));
    }
    crate::signing::verify_signature_bytes(&manifest_output.stdout, &sig_output.stdout).map_err(
        |err| io::Error::other(format!("manifest signature verification failed: {err}")),
    )?;

    let manifest: RemoteUpdateManifest = serde_json::from_slice(&manifest_output.stdout)
        .map_err(|err| io::Error::other(format!("failed to parse update manifest JSON: {err}")))?;

    let asset_key = platform.asset_key();
    let release = manifest.release_for_version(CURRENT_VERSION).ok_or_else(|| {
        io::Error::other(format!(
            "release manifest does not include herdr {CURRENT_VERSION}; build herdr for {} or install it there manually",
            platform.asset_key()
        ))
    })?;
    // #32: never seed a binary the remote can't actually run. Published release assets lag the dev
    // protocol, so a fresh host (commonly linux-aarch64 / Graviton, which has no bundled payload)
    // that falls to this Download tier would otherwise install an older protocol build and only
    // fail the post-install protocol check — after a long opaque download. Fail fast with the same
    // actionable guidance whether the manifest reports a mismatching protocol or omits it entirely
    // (an omitted protocol means the asset predates protocol versioning, i.e. definitely too old).
    match release.protocol {
        Some(protocol) if protocol == CURRENT_PROTOCOL => {}
        Some(protocol) => {
            return Err(io::Error::other(format!(
                "release manifest has herdr {CURRENT_VERSION} protocol {protocol}, but this client needs protocol {CURRENT_PROTOCOL}; set {REMOTE_BINARY_ENV_VAR}=target/release/herdr or install a matching herdr on the remote host manually"
            )));
        }
        None => {
            return Err(io::Error::other(format!(
                "the published {asset_key} release for herdr {CURRENT_VERSION} predates protocol versioning and is too old for this client (needs protocol {CURRENT_PROTOCOL}); build herdr for {asset_key} and set {REMOTE_BINARY_ENV_VAR}=<path>, or install a matching herdr on the remote host manually"
            )));
        }
    }
    let asset = release.assets.get(&asset_key).ok_or_else(|| {
        io::Error::other(format!(
            "no {asset_key} binary in the release manifest for herdr {CURRENT_VERSION}"
        ))
    })?;

    let dir = private_download_dir(&asset_key)?;
    let path = dir.join("herdr.tmp");
    let status = Command::new("curl")
        .args(["-sfL", "--max-time", "120", "-o"])
        .arg(&path)
        .arg(&asset.url)
        .status()
        .map_err(|err| io::Error::new(err.kind(), format!("download failed: {err}")))?;
    if !status.success() {
        let _ = fs::remove_dir_all(&dir);
        return Err(io::Error::other("download failed"));
    }

    // Verify BEFORE this binary is ever piped to and executed on the remote host. The minisign
    // signature is mandatory (authenticity, the only check that survives a compromised release
    // host); SHA-256 is an optional cheap corruption pre-check, verified only when the manifest
    // advertises one (see `verify_downloaded_asset`).
    if let Err(err) = verify_downloaded_asset(&path, asset) {
        let _ = fs::remove_dir_all(&dir);
        return Err(err);
    }

    Ok(InstallSource::temporary(path, dir))
}

/// Verify a freshly downloaded release asset before it is seeded to (and executed on) a remote
/// host. The detached minisign signature is mandatory — a valid ed25519 signature proves both
/// authenticity and integrity, and survives a compromised release host. SHA-256, when the manifest
/// advertises it, is an additional cheap corruption pre-check (not load-bearing).
fn verify_downloaded_asset(path: &Path, asset: &RemoteAsset) -> io::Result<()> {
    verify_optional_sha256(path, asset)?;

    let sig_url = asset.sig_url();
    let output = Command::new("curl")
        .args([
            "-sfL",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            &sig_url,
        ])
        .output()
        .map_err(|err| io::Error::new(err.kind(), format!("failed to fetch signature: {err}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to download signature from {sig_url}"
        )));
    }
    crate::signing::verify_signature(path, &output.stdout)
}

/// Cheap corruption pre-check: verify the SHA-256 if the manifest advertised one. Absent is fine —
/// the mandatory signature still covers integrity.
fn verify_optional_sha256(path: &Path, asset: &RemoteAsset) -> io::Result<()> {
    if let Some(expected) = &asset.sha256 {
        crate::checksum::verify_sha256(path, expected)?;
    }
    Ok(())
}

fn private_download_dir(asset_key: &str) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::temp_dir();
    // Owner-only (0700) regardless of the process umask: the download lands in a shared temp dir,
    // and the verified binary is reopened by path before being streamed to the remote. A
    // world/group-writable dir would let a local user swap the file between verification and use
    // (TOCTOU). 0700 keeps everyone else out of the directory entirely.
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    for attempt in 0..100 {
        let dir = base.join(format!(
            "herdr-remote-{}-{}-{attempt}",
            std::process::id(),
            asset_key
        ));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create private herdr remote download directory",
    ))
}

fn confirm_remote_install(
    target: &str,
    remote_herdr: &RemoteHerdr,
    source_description: &str,
    policy: RemotePrepPolicy,
) -> io::Result<()> {
    // Core of requirement #5: a fresh ssh-reachable host auto-installs herdr with no prompt.
    if matches!(policy, RemotePrepPolicy::NonInteractive { .. }) {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(format!(
            "matching remote herdr {CURRENT_VERSION} is not installed at {}; run from an interactive terminal to approve installation",
            remote_herdr.shell_path
        )));
    }

    eprintln!(
        "matching herdr {CURRENT_VERSION} is not installed on {target} for {}.",
        remote_herdr.platform.asset_key()
    );
    eprint!(
        "Install {} to {}? [Y/n] ",
        source_description, remote_herdr.shell_path
    );
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer == "n" || answer == "no" {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote herdr installation cancelled",
        ));
    }

    Ok(())
}

fn install_remote_herdr(
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
    source_path: &Path,
) -> io::Result<()> {
    // mktemp the staging file rather than a predictable "$dest.tmp.$$": `cat >` follows symlinks, so
    // a guessable name in $HOME could be pre-planted (symlink redirect / pre-created file). mktemp
    // creates an exclusive, unpredictable, owner-only file (no symlink follow), then we chmod+mv it
    // into place.
    let script = format!(
        r#"dest="$HOME/{install_suffix}"
dir="${{dest%/*}}"
mkdir -p "$dir"
tmp="$(mktemp "${{dest}}.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
chmod 755 "$tmp"
mv "$tmp" "$dest"
trap - EXIT
"#,
        install_suffix = remote_herdr.install_suffix
    );

    // Capture (never inherit) the install child's output: this also runs inside the in-client
    // add-remote worker, where the raw-mode TUI owns the terminal, so any inherited byte (ssh's
    // "Permanently added … to known hosts" warning, remote shell chatter) scrolls/garbles the
    // screen mid-provision (issue #32 follow-up). stdout is discarded; stderr is kept only to
    // enrich a failure message.
    let mut child = target
        .command(&format!("sh -eu -c {}", shell_quote(&script)))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| io::Error::new(err.kind(), format!("failed to start ssh install: {err}")))?;

    let mut source = File::open(source_path)?;
    let copy_result = match child.stdin.take() {
        Some(mut stdin) => io::copy(&mut source, &mut stdin).map(|_| ()),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "ssh install stdin missing",
        )),
    };
    // The ~11 MB binary went to stdin above; stderr stays tiny (one ssh warning at most), so
    // wait_with_output cannot deadlock on a full pipe.
    let output = child.wait_with_output()?;
    copy_result?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        Err(io::Error::other(if stderr.is_empty() {
            format!("remote install exited with {}", output.status)
        } else {
            format!("remote install exited with {}: {stderr}", output.status)
        }))
    }
}

fn ssh_output(target: &SshTarget, command: &str) -> io::Result<Output> {
    target.command(command).output()
}

fn remote_bridge_command(
    remote_herdr: &RemoteHerdr,
    session_name: &str,
    kind: RemoteBridgeKind,
) -> String {
    let mut command = format!("exec {}", remote_herdr.shell_path);
    if session_name != crate::session::DEFAULT_SESSION_NAME {
        command.push_str(" --session ");
        command.push_str(&shell_quote(session_name));
    }
    command.push(' ');
    command.push_str(kind.subcommand());
    command
}

fn reattach_command(
    program: &str,
    target: &str,
    session_name: &str,
    keybindings: RemoteKeybindings,
    live_handoff: bool,
) -> String {
    let program = if program.is_empty() { "herdr" } else { program };
    let mut command = format!("{} --remote {}", shell_quote(program), shell_quote(target));
    if keybindings != RemoteKeybindings::Local {
        command.push_str(" --remote-keybindings ");
        command.push_str(keybindings.as_str());
    }
    if live_handoff {
        command.push_str(" --handoff");
    }
    if session_name != crate::session::DEFAULT_SESSION_NAME {
        command.push_str(" --session ");
        command.push_str(&shell_quote(session_name));
    }
    command
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '%' | '_' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
                )
        })
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

fn command_failed(context: &str, output: &Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        io::Error::other(format!("{context}: {}", output.status))
    } else {
        io::Error::other(format!("{context}: {stderr}"))
    }
}

struct SshStdioBridge {
    local_socket: PathBuf,
    should_stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn spawn_bridge_worker(
    stream: UnixStream,
    run: impl FnOnce(UnixStream) -> io::Result<()> + Send + 'static,
) {
    let _ = thread::spawn(move || {
        if let Err(err) = run(stream) {
            // Log, never eprintln: the bridge lives in the in-client TUI process, and a connection
            // can fail repeatedly during connect/reconnect — printing would flood the raw-mode
            // screen (issue #32 follow-up).
            tracing::warn!("remote bridge connection failed: {err}");
        }
    });
}

impl SshStdioBridge {
    fn start(
        target: SshTarget,
        remote_herdr: RemoteHerdr,
        local_socket: PathBuf,
        session_name: String,
        kind: RemoteBridgeKind,
    ) -> io::Result<Self> {
        let _ = std::fs::remove_file(&local_socket);
        // Born owner-only via the umask guard; the chmod below stays authoritative. Closes the
        // TOCTOU window where another local user could connect to the bridge socket.
        let listener = {
            let _umask = crate::ipc::UmaskGuard::restrictive();
            UnixListener::bind(&local_socket)?
        };
        crate::ipc::restrict_socket_permissions(&local_socket, BRIDGE_SOCKET_PERMISSION_MODE)?;
        listener.set_nonblocking(true)?;

        let should_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&should_stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if let Err(err) = stream.set_nonblocking(false) {
                            tracing::warn!("remote bridge failed to prepare client socket: {err}");
                            continue;
                        }
                        let worker_target = target.clone();
                        let worker_remote_herdr = remote_herdr.clone();
                        let worker_session_name = session_name.clone();
                        spawn_bridge_worker(stream, move |stream| {
                            bridge_connection(
                                stream,
                                &worker_target,
                                &worker_remote_herdr,
                                &worker_session_name,
                                kind,
                            )
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(BRIDGE_ACCEPT_POLL);
                    }
                    Err(err) => {
                        tracing::warn!("remote bridge listener failed: {err}");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_socket,
            should_stop,
            thread: Some(thread),
        })
    }
}

impl Drop for SshStdioBridge {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::Release);
        let _ = std::fs::remove_file(&self.local_socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bridge_connection(
    stream: UnixStream,
    target: &SshTarget,
    remote_herdr: &RemoteHerdr,
    session_name: &str,
    kind: RemoteBridgeKind,
) -> io::Result<()> {
    let mut command = target.command(&remote_bridge_command(remote_herdr, session_name, kind));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Never inherit the bridge ssh's stderr: this runs inside the raw-mode TUI client, so any
        // ssh chatter (host-key notices, multiplexing notes, transient warnings) would corrupt /
        // spam the screen. A genuine bridge failure surfaces as a dropped stream → reconnect, and
        // connection-setup errors are already reported by the detect/install phase.
        .stderr(Stdio::null());

    let mut child = command
        .spawn()
        .map_err(|err| io::Error::new(err.kind(), format!("failed to start ssh bridge: {err}")))?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ssh bridge stdin missing"))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ssh bridge stdout missing"))?;
    let mut stream_to_child = stream.try_clone()?;
    let mut child_to_stream = stream;

    let upload = thread::spawn(move || {
        let _ = copy_flush(&mut stream_to_child, &mut child_stdin);
    });
    let download = thread::spawn(move || {
        let _ = copy_flush(&mut child_stdout, &mut child_to_stream);
        let _ = child_to_stream.shutdown(std::net::Shutdown::Write);
    });

    let status = child.wait()?;
    let _ = upload.join();
    let _ = download.join();

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("ssh bridge exited with {status}"),
        ))
    }
}

fn copy_flush<R: io::Read, W: io::Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0;

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(bytes_read) => bytes_read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };

        writer.write_all(&buffer[..bytes_read])?;
        writer.flush()?;
        total += bytes_read as u64;
    }
}

fn run_client_process(
    local_client_socket: &Path,
    local_api_socket: &Path,
    reattach_command: &str,
    keybindings: RemoteKeybindings,
    main_remote_target: &str,
) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let status = remote_client_command(
        &exe,
        local_client_socket,
        local_api_socket,
        reattach_command,
        keybindings,
        main_remote_target,
    )
    .stdin(Stdio::inherit())
    .stdout(Stdio::inherit())
    .stderr(Stdio::inherit())
    .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("remote client exited with {status}"),
        ))
    }
}

fn remote_client_command(
    exe: &Path,
    local_client_socket: &Path,
    local_api_socket: &Path,
    reattach_command: &str,
    keybindings: RemoteKeybindings,
    main_remote_target: &str,
) -> Command {
    let mut command = Command::new(exe);
    command
        .arg("client")
        .env(
            crate::server::socket_paths::CLIENT_SOCKET_PATH_ENV_VAR,
            local_client_socket,
        )
        .env(crate::api::SOCKET_PATH_ENV_VAR, local_api_socket)
        .env("HERDR_RENDER_ENCODING", "terminal-ansi")
        .env(REATTACH_COMMAND_ENV_VAR, reattach_command)
        .env(MAIN_DISPLAY_NAME_ENV_VAR, main_remote_target)
        .env(MAIN_REMOTE_TARGET_ENV_VAR, main_remote_target)
        .env(REMOTE_KEYBINDINGS_ENV_VAR, keybindings.as_str());
    command
}

/// `reserve` keeps that many bytes of headroom under the sun_path budget so a
/// sibling path derived from this one (e.g. the api socket plus a "-client"
/// suffix) still fits.
fn local_forward_socket_path(
    target: &str,
    session_name: &str,
    kind: RemoteBridgeKind,
    reserve: usize,
) -> PathBuf {
    let pid = std::process::id();
    let target_clean = sanitize_path_component(target);
    let session_clean = sanitize_path_component(session_name);
    let kind_label = kind.path_label();

    let tmpdir = std::env::temp_dir();
    let readable = tmpdir.join(format!(
        "herdr-remote-{pid}-{target_clean}-{session_clean}-{kind_label}.sock"
    ));
    if fits_unix_socket_path(&readable, reserve) {
        return readable;
    }

    // macOS' per-user TMPDIR (~49 chars under /var/folders/...) can push the
    // readable name past sun_path's 104-byte ceiling. Fall back to a hashed
    // short name in TMPDIR, then to /tmp as a last resort when TMPDIR itself
    // is longer than the budget. The hash covers the full unsanitized
    // target/session so uniqueness does not depend on the prefix truncation;
    // the prefix is kept only for debuggability.
    let target_prefix: String = target_clean.chars().take(8).collect();
    let hash = short_socket_hash(target, session_name, kind_label);
    let short_name = format!("herdr-r-{pid}-{target_prefix}-{kind_label}.{hash}.sock");
    let short_in_tmp = tmpdir.join(&short_name);
    if fits_unix_socket_path(&short_in_tmp, reserve) {
        return short_in_tmp;
    }
    PathBuf::from("/tmp").join(short_name)
}

fn remote_bridge_socket_paths(target: &str, session_name: &str) -> RemoteBridgePaths {
    // The CLI-attach child (`herdr client`) re-derives its client socket from
    // HERDR_SOCKET_PATH (the api socket), and that derivation outranks the explicit
    // HERDR_CLIENT_SOCKET_PATH we also pass (see
    // server::socket_paths::client_socket_path_from_overrides). Bind the client
    // bridge at exactly the derived path so both views agree; the api path keeps
    // headroom for the appended "-client".
    let api_socket =
        local_forward_socket_path(target, session_name, RemoteBridgeKind::Api, "-client".len());
    let client_socket =
        crate::server::socket_paths::derive_client_socket_from_api_socket(&api_socket);
    RemoteBridgePaths {
        client_socket,
        api_socket,
    }
}

fn fits_unix_socket_path(path: &Path, reserve: usize) -> bool {
    use std::os::unix::ffi::OsStrExt;
    // sun_path is byte-limited: 104 bytes on macOS, 108 on Linux. Reserve
    // 1 byte for the trailing NUL and use the smaller cap for portability.
    const MAX: usize = 103;
    path.as_os_str().as_bytes().len() + reserve <= MAX
}

fn short_socket_hash(target: &str, session: &str, kind: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    0u8.hash(&mut hasher);
    session.hash(&mut hasher);
    0u8.hash(&mut hasher);
    kind.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn sanitize_path_component(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect();

    sanitized.trim_matches('-').chars().take(32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_argv(target: &SshTarget, remote_command: &str) -> Vec<String> {
        target
            .command(remote_command)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn ssh_target_command_inserts_dash_t_before_bare_destination() {
        assert_eq!(
            ssh_argv(&SshTarget::bare("iq-64"), "uname -s"),
            [
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ClearAllForwardings=yes",
                "-T",
                "iq-64",
                "uname -s"
            ]
        );
    }

    #[test]
    fn ssh_target_command_emits_options_before_destination() {
        // An explicit user `-L` keeps its forward: ClearAllForwardings is NOT injected,
        // since it would clear command-line forwards too.
        let target = SshTarget::new(
            "iq-64",
            vec![
                "-L".into(),
                "9000:localhost:9000".into(),
                "-J".into(),
                "jump".into(),
            ],
        );
        assert_eq!(
            ssh_argv(&target, "uname -s"),
            [
                "-o",
                "ConnectTimeout=10",
                "-L",
                "9000:localhost:9000",
                "-J",
                "jump",
                "-T",
                "iq-64",
                "uname -s"
            ]
        );
    }

    #[test]
    fn ssh_target_command_clears_config_forwardings_without_user_forwards() {
        // ssh_config-inherited LocalForward/RemoteForward must not leak into herdr's
        // exec/bridge sessions: a held forward port (the user's own interactive ssh, or a
        // sibling herdr bridge) would fail every connection with `bind: Address already in
        // use`. Non-forwarding user options keep the clear.
        let target = SshTarget::new("iq-64", vec!["-J".into(), "jump".into()]);
        let argv = ssh_argv(&target, "x");
        assert!(argv
            .windows(2)
            .any(|pair| pair == ["-o", "ClearAllForwardings=yes"]));

        // Any explicit forward flag (or an explicit ClearAllForwardings) disables it.
        for forward in [vec!["-D".into(), "1080".into()], vec!["-R8000:h:80".into()]] {
            let target = SshTarget::new("iq-64", forward);
            let argv = ssh_argv(&target, "x");
            assert!(!argv.contains(&"ClearAllForwardings=yes".to_string()));
        }
        let target = SshTarget::new("iq-64", vec!["-o".into(), "ClearAllForwardings=no".into()]);
        let argv = ssh_argv(&target, "x");
        assert!(!argv.contains(&"ClearAllForwardings=yes".to_string()));
    }

    #[test]
    fn ssh_target_command_does_not_duplicate_user_supplied_dash_t() {
        let target = SshTarget::new("iq-64", vec!["-T".into()]);
        assert_eq!(
            ssh_argv(&target, "x"),
            [
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ClearAllForwardings=yes",
                "-T",
                "iq-64",
                "x"
            ]
        );
    }

    #[test]
    fn ssh_target_command_respects_user_connect_timeout() {
        let target = SshTarget::new("iq-64", vec!["-o".into(), "ConnectTimeout=3".into()]);
        assert_eq!(
            ssh_argv(&target, "x"),
            [
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ConnectTimeout=3",
                "-T",
                "iq-64",
                "x"
            ]
        );
    }

    fn probe_lines(version: &str, protocol: u32, bridge_ok: bool) -> String {
        format!(
            "HERDR_PROBE_VERSION {version}\nHERDR_PROBE_STATUS {{\"protocol\":{protocol}}}\n{}\n",
            if bridge_ok {
                "HERDR_PROBE_BRIDGE_OK"
            } else {
                "HERDR_PROBE_BRIDGE_MISSING"
            }
        )
    }

    #[test]
    fn probe_reports_compatible_for_matching_binary() {
        let stdout = probe_lines(&format!("herdr {CURRENT_VERSION}"), CURRENT_PROTOCOL, true);
        assert_eq!(
            interpret_remote_binary_probe(&stdout),
            RemoteBinaryCheck::Compatible
        );
    }

    #[test]
    fn probe_reports_protocol_mismatch_when_version_matches_but_protocol_is_old() {
        // The dev2 case: version 0.6.4 matched, but the installed asset spoke protocol 6.
        let stdout = probe_lines(&format!("herdr {CURRENT_VERSION}"), 6, true);
        assert_eq!(
            interpret_remote_binary_probe(&stdout),
            RemoteBinaryCheck::ProtocolMismatch { reported: Some(6) }
        );
    }

    #[test]
    fn probe_reports_missing_bridge_when_subcommands_absent() {
        let stdout = probe_lines(&format!("herdr {CURRENT_VERSION}"), CURRENT_PROTOCOL, false);
        assert_eq!(
            interpret_remote_binary_probe(&stdout),
            RemoteBinaryCheck::MissingBridgeSupport
        );
    }

    #[test]
    fn probe_reports_version_mismatch_before_protocol() {
        let stdout = probe_lines("herdr 0.5.10", 6, true);
        assert_eq!(
            interpret_remote_binary_probe(&stdout),
            RemoteBinaryCheck::VersionMismatch {
                reported: "herdr 0.5.10".to_string()
            }
        );
    }

    #[test]
    fn probe_reports_not_executable_and_unintelligible() {
        assert_eq!(
            interpret_remote_binary_probe("HERDR_PROBE_NOT_EXECUTABLE\n"),
            RemoteBinaryCheck::NotExecutable
        );
        assert_eq!(
            interpret_remote_binary_probe("HERDR_PROBE_NO_VERSION\n"),
            RemoteBinaryCheck::Unintelligible
        );
        assert_eq!(
            interpret_remote_binary_probe(""),
            RemoteBinaryCheck::Unintelligible
        );
    }

    #[test]
    fn protocol_mismatch_install_message_is_actionable_and_not_about_version() {
        let msg = RemoteBinaryCheck::ProtocolMismatch { reported: Some(6) }
            .install_failure_message("$HOME/.local/bin/herdr");
        assert!(msg.contains("protocol 6"));
        assert!(msg.contains("HERDR_REMOTE_BINARY"));
        assert!(
            !msg.contains("did not report version"),
            "protocol mismatch must not be reported as a version problem: {msg}"
        );
    }

    #[test]
    fn non_interactive_attaches_to_protocol_compatible_running_server_without_handoff() {
        // Version/binary differs but protocol matches: attach to the running server, no restart.
        for reason in [
            RemoteServerRestartReason::VersionMismatch,
            RemoteServerRestartReason::BinaryUpdated,
        ] {
            assert_eq!(
                non_interactive_server_action(reason, false, false),
                NonInteractiveServerAction::AttachExisting
            );
            // Even if handoff is enabled, an unsupported server still attaches as-is.
            assert_eq!(
                non_interactive_server_action(reason, true, false),
                NonInteractiveServerAction::AttachExisting
            );
        }
    }

    #[test]
    fn non_interactive_prefers_live_handoff_when_available() {
        for reason in [
            RemoteServerRestartReason::ProtocolMismatch,
            RemoteServerRestartReason::VersionMismatch,
            RemoteServerRestartReason::BinaryUpdated,
        ] {
            assert_eq!(
                non_interactive_server_action(reason, true, true),
                NonInteractiveServerAction::LiveHandoff
            );
        }
    }

    #[test]
    fn non_interactive_protocol_mismatch_without_handoff_is_stuck_not_hard_stopped() {
        // The key safety property: a protocol mismatch we cannot hand off is reported as stuck,
        // never resolved by hard-stopping (which would kill the remote server's panes).
        assert_eq!(
            non_interactive_server_action(RemoteServerRestartReason::ProtocolMismatch, true, false),
            NonInteractiveServerAction::ProtocolStuck
        );
        assert_eq!(
            non_interactive_server_action(RemoteServerRestartReason::ProtocolMismatch, false, true),
            NonInteractiveServerAction::ProtocolStuck
        );
    }

    #[test]
    fn bridge_socket_is_user_only() {
        use std::os::unix::fs::PermissionsExt;

        let socket = std::env::temp_dir().join(format!(
            "herdr-bridge-permissions-test-{}.sock",
            std::process::id()
        ));
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let bridge = SshStdioBridge::start(
            SshTarget::bare("example"),
            remote_herdr,
            socket.clone(),
            "default".to_string(),
            RemoteBridgeKind::Client,
        )
        .expect("start bridge listener");

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, BRIDGE_SOCKET_PERMISSION_MODE);

        drop(bridge);
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn bridge_worker_returns_before_connection_finishes() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();

        let start = Instant::now();
        spawn_bridge_worker(stream, move |_| {
            thread::sleep(Duration::from_millis(200));
            finished_tx.send(()).unwrap();
            Ok(())
        });

        assert!(start.elapsed() < Duration::from_millis(50));
        assert!(finished_rx.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn extract_remote_args_removes_space_form() {
        let args = vec![
            "herdr".into(),
            "--remote".into(),
            "dev".into(),
            "--help".into(),
        ];
        let (cleaned, remote) = extract_remote_args(&args).unwrap();
        assert_eq!(cleaned, vec!["herdr", "--help"]);
        let remote = remote.unwrap();
        assert_eq!(remote.target, "dev");
        assert_eq!(remote.keybindings, RemoteKeybindings::Local);
    }

    #[test]
    fn extract_remote_args_removes_equals_form() {
        let args = vec!["herdr".into(), "--remote=user@host".into()];
        let (cleaned, remote) = extract_remote_args(&args).unwrap();
        assert_eq!(cleaned, vec!["herdr"]);
        let remote = remote.unwrap();
        assert_eq!(remote.target, "user@host");
        assert_eq!(remote.keybindings, RemoteKeybindings::Local);
    }

    #[test]
    fn extract_remote_args_accepts_remote_keybindings_server() {
        let args = vec![
            "herdr".into(),
            "--remote".into(),
            "dev".into(),
            "--remote-keybindings=server".into(),
        ];
        let (cleaned, remote) = extract_remote_args(&args).unwrap();
        assert_eq!(cleaned, vec!["herdr"]);
        let remote = remote.unwrap();
        assert_eq!(remote.target, "dev");
        assert_eq!(remote.keybindings, RemoteKeybindings::Server);
    }

    #[test]
    fn extract_remote_args_accepts_remote_keybindings_space_form() {
        let args = vec![
            "herdr".into(),
            "--remote=dev".into(),
            "--remote-keybindings".into(),
            "server".into(),
        ];
        let (cleaned, remote) = extract_remote_args(&args).unwrap();
        assert_eq!(cleaned, vec!["herdr"]);
        assert_eq!(remote.unwrap().keybindings, RemoteKeybindings::Server);
    }

    #[test]
    fn extract_remote_args_accepts_explicit_handoff() {
        let args = vec!["herdr".into(), "--remote=dev".into(), "--handoff".into()];

        let (cleaned, remote) = extract_remote_args(&args).unwrap();

        assert_eq!(cleaned, vec!["herdr"]);
        let remote = remote.unwrap();
        assert_eq!(remote.target, "dev");
        assert!(remote.live_handoff);
    }

    #[test]
    fn extract_remote_args_preserves_handoff_without_remote() {
        let args = vec!["herdr".into(), "update".into(), "--handoff".into()];

        let (cleaned, remote) = extract_remote_args(&args).unwrap();

        assert_eq!(cleaned, args);
        assert!(remote.is_none());
    }

    #[test]
    fn extract_remote_args_rejects_remote_keybindings_without_remote() {
        let args = vec!["herdr".into(), "--remote-keybindings=server".into()];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "--remote-keybindings requires --remote");
    }

    #[test]
    fn extract_remote_args_rejects_duplicate_remote_keybindings() {
        let args = vec![
            "herdr".into(),
            "--remote=dev".into(),
            "--remote-keybindings=local".into(),
            "--remote-keybindings=server".into(),
        ];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "--remote-keybindings can only be specified once");
    }

    #[test]
    fn extract_remote_args_requires_value() {
        let args = vec!["herdr".into(), "--remote".into()];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "missing value for --remote");
    }

    #[test]
    fn extract_remote_args_rejects_empty_value() {
        let args = vec!["herdr".into(), "--remote=".into()];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "missing value for --remote");
    }

    #[test]
    fn extract_remote_args_rejects_duplicate_values() {
        let args = vec![
            "herdr".into(),
            "--remote=dev".into(),
            "--remote=prod".into(),
        ];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "--remote can only be specified once");
    }

    #[test]
    fn extract_remote_args_rejects_option_like_target() {
        let args = vec!["herdr".into(), "--remote".into(), "-oProxyCommand=x".into()];
        let err = extract_remote_args(&args).unwrap_err();
        assert_eq!(err, "--remote target must not start with '-'");
    }

    #[test]
    fn sanitize_path_component_removes_shell_sensitive_chars() {
        assert_eq!(sanitize_path_component("user@host:22"), "user-host-22");
    }

    #[test]
    fn remote_platform_maps_uname_values() {
        assert_eq!(
            RemotePlatform::from_uname("Linux", "amd64")
                .unwrap()
                .asset_key(),
            "linux-x86_64"
        );
        assert_eq!(
            RemotePlatform::from_uname("Darwin", "arm64")
                .unwrap()
                .asset_key(),
            "macos-aarch64"
        );
        assert!(RemotePlatform::from_uname("FreeBSD", "x86_64").is_none());
    }

    #[test]
    fn reattach_command_includes_remote_and_session() {
        assert_eq!(
            reattach_command(
                "target/release/herdr",
                "user@host",
                "work",
                RemoteKeybindings::Local,
                false,
            ),
            "target/release/herdr --remote user@host --session work"
        );
        assert_eq!(
            reattach_command(
                "herdr",
                "host name",
                crate::session::DEFAULT_SESSION_NAME,
                RemoteKeybindings::Local,
                false,
            ),
            "herdr --remote 'host name'"
        );
        assert_eq!(
            reattach_command(
                "herdr",
                "host",
                crate::session::DEFAULT_SESSION_NAME,
                RemoteKeybindings::Server,
                false,
            ),
            "herdr --remote host --remote-keybindings server"
        );
        assert_eq!(
            reattach_command(
                "herdr",
                "host",
                crate::session::DEFAULT_SESSION_NAME,
                RemoteKeybindings::Local,
                true,
            ),
            "herdr --remote host --handoff"
        );
    }

    #[test]
    fn remote_client_command_sets_main_target_metadata_env() {
        let command = remote_client_command(
            Path::new("/tmp/herdr"),
            Path::new("/tmp/herdr-client.sock"),
            Path::new("/tmp/herdr-api.sock"),
            "herdr --remote iq-64",
            RemoteKeybindings::Local,
            "iq-64",
        );
        let envs: BTreeMap<String, Option<String>> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().to_string(),
                    value.map(|value| value.to_string_lossy().to_string()),
                )
            })
            .collect();

        assert_eq!(
            envs.get(MAIN_DISPLAY_NAME_ENV_VAR),
            Some(&Some("iq-64".to_string()))
        );
        assert_eq!(
            envs.get(MAIN_REMOTE_TARGET_ENV_VAR),
            Some(&Some("iq-64".to_string()))
        );
        assert_eq!(
            envs.get(crate::api::SOCKET_PATH_ENV_VAR),
            Some(&Some("/tmp/herdr-api.sock".to_string()))
        );
    }

    #[test]
    fn remote_bridge_command_uses_installed_binary() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Client,
            ),
            "exec \"$HOME/.local/bin/herdr\" remote-client-bridge"
        );
        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Api,
            ),
            "exec \"$HOME/.local/bin/herdr\" remote-api-bridge"
        );
    }

    #[test]
    fn remote_path_probe_uses_path_binary_when_version_matches() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let stdout = matching_path_probe_stdout("/usr/bin/herdr");
        let remote_herdr =
            remote_herdr_from_path_probe(&remote_herdr, &stdout).expect("matching path binary");

        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Client,
            ),
            "exec /usr/bin/herdr remote-client-bridge"
        );
    }

    #[test]
    fn remote_path_probe_quotes_discovered_binary() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let stdout = matching_path_probe_stdout("/opt/herdr bin/herdr");
        let remote_herdr =
            remote_herdr_from_path_probe(&remote_herdr, &stdout).expect("matching path binary");

        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Client,
            ),
            "exec '/opt/herdr bin/herdr' remote-client-bridge"
        );
    }

    #[test]
    fn remote_path_probe_uses_macos_path_binary_when_version_matches() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "macos",
            arch: "aarch64",
        });
        let stdout = matching_path_probe_stdout("/opt/homebrew/bin/herdr");
        let remote_herdr =
            remote_herdr_from_path_probe(&remote_herdr, &stdout).expect("matching path binary");

        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Client,
            ),
            "exec /opt/homebrew/bin/herdr remote-client-bridge"
        );
        assert_eq!(remote_herdr.platform.asset_key(), "macos-aarch64");
    }

    #[test]
    fn remote_path_probe_quotes_single_quotes_in_discovered_binary() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let stdout = matching_path_probe_stdout("/opt/herdr's/bin/herdr");
        let remote_herdr =
            remote_herdr_from_path_probe(&remote_herdr, &stdout).expect("matching path binary");

        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Client,
            ),
            "exec '/opt/herdr'\\''s/bin/herdr' remote-client-bridge"
        );
    }

    #[test]
    fn remote_binary_match_command_requires_bridge_probe() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "macos",
            arch: "aarch64",
        });

        assert_eq!(
            remote_binary_match_command(&remote_herdr),
            "test -x \"$HOME/.local/bin/herdr\" && \"$HOME/.local/bin/herdr\" --version && \"$HOME/.local/bin/herdr\" status client --json && HERDR_REMOTE_BRIDGE_PROBE=1 \"$HOME/.local/bin/herdr\" remote-client-bridge && HERDR_REMOTE_BRIDGE_PROBE=1 \"$HOME/.local/bin/herdr\" remote-api-bridge"
        );
    }

    #[test]
    fn remote_herdr_from_exe_name_uses_commit_labeled_binary() {
        let platform = RemotePlatform {
            os: "macos",
            arch: "aarch64",
        };
        let remote_herdr =
            remote_herdr_from_exe_name(platform, "herdr-39986ed").expect("commit binary");

        assert_eq!(
            remote_bridge_command(
                &remote_herdr,
                crate::session::DEFAULT_SESSION_NAME,
                RemoteBridgeKind::Api,
            ),
            "exec \"$HOME/.local/bin/herdr-39986ed\" remote-api-bridge"
        );
    }

    #[test]
    fn remote_herdr_from_exe_name_skips_plain_binary_name() {
        let platform = RemotePlatform {
            os: "macos",
            arch: "aarch64",
        };

        assert!(remote_herdr_from_exe_name(platform, "herdr").is_none());
    }

    #[test]
    fn remote_path_probe_ignores_version_mismatch() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let remote_herdr = remote_herdr_from_path_probe(
            &remote_herdr,
            &format!("/usr/bin/herdr\nherdr 0.0.0\n{{\"protocol\":{CURRENT_PROTOCOL}}}\n"),
        );

        assert!(remote_herdr.is_none());
    }

    #[test]
    fn remote_path_probe_ignores_relative_paths() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let stdout = matching_path_probe_stdout("bin/herdr");
        let remote_herdr = remote_herdr_from_path_probe(&remote_herdr, &stdout);

        assert!(remote_herdr.is_none());
    }

    #[test]
    fn remote_path_probe_ignores_protocol_mismatch() {
        let remote_herdr = RemoteHerdr::for_platform(RemotePlatform {
            os: "linux",
            arch: "x86_64",
        });
        let stdout = format!("/usr/bin/herdr\nherdr {CURRENT_VERSION}\n{{\"protocol\":0}}\n");
        let remote_herdr = remote_herdr_from_path_probe(&remote_herdr, &stdout);

        assert!(remote_herdr.is_none());
    }

    #[test]
    fn parse_client_status_json_reads_protocol() {
        assert_eq!(
            parse_client_status_json(r#"{"version":"x","protocol":8,"binary":"/bin/herdr"}"#)
                .map(|status| status.protocol),
            Some(8)
        );
        assert!(parse_client_status_json(r#"{"protocol":"unknown"}"#).is_none());
    }

    #[test]
    fn parse_remote_server_status_json_reads_running_server() {
        assert_eq!(
            parse_remote_server_status_json(
                r#"{"status":"running","running":true,"version":"0.6.0","protocol":8,"capabilities":{"live_handoff":true}}"#
            )
            .unwrap(),
            RemoteServerStatus::Running {
                version: Some("0.6.0".into()),
                protocol: Some(8),
                live_handoff: true
            }
        );
    }

    #[test]
    fn parse_remote_server_status_json_treats_missing_capability_as_no_handoff() {
        assert_eq!(
            parse_remote_server_status_json(
                r#"{"status":"running","running":true,"version":"0.6.0","protocol":8}"#
            )
            .unwrap(),
            RemoteServerStatus::Running {
                version: Some("0.6.0".into()),
                protocol: Some(8),
                live_handoff: false
            }
        );
    }

    #[test]
    fn parse_remote_server_status_json_reads_stopped_server() {
        assert_eq!(
            parse_remote_server_status_json(
                r#"{"status":"not_running","running":false,"version":null,"protocol":null}"#
            )
            .unwrap(),
            RemoteServerStatus::NotRunning
        );
    }

    #[test]
    fn remote_update_manifest_uses_root_assets_for_latest_version() {
        let manifest: RemoteUpdateManifest = serde_json::from_str(
            r#"{
                "version": "1.2.3",
                "assets": {
                    "linux-x86_64": "https://example.com/latest"
                },
                "releases": {
                    "1.2.3": {
                        "assets": {
                            "linux-x86_64": "https://example.com/archive"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            manifest
                .release_for_version("1.2.3")
                .and_then(|release| release.assets.get("linux-x86_64"))
                .map(|asset| asset.url.as_str()),
            Some("https://example.com/latest")
        );
    }

    #[test]
    fn remote_update_manifest_reads_archived_release_assets() {
        let manifest: RemoteUpdateManifest = serde_json::from_str(
            r#"{
                "version": "1.2.4",
                "assets": {
                    "linux-x86_64": "https://example.com/latest"
                },
                "releases": {
                    "1.2.3": {
                        "notes": "ignored",
                        "assets": {
                            "linux-x86_64": "https://example.com/archive"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            manifest
                .release_for_version("1.2.3")
                .and_then(|release| release.assets.get("linux-x86_64"))
                .map(|asset| asset.url.as_str()),
            Some("https://example.com/archive")
        );
    }

    #[test]
    fn remote_asset_parses_object_with_sha256_and_sig() {
        let manifest: RemoteUpdateManifest = serde_json::from_str(
            r#"{
                "version": "1.2.3",
                "assets": {
                    "linux-x86_64": {
                        "url": "https://example.com/herdr-linux-x86_64",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "sig": "https://example.com/herdr-linux-x86_64.sig"
                    }
                }
            }"#,
        )
        .unwrap();
        let asset = manifest.assets.get("linux-x86_64").unwrap();
        assert_eq!(asset.url, "https://example.com/herdr-linux-x86_64");
        assert_eq!(
            asset.sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            asset.sig_url(),
            "https://example.com/herdr-linux-x86_64.sig"
        );
    }

    #[test]
    fn remote_asset_sig_url_defaults_to_minisig_sidecar() {
        let asset = RemoteAsset {
            url: "https://example.com/herdr-linux".into(),
            sha256: None,
            sig: None,
        };
        assert_eq!(asset.sig_url(), "https://example.com/herdr-linux.minisig");
    }

    #[test]
    fn verify_optional_sha256_accepts_missing_hash() {
        let dir = std::env::temp_dir().join(format!("herdr-verify-none-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("herdr.tmp");
        fs::write(&path, b"binary").unwrap();
        // No advertised hash: the optional pre-check passes; the (mandatory) signature is enforced
        // separately by verify_downloaded_asset.
        let asset = RemoteAsset {
            url: "https://example.com/herdr".into(),
            sha256: None,
            sig: None,
        };
        verify_optional_sha256(&path, &asset).expect("missing hash is allowed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_optional_sha256_rejects_mismatch() {
        let dir = std::env::temp_dir().join(format!("herdr-verify-mm-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("herdr.tmp");
        fs::write(&path, b"binary").unwrap();
        // Wrong (but well-formed) hash fails the pre-check, before any signature fetch.
        let asset = RemoteAsset {
            url: "https://example.com/herdr".into(),
            sha256: Some("0".repeat(64)),
            sig: None,
        };
        let err = verify_optional_sha256(&path, &asset).expect_err("bad sha256 must fail");
        assert!(err.to_string().contains("sha256 mismatch"), "got: {err}");
        let _ = fs::remove_dir_all(&dir);
    }

    struct RestoreEnv(&'static str, Option<std::ffi::OsString>);
    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            match self.1.take() {
                Some(v) => std::env::set_var(self.0, v),
                None => std::env::remove_var(self.0),
            }
        }
    }

    #[test]
    fn verify_override_binary_warns_but_allows_missing_sidecar_by_default() {
        let _guard = remote_env_lock().lock().unwrap();
        let _restore = RestoreEnv(
            REMOTE_BINARY_REQUIRE_SIG_ENV_VAR,
            std::env::var_os(REMOTE_BINARY_REQUIRE_SIG_ENV_VAR),
        );
        std::env::remove_var(REMOTE_BINARY_REQUIRE_SIG_ENV_VAR);

        let dir =
            std::env::temp_dir().join(format!("herdr-override-default-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("herdr");
        fs::write(&path, b"binary").unwrap();
        // No sibling .minisig and no strict env: operator-provided override is seeded with a warning.
        verify_override_binary(&path).expect("missing sidecar is allowed by default");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_override_binary_requires_signature_when_env_set() {
        let _guard = remote_env_lock().lock().unwrap();
        let _restore = RestoreEnv(
            REMOTE_BINARY_REQUIRE_SIG_ENV_VAR,
            std::env::var_os(REMOTE_BINARY_REQUIRE_SIG_ENV_VAR),
        );
        std::env::set_var(REMOTE_BINARY_REQUIRE_SIG_ENV_VAR, "1");

        let dir =
            std::env::temp_dir().join(format!("herdr-override-strict-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("herdr");
        fs::write(&path, b"binary").unwrap();
        // With the strict env set, a missing sidecar fails closed instead of warning.
        let err = verify_override_binary(&path).expect_err("missing sidecar must fail closed");
        assert!(
            err.to_string()
                .contains("refusing to seed an unverified binary"),
            "got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_update_manifest_uses_archived_release_protocol() {
        let manifest: RemoteUpdateManifest = serde_json::from_str(
            r#"{
                "version": "1.2.4",
                "protocol": 42,
                "assets": {
                    "linux-x86_64": "https://example.com/latest"
                },
                "releases": {
                    "1.2.3": {
                        "notes": "ignored",
                        "protocol": 41,
                        "assets": {
                            "linux-x86_64": "https://example.com/archive"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            manifest
                .release_for_version("1.2.3")
                .and_then(|release| release.protocol),
            Some(41)
        );
    }

    #[test]
    fn remote_update_manifest_does_not_inherit_latest_protocol_for_archived_assets() {
        let manifest: RemoteUpdateManifest = serde_json::from_str(
            r#"{
                "version": "1.2.4",
                "protocol": 42,
                "assets": {
                    "linux-x86_64": "https://example.com/latest"
                },
                "releases": {
                    "1.2.3": {
                        "notes": "ignored",
                        "assets": {
                            "linux-x86_64": "https://example.com/archive"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            manifest
                .release_for_version("1.2.3")
                .and_then(|release| release.protocol),
            None
        );
    }

    #[test]
    fn remote_server_restart_reason_requires_stop_for_protocol_mismatch() {
        assert_eq!(
            remote_server_restart_reason(Some(CURRENT_VERSION), Some(0), false),
            Some(RemoteServerRestartReason::ProtocolMismatch)
        );
    }

    #[test]
    fn remote_server_restart_reason_offers_restart_after_binary_update() {
        assert_eq!(
            remote_server_restart_reason(Some(CURRENT_VERSION), Some(CURRENT_PROTOCOL), true),
            Some(RemoteServerRestartReason::BinaryUpdated)
        );
    }

    #[test]
    fn remote_server_restart_reason_offers_restart_for_version_mismatch() {
        assert_eq!(
            remote_server_restart_reason(Some("0.0.0"), Some(CURRENT_PROTOCOL), false),
            Some(RemoteServerRestartReason::VersionMismatch)
        );
        assert_eq!(
            remote_server_restart_reason(None, Some(CURRENT_PROTOCOL), false),
            Some(RemoteServerRestartReason::VersionMismatch)
        );
    }

    #[test]
    fn remote_server_restart_reason_allows_current_server() {
        assert_eq!(
            remote_server_restart_reason(Some(CURRENT_VERSION), Some(CURRENT_PROTOCOL), false),
            None
        );
    }

    #[test]
    fn install_source_description_uses_override_binary() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "aarch64",
        };
        assert_eq!(
            install_source_description_for(
                &platform,
                Some(Path::new("/tmp/herdr-aarch64")),
                NonOverrideSeed::Download
            ),
            "HERDR_REMOTE_BINARY (/tmp/herdr-aarch64)"
        );
    }

    #[test]
    fn install_source_description_uses_local_binary_when_allowed() {
        let platform = RemotePlatform::local();

        assert_eq!(
            install_source_description_for(&platform, None, NonOverrideSeed::LocalExe),
            "the current local herdr binary"
        );
    }

    #[test]
    fn install_source_description_uses_release_asset_when_local_binary_cannot_seed_remote() {
        let platform = RemotePlatform::local();

        assert_eq!(
            install_source_description_for(&platform, None, NonOverrideSeed::Download),
            format!(
                "the {CURRENT_VERSION} release asset for {}",
                platform.asset_key()
            )
        );
    }

    #[test]
    fn install_source_description_uses_bundled_binary_for_cross_platform_build() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        assert_eq!(
            install_source_description_for(&platform, None, NonOverrideSeed::Bundle),
            "the linux-x86_64 fat bundle repacked from this multi-platform build"
        );
    }

    fn test_bundle_index(
        version: &str,
        commit: Option<&str>,
        entries: &[(&str, &str)],
    ) -> crate::bundle::BundleIndex {
        crate::bundle::BundleIndex {
            format: 2,
            herdr_version: version.to_string(),
            build_commit: commit.map(str::to_string),
            image_len: 0,
            entries: entries
                .iter()
                .map(|(os, arch)| crate::bundle::BundleEntry {
                    os: (*os).to_string(),
                    arch: (*arch).to_string(),
                    offset: 0,
                    compressed_len: 0,
                    uncompressed_len: 0,
                    crc32: 0,
                    sha256: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn bundle_seeds_platform_requires_version_match_and_entry() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let index = test_bundle_index(
            CURRENT_VERSION,
            None,
            &[("linux", "x86_64"), ("macos", "aarch64")],
        );
        assert!(bundle_seeds_platform(
            &index,
            &platform,
            CURRENT_VERSION,
            None
        ));

        // A bundle built at a different version is never usable.
        assert!(!bundle_seeds_platform(
            &index,
            &platform,
            "0.0.0-other",
            None
        ));

        // No carried entry for the requested os/arch.
        let missing = RemotePlatform {
            os: "linux",
            arch: "aarch64",
        };
        assert!(!bundle_seeds_platform(
            &index,
            &missing,
            CURRENT_VERSION,
            None
        ));
    }

    #[test]
    fn bundle_seeds_platform_enforces_commit_when_both_known() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let index = test_bundle_index(CURRENT_VERSION, Some("abc123"), &[("linux", "x86_64")]);
        assert!(bundle_seeds_platform(
            &index,
            &platform,
            CURRENT_VERSION,
            Some("abc123")
        ));
        // Same version but a different commit must not be silently seeded.
        assert!(!bundle_seeds_platform(
            &index,
            &platform,
            CURRENT_VERSION,
            Some("def456")
        ));
        // Commit unknown on one side falls back to a version-only match.
        assert!(bundle_seeds_platform(
            &index,
            &platform,
            CURRENT_VERSION,
            None
        ));
    }

    #[test]
    fn choose_seed_source_prefers_local_then_bundle_then_download() {
        assert_eq!(choose_seed_source(true, true), NonOverrideSeed::LocalExe);
        assert_eq!(choose_seed_source(true, false), NonOverrideSeed::LocalExe);
        assert_eq!(choose_seed_source(false, true), NonOverrideSeed::Bundle);
        assert_eq!(choose_seed_source(false, false), NonOverrideSeed::Download);
    }

    #[test]
    fn can_seed_remote_without_download_refuses_unbuildable_platform() {
        let _guard = remote_env_lock().lock().unwrap();
        // Ensure no override is set so the classification path is exercised; restore on exit.
        let saved_override = std::env::var_os(REMOTE_BINARY_ENV_VAR);
        std::env::remove_var(REMOTE_BINARY_ENV_VAR);
        struct RestoreOverride(Option<std::ffi::OsString>);
        impl Drop for RestoreOverride {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var(REMOTE_BINARY_ENV_VAR, v),
                    None => std::env::remove_var(REMOTE_BINARY_ENV_VAR),
                }
            }
        }
        let _restore = RestoreOverride(saved_override);

        // A foreign os/arch that this from-source build can neither run locally nor bundle classifies
        // as Download — so it CANNOT be seeded without an internet download.
        let unbuildable = RemotePlatform {
            os: if RemotePlatform::local().os == "linux" {
                "macos"
            } else {
                "linux"
            },
            arch: if RemotePlatform::local().arch == "x86_64" {
                "aarch64"
            } else {
                "x86_64"
            },
        };
        assert_eq!(
            classify_seed_source(&unbuildable),
            NonOverrideSeed::Download
        );
        assert!(
            !can_seed_remote_without_download(&unbuildable),
            "an unbuildable (Download-only) platform refuses a download-free seed"
        );

        // The local platform seeds from the running exe (a from-source test binary is not package-
        // manager-managed) — so it CAN be seeded without a download.
        let local = RemotePlatform::local();
        if classify_seed_source(&local) != NonOverrideSeed::Download {
            assert!(
                can_seed_remote_without_download(&local),
                "a locally-seedable platform allows a download-free seed"
            );
        }
    }

    #[test]
    fn resolve_install_source_uses_override_binary_without_temporary_cleanup() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "aarch64",
        };
        let source = resolve_install_source(&platform, Some(PathBuf::from("/tmp/herdr-aarch64")))
            .expect("override source");
        assert_eq!(source.path, PathBuf::from("/tmp/herdr-aarch64"));
        assert!(source.temporary_dir.is_none());
    }

    fn matching_path_probe_stdout(path: &str) -> String {
        format!("{path}\nherdr {CURRENT_VERSION}\n{{\"protocol\":{CURRENT_PROTOCOL}}}\n")
    }

    fn remote_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn socket_path_byte_len(path: &Path) -> usize {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }

    #[test]
    fn local_forward_socket_path_uses_readable_name_when_it_fits() {
        let _guard = remote_env_lock().lock().unwrap();
        // Short target + session leave plenty of room — keep the human-
        // readable form so the socket path stays grep-friendly.
        let path = local_forward_socket_path("dev", "default", RemoteBridgeKind::Client, 0);
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        assert!(
            filename.starts_with("herdr-remote-"),
            "expected readable name, got {filename}"
        );
        assert!(filename.contains("-dev-default-client."), "got {filename}");
        let api_path = local_forward_socket_path("dev", "default", RemoteBridgeKind::Api, 0);
        assert_ne!(path, api_path);
        assert!(
            fits_unix_socket_path(&path, 0),
            "socket path too long: {} ({} bytes)",
            path.display(),
            socket_path_byte_len(&path)
        );
    }

    #[test]
    fn remote_bridge_socket_paths_are_distinct_for_client_and_api() {
        let paths = remote_bridge_socket_paths("prod.example.com", "default");

        assert_ne!(paths.client_socket, paths.api_socket);
        assert!(paths
            .client_socket
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .contains("-client."));
        assert!(paths
            .api_socket
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .contains("-api."));
        assert!(fits_unix_socket_path(&paths.client_socket, 0));
        assert!(fits_unix_socket_path(&paths.api_socket, 0));
    }

    #[test]
    fn remote_bridge_client_socket_matches_child_api_derivation() {
        let _guard = remote_env_lock().lock().unwrap();
        // The CLI-attach child (`herdr client`) re-derives its client socket from
        // HERDR_SOCKET_PATH; that derivation outranks the explicit
        // HERDR_CLIENT_SOCKET_PATH we also pass (see
        // server::socket_paths::client_socket_path_from_overrides). The bridge must
        // bind exactly the derived path or the child connects to a socket nobody
        // listens on and exits immediately.
        let paths = remote_bridge_socket_paths("dev2-gv", "default");
        assert_eq!(
            paths.client_socket,
            crate::server::socket_paths::derive_client_socket_from_api_socket(&paths.api_socket),
        );
    }

    #[test]
    fn remote_bridge_client_socket_fits_even_when_api_uses_hashed_fallback() {
        let _guard = remote_env_lock().lock().unwrap();
        // Deriving the client path appends "-client" to the api name, so the api
        // path must reserve that headroom under the sun_path budget even in the
        // hashed-fallback regime.
        let paths = remote_bridge_socket_paths(
            "longish-host.example.com",
            "a-fairly-long-session-name-here",
        );
        assert!(
            fits_unix_socket_path(&paths.api_socket, 0),
            "api path too long: {} ({} bytes)",
            paths.api_socket.display(),
            socket_path_byte_len(&paths.api_socket)
        );
        assert!(
            fits_unix_socket_path(&paths.client_socket, 0),
            "derived client path too long: {} ({} bytes)",
            paths.client_socket.display(),
            socket_path_byte_len(&paths.client_socket)
        );
        assert_eq!(
            paths.client_socket,
            crate::server::socket_paths::derive_client_socket_from_api_socket(&paths.api_socket),
        );
    }

    #[test]
    fn local_forward_socket_path_fits_in_sun_path() {
        let _guard = remote_env_lock().lock().unwrap();
        // Worst case for the readable form: macOS-style 49-char TMPDIR +
        // max-length sanitized components. Should fall back to the hashed
        // short name, which fits under TMPDIR.
        let target = "longish-host.example.com";
        let session = "a-fairly-long-session-name-here";
        let path = local_forward_socket_path(target, session, RemoteBridgeKind::Client, 0);
        assert!(
            fits_unix_socket_path(&path, 0),
            "socket path too long for sun_path: {} ({} bytes)",
            path.display(),
            socket_path_byte_len(&path)
        );
    }

    #[test]
    fn local_forward_socket_path_falls_back_to_tmp_when_dir_is_long() {
        let _guard = remote_env_lock().lock().unwrap();
        // Force a TMPDIR long enough that even the hashed short name cannot
        // fit inside it. The fallback should drop to /tmp.
        let prior = std::env::var_os("TMPDIR");
        let long_dir = std::env::temp_dir().join("a".repeat(80));
        let _ = fs::create_dir_all(&long_dir);
        std::env::set_var("TMPDIR", &long_dir);

        let path = local_forward_socket_path(
            "longish-host.example.com",
            "default",
            RemoteBridgeKind::Client,
            0,
        );
        let fits = fits_unix_socket_path(&path, 0);
        let parent = path.parent().map(Path::to_path_buf);
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        match prior {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
        let _ = fs::remove_dir_all(&long_dir);

        assert!(fits, "fallback path still overflows: {}", path.display());
        assert_eq!(parent.as_deref(), Some(Path::new("/tmp")));
        assert!(
            filename.starts_with("herdr-r-"),
            "expected hashed fallback, got {filename}"
        );
    }

    #[test]
    fn install_source_cleanup_removes_temporary_directory() {
        let dir = std::env::temp_dir().join(format!(
            "herdr-install-source-cleanup-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("create temp dir");
        let path = dir.join("herdr.tmp");
        fs::write(&path, b"test").expect("write temp file");

        InstallSource::temporary(path, dir.clone()).cleanup();

        assert!(!dir.exists());
    }

    #[test]
    fn provision_stage_labels_are_present_tense_and_name_the_source() {
        assert_eq!(
            RemoteProvisionStage::Connecting.label(),
            "connecting to remote…"
        );
        assert_eq!(
            RemoteProvisionStage::Installing.label(),
            "installing herdr on the remote…"
        );
        assert_eq!(
            RemoteProvisionStage::Seeding {
                source: "the linux-aarch64 fat bundle repacked from this multi-platform build".into(),
            }
            .label(),
            "provisioning herdr from the linux-aarch64 fat bundle repacked from this multi-platform build…"
        );
    }
}
