//! Read-only enumeration of connectable `Host` aliases from the user's ssh client config.
//!
//! herdr hands a bare ssh alias to `ssh` as a remote target; ssh resolves `HostName`/`User`/
//! `Port`/`ProxyJump` from `~/.ssh/config` at connect time (`src/remote/unix.rs`). This module is
//! the *discovery* half: it parses `~/.ssh/config` (following `Include` directives) and surfaces
//! each concrete alias plus its resolved `HostName`/`User` for display. It NEVER writes the ssh
//! config and never resolves tokens like `%h` — that stays ssh's job at connect time.
//!
//! This is platform-neutral text + read-only file IO (the server API handler that calls it is
//! cross-platform), so it deliberately lives outside the `#[cfg(unix)]`-gated `src/remote/` module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Environment override for the ssh config path. When set (and non-empty), it replaces the default
/// `~/.ssh/config`. Mirrors how a user would point ssh at a non-default config.
pub const SSH_CONFIG_PATH_ENV_VAR: &str = "HERDR_SSH_CONFIG_PATH";

/// Cap on `Include` nesting depth, a backstop against pathological configs (cycles are already
/// caught by the visited-path set, but a deep legitimate chain is also not worth following).
const MAX_INCLUDE_DEPTH: usize = 16;

/// Per-file byte cap. The API handler runs `discover_hosts()` synchronously on the server loop, so a
/// huge config/include must not be slurped into memory there. Files larger than this are skipped.
const MAX_CONFIG_FILE_BYTES: u64 = 1 << 20;

/// Total files (default config + all includes) read in one discovery pass. Bounds a config whose
/// glob `Include`s fan out into a large directory tree.
const MAX_CONFIG_FILES: usize = 256;

/// Directory entries a single glob `Include` will examine before giving up. Bounds the `read_dir`
/// scan so a pattern like `Include config.d/*` pointed at a huge directory cannot pin the loop
/// iterating/sorting unboundedly. Set well above any realistic `~/.ssh/config.d`.
const MAX_GLOB_SCAN_ENTRIES: usize = 8192;

/// Request-wide budget on total directory entries examined across ALL glob `Include`s in one
/// discovery pass. The per-glob cap alone does not stop a root file with tens of thousands of
/// `Include config.d/*` lines from re-scanning a directory for every line; this bounds the
/// multiplicative work so a pathological config cannot pin the synchronous app-loop discovery.
const MAX_TOTAL_GLOB_SCANS: usize = 65536;

/// Hard cap on discovered aliases. The per-file (1 MiB) and total-file (256) caps bound the input,
/// but a fan-out of many small files could still push tens of millions of `Host` aliases into one
/// synchronously-served response. Stop discovery once this many aliases are collected (truncated).
/// Far above any realistic personal ssh config.
const MAX_HOSTS: usize = 4096;

/// A single connectable ssh alias discovered in the config, with its resolved display fields.
///
/// Doubles as the `remote.ssh_config_hosts` wire payload (referenced from `ResponseResult`), so it
/// derives serde directly — the unset display fields stay off the wire via `skip_serializing_if`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfigHost {
    /// The concrete `Host` alias (the destination herdr would hand to `ssh`).
    pub alias: String,
    /// The block's `HostName`, if set — shown for disambiguation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The block's `User`, if set — shown for disambiguation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Enumerate connectable host aliases from the default (or env-overridden) ssh config.
///
/// Returns an empty vec when the config is missing or unreadable — discovery is best-effort and a
/// missing `~/.ssh/config` is the common case, not an error.
pub fn discover_hosts() -> Vec<SshConfigHost> {
    let Some(path) = default_config_path() else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    let mut seen_aliases = HashSet::new();
    let mut visited_files = HashSet::new();
    // The active `Host` block, shared across `Include` boundaries so a per-host include attributes
    // its directives to the including file's block (OpenSSH inline-insertion semantics).
    let mut current_aliases = Vec::new();
    // Request-wide remaining glob-scan budget, decremented across every glob `Include`.
    let mut glob_scans_remaining = MAX_TOTAL_GLOB_SCANS;
    parse_file(
        &path,
        0,
        &mut hosts,
        &mut seen_aliases,
        &mut visited_files,
        &mut current_aliases,
        &mut glob_scans_remaining,
    );
    hosts
}

/// Resolve the ssh config path: the env override if set and non-empty, else `~/.ssh/config`.
fn default_config_path() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(SSH_CONFIG_PATH_ENV_VAR) {
        if !value.is_empty() {
            return Some(PathBuf::from(value));
        }
    }
    Some(home_dir()?.join(".ssh").join("config"))
}

/// Best-effort home directory: `$HOME` on Unix, falling back to `%USERPROFILE%` on Windows. No new
/// dependency — ssh discovery only needs a base for the default path and relative `Include`s.
fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(home));
    }
    if cfg!(windows) {
        if let Some(profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(profile));
        }
    }
    None
}

/// `~/.ssh`, the base for resolving relative `Include` paths (per ssh_config(5)).
fn ssh_dir() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssh"))
}

fn parse_file(
    path: &Path,
    depth: usize,
    hosts: &mut Vec<SshConfigHost>,
    seen_aliases: &mut HashSet<String>,
    visited_files: &mut HashSet<PathBuf>,
    // The aliases of the current `Host` block, awaiting `HostName`/`User` lines beneath them.
    // Threaded through `Include` so the active block is shared across the include boundary (OpenSSH
    // inserts included contents inline): a per-host include attributes to the including block, and a
    // `Host` opened in the include continues as the active block on return. A `Match` clears it.
    current_aliases: &mut Vec<usize>,
    // Request-wide remaining glob-scan budget (see `MAX_TOTAL_GLOB_SCANS`).
    glob_scans_remaining: &mut usize,
) {
    // Canonicalize so the same file reached via different relative paths is only visited once
    // (cycle guard). Fall back to the raw path if canonicalization fails (e.g. file is missing).
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited_files.insert(canonical) {
        return;
    }
    // Bound discovery: it runs synchronously on the server loop. Cap the total files read across a
    // glob-fanned `Include` tree, require a regular file (a FIFO/device would block `read_to_string`
    // forever; a directory/socket is not a config), and skip files larger than the per-file cap.
    if visited_files.len() > MAX_CONFIG_FILES {
        return;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_CONFIG_FILE_BYTES {
        return;
    }
    // Output cap: once enough aliases are collected, stop traversing (don't read/parse more files).
    if hosts.len() >= MAX_HOSTS {
        return;
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };

    for raw_line in contents.lines() {
        let Some((keyword, rest)) = split_keyword(raw_line) else {
            continue;
        };
        match keyword.as_str() {
            "host" => {
                current_aliases.clear();
                for token in tokenize(rest) {
                    if hosts.len() >= MAX_HOSTS {
                        break;
                    }
                    if !is_connectable_alias(&token) {
                        continue;
                    }
                    if !seen_aliases.insert(token.clone()) {
                        // First occurrence wins (ssh-config precedence); skip later duplicates but
                        // still treat this as the active block for any HostName/User beneath it.
                        if let Some(index) = hosts.iter().position(|h| h.alias == token) {
                            current_aliases.push(index);
                        }
                        continue;
                    }
                    current_aliases.push(hosts.len());
                    hosts.push(SshConfigHost {
                        alias: token,
                        hostname: None,
                        user: None,
                    });
                }
            }
            "match" => {
                // We only enumerate `Host` blocks; a `Match` block's directives must not attach to
                // the previous host. Don't crash on `Match` selectors — just stop attributing.
                current_aliases.clear();
            }
            "hostname" => {
                if let Some(value) = first_token(rest) {
                    for &index in current_aliases.iter() {
                        if hosts[index].hostname.is_none() {
                            hosts[index].hostname = Some(value.clone());
                        }
                    }
                }
            }
            "user" => {
                if let Some(value) = first_token(rest) {
                    for &index in current_aliases.iter() {
                        if hosts[index].user.is_none() {
                            hosts[index].user = Some(value.clone());
                        }
                    }
                }
            }
            "include" => {
                if depth >= MAX_INCLUDE_DEPTH {
                    continue;
                }
                // Once no further file can be read or the request-wide glob-scan budget is spent,
                // stop processing Include lines entirely — expanding more would be wasted work that
                // could pin the synchronous app-loop discovery.
                if visited_files.len() >= MAX_CONFIG_FILES || *glob_scans_remaining == 0 {
                    break;
                }
                for included in resolve_includes(rest, glob_scans_remaining) {
                    parse_file(
                        &included,
                        depth + 1,
                        hosts,
                        seen_aliases,
                        visited_files,
                        current_aliases,
                        glob_scans_remaining,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Split a config line into `(lowercased keyword, remainder)`, dropping comments and blank lines.
/// ssh_config keywords are case-insensitive; `Key=Value` and `Key Value` are both accepted.
fn split_keyword(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    // Keyword/argument separator is whitespace and/or a single '='.
    let split_at = trimmed.find(|c: char| c.is_whitespace() || c == '=')?;
    let keyword = trimmed[..split_at].to_ascii_lowercase();
    let rest = trimmed[split_at..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    Some((keyword, rest))
}

/// Tokenize the argument portion of a line, honoring double quotes (ssh_config allows quoted
/// patterns/paths with spaces). Falls back to whitespace splitting. An unquoted `#` that begins a
/// token starts a trailing comment — the rest of the line is dropped so a comment like
/// `Host prod # main` does not surface `#`/`main` as bogus aliases. A `#` inside a token
/// (`web#1`) or inside quotes is preserved.
fn tokenize(rest: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in rest.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes && current.is_empty() => break,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn first_token(rest: &str) -> Option<String> {
    tokenize(rest).into_iter().next()
}

/// A `Host` token is connectable only if it is a literal alias: no glob wildcards (`*`/`?`), no
/// negated pattern (`!...`), and no embedded whitespace. Those match-only patterns aren't
/// destinations ssh can connect to, and a whitespace alias (from a quoted `Host "a b"` pattern)
/// would make the picker's `ssh <alias>` target ambiguous, so it is dropped at discovery.
fn is_connectable_alias(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with('!')
        && !token.contains('*')
        && !token.contains('?')
        && !token.chars().any(char::is_whitespace)
}

/// Resolve the path tokens of an `Include` line to concrete files. Relative paths are resolved
/// against `~/.ssh/`; `~` is expanded to the home directory. Single-level glob patterns (`*`/`?`)
/// are expanded best-effort via `read_dir`. Missing/unreadable entries are silently skipped.
fn resolve_includes(rest: &str, glob_scans_remaining: &mut usize) -> Vec<PathBuf> {
    let mut resolved = Vec::new();
    for token in tokenize(rest) {
        let expanded = expand_tilde(&token);
        let base = if expanded.is_absolute() {
            expanded
        } else if let Some(dir) = ssh_dir() {
            dir.join(expanded)
        } else {
            continue;
        };
        if has_glob(&token) {
            resolved.extend(glob_expand(&base, glob_scans_remaining));
        } else {
            resolved.push(base);
        }
    }
    resolved
}

fn expand_tilde(token: &str) -> PathBuf {
    if let Some(rest) = token.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(token)
}

fn has_glob(token: &str) -> bool {
    token.contains('*') || token.contains('?')
}

/// Best-effort single-directory glob: matches the final path component (which may contain `*`/`?`)
/// against the entries of its parent directory. Does not recurse into `**`.
fn glob_expand(pattern: &Path, glob_scans_remaining: &mut usize) -> Vec<PathBuf> {
    let Some(parent) = pattern.parent() else {
        return Vec::new();
    };
    let Some(file_pattern) = pattern.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    // Bound the scan three ways: this single glob examines at most MAX_GLOB_SCAN_ENTRIES, the whole
    // discovery examines at most MAX_TOTAL_GLOB_SCANS (shared `glob_scans_remaining`), and we stop
    // collecting once matches could exhaust the total file budget. discover_hosts runs synchronously
    // on the app loop, so a pathological directory or a flood of glob Includes can't pin it.
    let mut matched = Vec::new();
    for (scanned, entry) in entries.flatten().enumerate() {
        if scanned >= MAX_GLOB_SCAN_ENTRIES
            || *glob_scans_remaining == 0
            || matched.len() >= MAX_CONFIG_FILES
        {
            break;
        }
        *glob_scans_remaining -= 1;
        if let Some(name) = entry.file_name().to_str() {
            if glob_match(file_pattern, name) {
                matched.push(entry.path());
            }
        }
    }
    matched.sort();
    matched
}

/// Minimal glob matcher supporting `*` (any run) and `?` (single char) — enough for the typical
/// `Include ~/.ssh/config.d/*` form. No character classes or `**`.
///
/// Iterative two-pointer matching with single-star backtracking: linear-ish (`O(n*m)` worst case)
/// and non-recursive, so a pathological pattern from a local `Include` (e.g. `*a*a*a*b`) applied to
/// a long filename cannot blow up CPU/stack the way naive recursive backtracking would, while
/// discovery runs synchronously on the app loop.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = candidate.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Last `*` position and the text index it was matched against, for backtracking.
    let mut star: Option<usize> = None;
    let mut star_text = 0usize;
    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star = Some(pi);
            star_text = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` swallow one more text char and retry.
            pi = s + 1;
            star_text += 1;
            ti = star_text;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Process-wide serialization for every test that mutates `HOME` / `HERDR_SSH_CONFIG_PATH` (which is
/// global). Shared so the `ssh_config` unit tests and the `remote.ssh_config_hosts` API handler test
/// (`src/app/api/remotes.rs`) cannot clobber each other's env under plain `cargo test` (nextest, the
/// repo's `just test`, already isolates each test in its own process).
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A scratch dir under the system temp, with an env guard pointing `HERDR_SSH_CONFIG_PATH` at a
    /// config file inside it. `HOME` is repointed so relative `Include`s resolve under the scratch.
    struct ConfigFixture {
        dir: PathBuf,
        _home_guard: EnvGuard,
        _path_guard: EnvGuard,
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    impl ConfigFixture {
        fn new(name: &str, body: &str) -> Self {
            // Unique-ish per test name; tests using env vars run serially below.
            let dir = std::env::temp_dir().join(format!("herdr-ssh-cfg-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join(".ssh")).unwrap();
            let config_path = dir.join(".ssh").join("config");
            write_file(&config_path, body);
            let _home_guard = EnvGuard::set("HOME", &dir);
            let _path_guard = EnvGuard::set(SSH_CONFIG_PATH_ENV_VAR, &config_path);
            Self {
                dir,
                _home_guard,
                _path_guard,
            }
        }

        fn write_extra(&self, rel: &str, body: &str) {
            let path = self.dir.join(".ssh").join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            write_file(&path, body);
        }
    }

    impl Drop for ConfigFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn write_file(path: &Path, body: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn enumerates_concrete_hosts_with_hostname_and_user() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "basic",
            "Host prod\n  HostName 10.0.0.5\n  User deploy\n\nHost db\n  HostName db.internal\n",
        );
        let hosts = discover_hosts();
        assert_eq!(
            hosts,
            vec![
                SshConfigHost {
                    alias: "prod".into(),
                    hostname: Some("10.0.0.5".into()),
                    user: Some("deploy".into()),
                },
                SshConfigHost {
                    alias: "db".into(),
                    hostname: Some("db.internal".into()),
                    user: None,
                },
            ]
        );
    }

    #[test]
    fn skips_aliases_containing_whitespace() {
        let _lock = ENV_LOCK.lock().unwrap();
        // PRRT...3e8: a quoted Host pattern yields a token with embedded spaces; such an alias is not
        // a single ssh destination (the picker builds `ssh <alias>`), so it must be dropped.
        let _fixture = ConfigFixture::new(
            "ws-alias",
            "Host \"my host\"\n  HostName 10.0.0.5\n\nHost real\n  HostName r.host\n",
        );
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert_eq!(aliases, vec!["real".to_string()]);
    }

    #[test]
    fn skips_wildcard_and_negated_patterns() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "wildcards",
            "Host *\n  User everyone\n\nHost gw-? \n  HostName gw\n\nHost !secret real\n  HostName r\n",
        );
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        // `*`, `gw-?`, and `!secret` are dropped; only the literal `real` survives.
        assert_eq!(aliases, vec!["real".to_string()]);
    }

    #[test]
    fn multi_token_host_line_emits_each_alias() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "multi",
            "Host web1 web2\n  HostName shared.host\n  User app\n",
        );
        let hosts = discover_hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].alias, "web1");
        assert_eq!(hosts[1].alias, "web2");
        assert_eq!(hosts[0].hostname.as_deref(), Some("shared.host"));
        assert_eq!(hosts[1].user.as_deref(), Some("app"));
    }

    #[test]
    fn follows_include_directive() {
        let _lock = ENV_LOCK.lock().unwrap();
        let fixture = ConfigFixture::new("include", "Include config.d/extra\nHost main\n");
        fixture.write_extra("config.d/extra", "Host included\n  HostName inc.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert!(aliases.contains(&"included".to_string()));
        assert!(aliases.contains(&"main".to_string()));
    }

    #[test]
    fn include_attributes_directives_to_the_active_host_block_inline() {
        let _lock = ENV_LOCK.lock().unwrap();
        // PRRT...oT2: OpenSSH processes an Include as if its contents were inserted inline, so a
        // per-host include must attribute its HostName/User to the including file's active Host block,
        // and a Host opened inside the include continues as the active block afterward.
        let fixture = ConfigFixture::new(
            "include-inline",
            "Host prod\n  Include config.d/prod\n\nHost plain\n  HostName p.host\n",
        );
        fixture.write_extra(
            "config.d/prod",
            "HostName 10.0.0.5\n  User deploy\nHost extra\n  HostName e.host\n",
        );
        let hosts = discover_hosts();

        let prod = hosts.iter().find(|h| h.alias == "prod").expect("prod row");
        assert_eq!(prod.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(prod.user.as_deref(), Some("deploy"));
        // The include's own trailing Host is captured with its HostName.
        let extra = hosts
            .iter()
            .find(|h| h.alias == "extra")
            .expect("extra row");
        assert_eq!(extra.hostname.as_deref(), Some("e.host"));
        // After the include returns, the including file's next Host is its own block.
        let plain = hosts
            .iter()
            .find(|h| h.alias == "plain")
            .expect("plain row");
        assert_eq!(plain.hostname.as_deref(), Some("p.host"));
    }

    #[test]
    fn expands_glob_include() {
        let _lock = ENV_LOCK.lock().unwrap();
        let fixture = ConfigFixture::new("glob", "Include config.d/*\n");
        fixture.write_extra("config.d/a", "Host alpha\n");
        fixture.write_extra("config.d/b", "Host bravo\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert!(aliases.contains(&"alpha".to_string()));
        assert!(aliases.contains(&"bravo".to_string()));
    }

    #[test]
    fn include_cycle_does_not_loop_forever() {
        let _lock = ENV_LOCK.lock().unwrap();
        let fixture = ConfigFixture::new("cycle", "Include config.d/loop\nHost top\n");
        // The included file includes the top-level config back — visited-set must break the cycle.
        fixture.write_extra("config.d/loop", "Include ../config\nHost looped\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert!(aliases.contains(&"top".to_string()));
        assert!(aliases.contains(&"looped".to_string()));
    }

    #[test]
    fn match_block_does_not_attach_to_previous_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "match",
            "Host real\n  HostName r.host\n\nMatch host *.internal\n  User mole\n",
        );
        let hosts = discover_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "real");
        // The `Match` block's `User mole` must NOT land on `real`.
        assert_eq!(hosts[0].user, None);
    }

    #[test]
    fn first_occurrence_wins_for_duplicate_alias() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "dup",
            "Host dev\n  HostName first.host\n\nHost dev\n  HostName second.host\n",
        );
        let hosts = discover_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname.as_deref(), Some("first.host"));
    }

    #[test]
    fn skips_oversized_include_files() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex-1-2: a config/include larger than MAX_CONFIG_FILE_BYTES must be skipped so the
        // synchronous discovery on the server loop can't slurp a huge file into memory.
        let fixture =
            ConfigFixture::new("oversized", "Host real\n  HostName r.host\nInclude big\n");
        let mut big = String::with_capacity((MAX_CONFIG_FILE_BYTES as usize) + 4096);
        big.push_str("Host toobig\n  HostName b.host\n");
        while (big.len() as u64) <= MAX_CONFIG_FILE_BYTES {
            big.push_str("# padding padding padding padding padding padding padding\n");
        }
        fixture.write_extra("big", &big);

        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert_eq!(
            aliases,
            vec!["real".to_string()],
            "the oversized include's hosts must be skipped"
        );
    }

    #[test]
    fn caps_total_discovered_hosts() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex-2-2 (iter 2): a fan-out of many Host lines must not allocate an unbounded alias list
        // for one synchronous response. Discovery truncates at MAX_HOSTS.
        let mut body = String::new();
        for i in 0..(MAX_HOSTS + 100) {
            body.push_str(&format!("Host h{i}\n"));
        }
        let _fixture = ConfigFixture::new("many-hosts", &body);
        let hosts = discover_hosts();
        assert_eq!(hosts.len(), MAX_HOSTS, "discovery must cap at MAX_HOSTS");
    }

    #[test]
    fn missing_config_returns_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("herdr-ssh-cfg-missing");
        let _ = std::fs::remove_dir_all(&dir);
        let _home = EnvGuard::set("HOME", &dir);
        let _path = EnvGuard::set(SSH_CONFIG_PATH_ENV_VAR, &dir.join("nope").join("config"));
        assert!(discover_hosts().is_empty());
    }

    #[test]
    fn accepts_equals_and_case_insensitive_keywords() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture =
            ConfigFixture::new("equals", "HOST=prod\n  HOSTNAME = 10.0.0.9\n  user=root\n");
        let hosts = discover_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "prod");
        assert_eq!(hosts[0].hostname.as_deref(), Some("10.0.0.9"));
        assert_eq!(hosts[0].user.as_deref(), Some("root"));
    }

    #[test]
    fn inline_comment_is_stripped_but_hash_inside_a_token_is_kept() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _fixture = ConfigFixture::new(
            "inline-comment",
            "Host prod # main\n  HostName 10.0.0.5 # the box\n  User deploy # primary\n\nHost web#1\n  HostName w.host\n",
        );
        let hosts = discover_hosts();
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.clone()).collect();
        // `# main` is a trailing comment, not extra aliases; `web#1` keeps its in-token `#`.
        assert_eq!(aliases, vec!["prod".to_string(), "web#1".to_string()]);
        assert_eq!(hosts[0].hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(hosts[0].user.as_deref(), Some("deploy"));
        assert_eq!(hosts[1].hostname.as_deref(), Some("w.host"));
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("config-*", "config-prod"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("config-*", "other"));
        // Multiple stars and trailing literals.
        assert!(glob_match("*.conf", "site.conf"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(glob_match("**", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_match_adversarial_pattern_terminates() {
        // codex-1-1 (iter 2): the old recursive matcher was exponential on patterns like `*a*a...`
        // against a long non-matching name. The iterative matcher returns quickly and correctly.
        let pattern = "*a".repeat(32); // 64-char pattern, many stars
        let non_matching = "b".repeat(2048); // long, ends in 'b' so the trailing `a` never matches
        assert!(!glob_match(&pattern, &non_matching));
        let matching = format!("{}a", "x".repeat(2048));
        assert!(glob_match("*a", &matching));
    }
}
