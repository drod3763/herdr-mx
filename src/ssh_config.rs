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

/// Per-file byte cap. `discover_hosts()` is deferred off the app loop on a worker thread, but it is
/// still bounded work, so a huge config/include must not be slurped into memory. Files larger than
/// this are skipped.
const MAX_CONFIG_FILE_BYTES: u64 = 1 << 20;

/// Total files (default config + all includes) read in one discovery pass. Bounds a config whose
/// glob `Include`s fan out into a large directory tree.
const MAX_CONFIG_FILES: usize = 256;

/// Directory entries a single glob `Include` will examine before giving up. Bounds the `read_dir`
/// scan so a pattern like `Include config.d/*` pointed at a huge directory cannot pin the loop
/// iterating/sorting unboundedly. Set well above any realistic `~/.ssh/config.d`.
const MAX_GLOB_SCAN_ENTRIES: usize = 8192;

/// Max length of a single glob `Include` final component. A real pattern is short (`*`, `*.conf`);
/// a pathological huge one is rejected so per-entry match work stays bounded.
const MAX_GLOB_PATTERN_LEN: usize = 256;

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

/// Max bytes for a single alias / `HostName` / `User` value. A real ssh alias or DNS name fits
/// easily; a longer token is a pattern or garbage and is dropped/ignored so one line can't push a
/// huge string into the response.
const MAX_FIELD_LEN: usize = 256;

/// Total bytes of alias/hostname/user strings retained across the whole discovery. Even within the
/// host-count and per-field caps the aggregate could approach the wire frame limit, so stop once the
/// retained payload reaches this budget (well under the 2 MiB `MAX_FRAME_SIZE`).
const MAX_TOTAL_PAYLOAD_BYTES: usize = 1 << 20;

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
    // Cycle guard = the files currently on the include recursion stack (not a global visited set, so
    // a shared include reused under multiple `Host` blocks still applies to each); `files_read`
    // bounds the total reads.
    let mut include_stack = HashSet::new();
    let mut files_read = 0usize;
    let mut payload_bytes = 0usize;
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
        &mut include_stack,
        &mut files_read,
        &mut payload_bytes,
        &mut current_aliases,
        &mut glob_scans_remaining,
        &[],
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
    // Canonical paths of the files CURRENTLY being parsed (the include recursion stack), so a real
    // cycle (A includes B includes A) is caught while a shared include reused under several `Host`
    // blocks is still re-applied each time — matching OpenSSH's textual-insertion semantics.
    include_stack: &mut HashSet<PathBuf>,
    // Total files actually read this discovery pass; bounds re-reads of a shared include.
    files_read: &mut usize,
    // Total bytes of alias/hostname/user strings retained so far (see `MAX_TOTAL_PAYLOAD_BYTES`).
    payload_bytes: &mut usize,
    // The aliases of the current `Host` block, awaiting `HostName`/`User` lines beneath them.
    // Threaded through `Include` so pre-`Host` directives in an included file attribute to the
    // including block (OpenSSH inline-insertion for a shared include). The `Include` arm saves and
    // restores this around the recursive call, matching OpenSSH: a `Host` opened inside the included
    // file does NOT persist as the active block after the include returns (verified with `ssh -G`),
    // so a later parent `HostName`/`User` still attaches to the parent block. A `Match` clears it.
    current_aliases: &mut Vec<usize>,
    // Request-wide remaining glob-scan budget (see `MAX_TOTAL_GLOB_SCANS`).
    glob_scans_remaining: &mut usize,
    // Stack of enclosing conditional gates from the ancestor `Host`/`Match` blocks that led to this
    // file via nested `Include`s. Empty at top level (an unconditionally reached file). A `Host` alias
    // in this file is discoverable only if it satisfies every gate — mirroring that ssh processes a
    // conditional include, and the aliases it defines, only when the connection matches the enclosing
    // conditions. Directives before any `Host` line still attribute to the enclosing block. #11.
    gates: &[IncludeGate],
) {
    // Canonicalize so a cycle is detected regardless of how the same file is reached.
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if include_stack.contains(&canonical) {
        // Recursion cycle — this file is already an ancestor on the include stack.
        return;
    }
    // Bound discovery: it runs synchronously on the server loop. Cap the total files read across a
    // glob-fanned `Include` tree, require a regular file (a FIFO/device would block `read_to_string`
    // forever; a directory/socket is not a config), and skip files larger than the per-file cap.
    if *files_read >= MAX_CONFIG_FILES {
        return;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_file() || meta.len() > MAX_CONFIG_FILE_BYTES {
        return;
    }
    // Output cap: once enough aliases or bytes are collected, stop traversing (read no more files).
    if hosts.len() >= MAX_HOSTS || *payload_bytes >= MAX_TOTAL_PAYLOAD_BYTES {
        return;
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    *files_read += 1;
    include_stack.insert(canonical.clone());

    // The active condition opened by the most recent `Host`/`Match` line in THIS file. `None` before
    // any such line (top-level of this file). It gates only CHILD includes: a nested `Include` is
    // conditional on it. A `Host`/`Match` block or a pattern-only `Host *.corp` block all set this,
    // so conditional-vs-top-level is tracked precisely rather than inferred from a retained alias. #11.
    let mut active_gate: Option<IncludeGate> = None;

    for raw_line in contents.lines() {
        let Some((keyword, rest)) = split_keyword(raw_line) else {
            continue;
        };
        match keyword.as_str() {
            "host" => {
                current_aliases.clear();
                // A `Host` line opens a conditional scope for any `Include` beneath it — even when the
                // pattern is a non-connectable wildcard. Record its patterns so a child include is
                // gated on them.
                active_gate = Some(IncludeGate::host(rest));
                for token in tokenize(rest) {
                    if hosts.len() >= MAX_HOSTS || *payload_bytes >= MAX_TOTAL_PAYLOAD_BYTES {
                        break;
                    }
                    if !is_connectable_alias(&token) {
                        continue;
                    }
                    // A `Host` reached through conditional includes is discoverable only if it
                    // satisfies every enclosing gate — i.e. `ssh <alias>` would actually process the
                    // includes that led here. Top-level files have no gates, so all aliases pass.
                    if !gates.iter().all(|gate| gate.admits(&token)) {
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
                    *payload_bytes += token.len();
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
                // the previous host. Don't crash on `Match` selectors — just stop attributing. An
                // unconditional `Match all` (optionally after `canonical`/`final`) matches every
                // connection, so an `Include` beneath it stays as reachable as the enclosing scope; a
                // `Match` with real selectors we can't evaluate statically opens an opaque gate.
                current_aliases.clear();
                active_gate = match_gate(rest);
            }
            "hostname" => {
                // Ignore an over-length value (not a real DNS name). Each set adds to the payload
                // budget AND stops the fan-out once the budget is reached, so cloning the value onto
                // a many-alias Host block can't blow past the total byte cap.
                if let Some(value) = first_token(rest).filter(|v| v.len() <= MAX_FIELD_LEN) {
                    for &index in current_aliases.iter() {
                        if *payload_bytes >= MAX_TOTAL_PAYLOAD_BYTES {
                            break;
                        }
                        if hosts[index].hostname.is_none() {
                            *payload_bytes += value.len();
                            hosts[index].hostname = Some(value.clone());
                        }
                    }
                }
            }
            "user" => {
                if let Some(value) = first_token(rest).filter(|v| v.len() <= MAX_FIELD_LEN) {
                    for &index in current_aliases.iter() {
                        if *payload_bytes >= MAX_TOTAL_PAYLOAD_BYTES {
                            break;
                        }
                        if hosts[index].user.is_none() {
                            *payload_bytes += value.len();
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
                // skip Include expansion — expanding more would be wasted work that could pin the
                // synchronous app-loop discovery. Use `continue`, not `break`: the rest of THIS file
                // (e.g. later `Host` blocks) must still be parsed.
                if *files_read >= MAX_CONFIG_FILES || *glob_scans_remaining == 0 {
                    continue;
                }
                // An include nested in a conditional (`Host`/`Match`) scope is itself conditional: push
                // this file's active gate onto the stack so the included file's aliases are surfaced
                // only when they satisfy every enclosing condition. An include at top level of this
                // file (no active gate) inherits the stack unchanged, staying unconditional.
                let child_gates = match &active_gate {
                    Some(gate) => {
                        let mut extended = gates.to_vec();
                        extended.push(gate.clone());
                        extended
                    }
                    None => gates.to_vec(),
                };
                // Save the active block so it is restored after the include. OpenSSH restores the
                // including file's active `Host` scope once the include returns: a `Host` line inside
                // the included file does NOT leak forward, so a later parent `HostName`/`User` still
                // attaches to the parent block (verified against `ssh -G`). Pre-`Host` directives in
                // the included file still mutate the parent block during the call, because
                // `current_aliases` still holds the parent aliases until the child opens its own
                // `Host` — that shared-include attribution is preserved.
                let saved_aliases = current_aliases.clone();
                for included in resolve_includes(rest, glob_scans_remaining) {
                    parse_file(
                        &included,
                        depth + 1,
                        hosts,
                        seen_aliases,
                        include_stack,
                        files_read,
                        payload_bytes,
                        current_aliases,
                        glob_scans_remaining,
                        &child_gates,
                    );
                }
                *current_aliases = saved_aliases;
            }
            _ => {}
        }
    }
    // Pop this file off the include stack so it can be re-included under a later, non-recursive
    // context (OpenSSH re-inserts a shared include each time it appears).
    include_stack.remove(&canonical);
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
/// character-class pattern (`[...]`), no negated pattern (`!...`), and no embedded whitespace. Those
/// match-only patterns aren't destinations ssh can connect to, and a whitespace alias (from a quoted
/// `Host "a b"` pattern) would make the picker's `ssh <alias>` target ambiguous, so all are dropped.
fn is_connectable_alias(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_FIELD_LEN
        && !token.starts_with('!')
        && !token.contains('*')
        && !token.contains('?')
        && !token.contains('[')
        && !token.contains(']')
        && !token.chars().any(char::is_whitespace)
}

/// A conditional scope an `Include` sits under. When a file is pulled in via an `Include` nested in a
/// `Host` or `Match` block, ssh only processes it — and therefore the aliases it defines — when the
/// connection satisfies that enclosing condition. Discovery mirrors this: an alias from a
/// conditionally included file is surfaced only if it satisfies every gate on the stack of ancestor
/// conditions that led to the include. #11.
#[derive(Clone)]
enum IncludeGate {
    /// A `Host` line's pattern list. An alias is admitted when it matches at least one positive
    /// pattern and no negated (`!`) pattern — ssh's Host-pattern matching for the `*`/`?` wildcards.
    /// `Host *` admits every alias; `Host *.corp` admits only `*.corp` names; a concrete `Host prod`
    /// admits only `prod`. Bracket character classes (`db-[0-9]`) are matched literally, not expanded:
    /// - In a *positive* pattern that only under-reports — the candidate is always bracket-free
    ///   (`is_connectable_alias` rejects `[`/`]`), so a literal-bracket pattern just fails to match and
    ///   drops the reachable `db-[0-9]`-style alias.
    /// - In a *negated* pattern a literal-treated class would FAIL to match and wrongly *keep* an alias
    ///   ssh excludes (a false offer). So `admits` treats any gate with a bracketed negation as
    ///   admitting nothing. Net: the gate can under-report but never mis-admit.
    ///
    /// A rare pattern in a rare (gating) position; the fallback is typing the alias by hand.
    HostPatterns {
        positive: Vec<String>,
        negated: Vec<String>,
    },
    /// A `Match` block. Its selectors (`exec`, `host`, `user`, …) can't be evaluated statically for
    /// an arbitrary future target, so nothing beneath it is treated as unconditionally discoverable.
    MatchOpaque,
}

/// The gate a `Match` line opens for includes beneath it. `Match all` (optionally preceded by the
/// `canonical`/`final` pass keywords) is unconditional — ssh processes such a block for every
/// connection — so it adds no constraint and returns `None` (the enclosing scope is inherited
/// unchanged). Any `Match` with real selectors (`host`, `exec`, `user`, …) can't be evaluated for an
/// arbitrary future target, so it opens an opaque gate that admits nothing. #11.
fn match_gate(rest: &str) -> Option<IncludeGate> {
    let tokens: Vec<String> = tokenize(rest)
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let unconditional = tokens.iter().any(|t| t == "all")
        && tokens
            .iter()
            .all(|t| matches!(t.as_str(), "all" | "canonical" | "final"));
    if unconditional {
        None
    } else {
        Some(IncludeGate::MatchOpaque)
    }
}

impl IncludeGate {
    /// Build a `Host`-pattern gate from the tokens of a `Host` line, splitting negated patterns.
    fn host(rest: &str) -> Self {
        let mut positive = Vec::new();
        let mut negated = Vec::new();
        for token in tokenize(rest) {
            if let Some(stripped) = token.strip_prefix('!') {
                if !stripped.is_empty() {
                    negated.push(stripped.to_string());
                }
            } else if !token.is_empty() {
                positive.push(token);
            }
        }
        IncludeGate::HostPatterns { positive, negated }
    }

    /// Whether `alias` satisfies this gate — i.e. `ssh <alias>` would process the gated include.
    fn admits(&self, alias: &str) -> bool {
        match self {
            IncludeGate::MatchOpaque => false,
            IncludeGate::HostPatterns { positive, negated } => {
                // A negated pattern with a bracket character class (`!db-[0-9]`) is one this matcher
                // can't evaluate — `glob_match_chars` treats `[`/`]` literally and would FAIL to
                // match, wrongly *keeping* an alias ssh actually excludes. That is the unsafe
                // direction (offering an unreachable alias), so when exclusion is unprovable, refuse
                // to admit. (Positive bracket patterns fail-to-match too, but that only under-reports.)
                if negated.iter().any(|p| p.contains('[') || p.contains(']')) {
                    return false;
                }
                if negated
                    .iter()
                    .any(|p| glob_match_chars(&p.chars().collect::<Vec<_>>(), alias))
                {
                    return false;
                }
                positive
                    .iter()
                    .any(|p| glob_match_chars(&p.chars().collect::<Vec<_>>(), alias))
            }
        }
    }
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
    // A real `Include` glob component is short (`*`, `config-*`, `*.conf`). Reject a pathological
    // huge pattern outright so per-entry matching work stays bounded.
    if file_pattern.len() > MAX_GLOB_PATTERN_LEN {
        return Vec::new();
    }
    // Precompile the pattern's chars ONCE for the whole directory rather than rebuilding the Vec for
    // every scanned entry (a long pattern over a big directory would otherwise be pattern_len × scan
    // allocations/work).
    let pat: Vec<char> = file_pattern.chars().collect();
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
            if glob_match_chars(&pat, name) {
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
#[cfg(test)]
fn glob_match(pattern: &str, candidate: &str) -> bool {
    glob_match_chars(&pattern.chars().collect::<Vec<_>>(), candidate)
}

/// Matcher over a PRECOMPILED pattern slice, so `glob_expand` collects the pattern's chars once per
/// directory rather than rebuilding it for every scanned entry.
fn glob_match_chars(pat: &[char], candidate: &str) -> bool {
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
            "Host *\n  User everyone\n\nHost gw-? \n  HostName gw\n\nHost db-[0-9]\n  HostName db\n\nHost !secret real\n  HostName r\n",
        );
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        // `*`, `gw-?`, `db-[0-9]` (char class), and `!secret` are dropped; only `real` survives.
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
        // PRRT...oT2 + codex (re-run): a per-host `Include` attributes its leading HostName/User to
        // the enclosing `Host` block (inline directives), but it is CONDITIONAL — a `Host` opened
        // inside it is not a standalone discoverable alias (OpenSSH only sees it when `prod` matches).
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
        // `extra` (a Host opened inside the conditional per-host include) is NOT surfaced.
        assert!(
            !hosts.iter().any(|h| h.alias == "extra"),
            "a Host inside a conditional include is not a discoverable alias"
        );
        // After the include returns, the including file's next Host is its own block.
        let plain = hosts
            .iter()
            .find(|h| h.alias == "plain")
            .expect("plain row");
        assert_eq!(plain.hostname.as_deref(), Some("p.host"));
    }

    #[test]
    fn oversized_glob_pattern_is_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): a pathological huge glob pattern is rejected outright so per-entry match
        // work stays bounded. A normal short pattern still expands.
        let huge = "*".repeat(MAX_GLOB_PATTERN_LEN + 1);
        let fixture = ConfigFixture::new(
            "huge-glob",
            &format!("Include config.d/{huge}\nInclude config.d/*\n"),
        );
        fixture.write_extra("config.d/real", "Host real\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        // The oversized pattern matched nothing; the normal `*` include still found `real`.
        assert_eq!(aliases, vec!["real".to_string()]);
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
    fn conditional_include_hosts_are_not_discoverable_but_top_level_ones_are() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): a Host inside a per-host (conditional) include is not a standalone alias,
        // but a Host inside a TOP-LEVEL (unconditional) include is.
        let fixture = ConfigFixture::new(
            "conditional-include",
            "Include config.d/top\n\nHost gate\n  Include config.d/hidden\n",
        );
        fixture.write_extra("config.d/top", "Host toplevel\n  HostName t.host\n");
        fixture.write_extra("config.d/hidden", "Host hidden\n  HostName h.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(
            aliases.contains(&"toplevel".to_string()),
            "top-level include host is discoverable"
        );
        assert!(aliases.contains(&"gate".to_string()));
        assert!(
            !aliases.contains(&"hidden".to_string()),
            "a Host inside a conditional (per-host) include is not discoverable"
        );
    }

    #[test]
    fn include_inside_a_match_block_is_conditional() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): a `Match` block opens a conditional scope but retains no alias, so the old
        // `current_aliases.is_empty()` proxy wrongly treated an Include beneath it as top-level. ssh
        // only processes that include when the Match condition holds, so its hosts are not globally
        // discoverable.
        let fixture = ConfigFixture::new(
            "match-include",
            "Host real\n  HostName r.host\n\nMatch host bastion\n  Include config.d/match-only\n",
        );
        fixture.write_extra("config.d/match-only", "Host matchhost\n  HostName m.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(aliases.contains(&"real".to_string()));
        assert!(
            !aliases.contains(&"matchhost".to_string()),
            "a Host inside an Include under a Match block is not discoverable"
        );
    }

    #[test]
    fn sequential_top_level_includes_each_surface_their_hosts() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Characterization guard: two top-level `Include`s in the root file are both unconditional. A
        // `Host` line in the first included file opens a block, but the second file's own `Host` line
        // re-opens a fresh block, so `ssh other` resolves it — both aliases are connectable and must be
        // surfaced. (A tempting "fix" that leaks the first include's Host scope onto the second include
        // and gates its Host lines would WRONGLY drop `other`; this test locks the correct behavior.)
        let fixture = ConfigFixture::new(
            "sequential-includes",
            "Include config.d/a\nInclude config.d/b\n",
        );
        fixture.write_extra("config.d/a", "Host prod\n  HostName p.host\n");
        fixture.write_extra("config.d/b", "Host other\n  HostName o.host\n");
        let hosts = discover_hosts();
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.clone()).collect();

        assert!(aliases.contains(&"prod".to_string()));
        assert!(
            aliases.contains(&"other".to_string()),
            "a Host in a second top-level include is its own block and stays connectable"
        );
        let other = hosts.iter().find(|h| h.alias == "other").unwrap();
        assert_eq!(other.hostname.as_deref(), Some("o.host"));
    }

    #[test]
    fn include_under_negated_bracket_host_gate_is_not_surfaced() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex: `Host * !db-[0-9]` excludes `db-1` in ssh, so the include never applies to db-1 and
        // `ssh db-1` would not resolve through it. The matcher can't evaluate the bracket class in a
        // negation, so it must NOT offer db-1 (mis-admit is the unsafe direction). Conservative: a gate
        // with a bracketed negation admits nothing.
        let fixture = ConfigFixture::new(
            "negated-bracket-gate",
            "Host * !db-[0-9]\n  Include config.d/dbs\n",
        );
        fixture.write_extra("config.d/dbs", "Host db-1\n  HostName d1.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(
            !aliases.contains(&"db-1".to_string()),
            "an alias under a negated bracket-class Host gate must not be surfaced (unprovable exclusion)"
        );
    }

    #[test]
    fn include_under_match_all_surfaces_its_hosts() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): `Match all` is unconditional — ssh processes the include for every
        // connection — so a concrete Host inside that include is a real discoverable alias. A `Match`
        // with real selectors (`Match host …`) stays opaque and its include is suppressed.
        let fixture = ConfigFixture::new(
            "match-all-include",
            "Match all\n  Include config.d/hosts\n\nMatch host bastion\n  Include config.d/gated\n",
        );
        fixture.write_extra("config.d/hosts", "Host always\n  HostName a.host\n");
        fixture.write_extra("config.d/gated", "Host gatedhost\n  HostName g.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(
            aliases.contains(&"always".to_string()),
            "a Host under a `Match all` include is discoverable"
        );
        assert!(
            !aliases.contains(&"gatedhost".to_string()),
            "a Host under a conditional `Match host` include is not discoverable"
        );
    }

    #[test]
    fn include_under_host_pattern_hides_aliases_that_cannot_match_it() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): an Include under `Host *.corp` is conditional. A host inside it that CANNOT
        // match the enclosing pattern (`corphidden` has no `.corp` suffix) is never processed by
        // `ssh corphidden`, so it must not be surfaced.
        let fixture = ConfigFixture::new(
            "pattern-host-include-miss",
            "Host real\n  HostName r.host\n\nHost *.corp\n  Include config.d/corp\n",
        );
        fixture.write_extra("config.d/corp", "Host corphidden\n  HostName c.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(aliases.contains(&"real".to_string()));
        assert!(
            !aliases.contains(&"corphidden".to_string()),
            "a Host that cannot match the enclosing Host pattern is not discoverable"
        );
    }

    #[test]
    fn include_under_host_pattern_surfaces_aliases_that_match_it() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): the flip side — a host inside an Include under `Host *.corp` that DOES match
        // the pattern (`db.corp`) is processed by `ssh db.corp`, so it is a real connectable alias and
        // must be surfaced. Also covers the catch-all `Host *` case.
        let fixture = ConfigFixture::new(
            "pattern-host-include-hit",
            "Host *.corp\n  Include config.d/corp\n\nHost *\n  Include config.d/all\n",
        );
        fixture.write_extra("config.d/corp", "Host db.corp\n  HostName d.host\n");
        fixture.write_extra("config.d/all", "Host anything\n  HostName a.host\n");
        let hosts = discover_hosts();
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.clone()).collect();

        assert!(
            aliases.contains(&"db.corp".to_string()),
            "a Host matching the enclosing `*.corp` pattern is discoverable"
        );
        assert!(
            aliases.contains(&"anything".to_string()),
            "a Host under a catch-all `Host *` include is discoverable"
        );
        // Resolved display fields still attach through the conditional include.
        let db = hosts.iter().find(|h| h.alias == "db.corp").unwrap();
        assert_eq!(db.hostname.as_deref(), Some("d.host"));
    }

    #[test]
    fn include_under_concrete_host_hides_non_matching_alias() {
        let _lock = ENV_LOCK.lock().unwrap();
        // A concrete `Host prod` gates its include to `prod` only; a differently-named host defined in
        // that include is never reached by `ssh <that-name>`, so it stays hidden.
        let fixture = ConfigFixture::new(
            "concrete-host-include",
            "Host prod\n  Include config.d/prod\n",
        );
        fixture.write_extra("config.d/prod", "Host staging\n  HostName s.host\n");
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();

        assert!(aliases.contains(&"prod".to_string()));
        assert!(
            !aliases.contains(&"staging".to_string()),
            "a Host that cannot match the enclosing concrete Host is not discoverable"
        );
    }

    #[test]
    fn parent_directive_after_include_that_opens_a_host_still_attaches_to_parent() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex: OpenSSH restores the including file's active Host scope after an Include — a `Host`
        // opened in the included file does not leak forward. Verified with `ssh -G parent` on this
        // exact config: hostname=parent.host AND user=deploy both attach to `parent`, even though
        // `User deploy` follows an Include whose child opened `Host child`.
        let fixture = ConfigFixture::new(
            "include-restore-scope",
            "Host parent\n  HostName parent.host\n  Include config.d/child\n  User deploy\n",
        );
        fixture.write_extra("config.d/child", "Host child\n  HostName child.host\n");
        let hosts = discover_hosts();
        let parent = hosts.iter().find(|h| h.alias == "parent").expect("parent");
        assert_eq!(parent.hostname.as_deref(), Some("parent.host"));
        assert_eq!(
            parent.user.as_deref(),
            Some("deploy"),
            "User after an Include that opened its own Host must still attach to the parent block"
        );
    }

    #[test]
    fn shared_include_reused_under_multiple_hosts_applies_to_each() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): OpenSSH re-inserts a shared Include each time it appears. A file pulled in
        // under two Host blocks must attribute its HostName/User to BOTH, not only the first (the old
        // global visited-set guard dropped it for the second block).
        let fixture = ConfigFixture::new(
            "shared-include",
            "Host a\n  Include config.d/common\n\nHost b\n  Include config.d/common\n",
        );
        fixture.write_extra("config.d/common", "HostName shared.host\n  User shared\n");
        let hosts = discover_hosts();

        let a = hosts.iter().find(|h| h.alias == "a").expect("host a");
        let b = hosts.iter().find(|h| h.alias == "b").expect("host b");
        assert_eq!(a.hostname.as_deref(), Some("shared.host"));
        assert_eq!(a.user.as_deref(), Some("shared"));
        assert_eq!(b.hostname.as_deref(), Some("shared.host"));
        assert_eq!(b.user.as_deref(), Some("shared"));
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
    fn include_budget_exhaustion_still_parses_later_host_lines() {
        let _lock = ENV_LOCK.lock().unwrap();
        // PRRT...Hph: exhausting the file/glob budget must stop only further Include expansion, not
        // the rest of the current file — `Host` blocks after the spent Include still get parsed.
        let fixture = ConfigFixture::new(
            "budget-continue",
            "Include config.d/*\nInclude config.d/*\nHost trailing\n  HostName t.host\n",
        );
        for i in 0..MAX_CONFIG_FILES {
            fixture.write_extra(&format!("config.d/g{i}"), &format!("Host g{i}\n"));
        }
        let aliases: Vec<_> = discover_hosts().into_iter().map(|h| h.alias).collect();
        assert!(
            aliases.contains(&"trailing".to_string()),
            "a Host after a budget-exhausted Include must still be parsed"
        );
    }

    #[test]
    fn caps_oversized_alias_and_field_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): a single line can't push a huge string into the response. An over-length
        // alias is dropped; an over-length HostName/User is ignored; an at-cap alias is kept.
        let long = "a".repeat(MAX_FIELD_LEN + 1);
        let at_cap = "b".repeat(MAX_FIELD_LEN);
        let body = format!(
            "Host {long}\n  HostName h.host\n\nHost prod\n  HostName {long}\n  User {long}\n\nHost {at_cap}\n"
        );
        let _fixture = ConfigFixture::new("field-caps", &body);
        let hosts = discover_hosts();
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.clone()).collect();

        assert!(
            !aliases.iter().any(|a| a.len() > MAX_FIELD_LEN),
            "no over-length alias survives"
        );
        assert!(aliases.contains(&"prod".to_string()));
        assert!(aliases.contains(&at_cap), "an at-cap alias is kept");
        let prod = hosts.iter().find(|h| h.alias == "prod").unwrap();
        assert!(prod.hostname.is_none(), "oversized HostName ignored");
        assert!(prod.user.is_none(), "oversized User ignored");
    }

    #[test]
    fn caps_total_discovered_payload_bytes() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): discovery stops once the retained alias/field payload reaches the byte
        // budget, so the response stays bounded even within the host-count and per-file caps. Split
        // ~1.3 MiB of long aliases across include files (each under the 1 MiB per-file cap).
        let fixture = ConfigFixture::new(
            "payload-budget",
            "Include config.d/a\nInclude config.d/b\nInclude config.d/c\n",
        );
        let per_file = 2000usize; // 2000 * ~250 bytes ≈ 0.5 MiB/file, 3 files > 1 MiB budget
        for (fi, name) in ["a", "b", "c"].iter().enumerate() {
            let mut body = String::new();
            for i in 0..per_file {
                let alias = format!("{:0>240}", fi * per_file + i); // unique ~240-char aliases
                body.push_str("Host ");
                body.push_str(&alias);
                body.push('\n');
            }
            fixture.write_extra(&format!("config.d/{name}"), &body);
        }
        let hosts = discover_hosts();
        assert!(
            hosts.len() < per_file * 3,
            "the byte budget must truncate discovery before all {} aliases: got {}",
            per_file * 3,
            hosts.len()
        );
    }

    #[test]
    fn hostname_user_fanout_respects_the_payload_budget() {
        let _lock = ENV_LOCK.lock().unwrap();
        // codex (re-run): a single Host line with thousands of aliases, then a 256-byte HostName +
        // User, must not clone the value onto every alias past the payload budget.
        let big_value = "h".repeat(MAX_FIELD_LEN);
        let mut line = String::from("Host");
        for i in 0..(MAX_HOSTS + 100) {
            line.push(' ');
            line.push_str(&format!("a{i}"));
        }
        let body = format!("{line}\n  HostName {big_value}\n  User {big_value}\n");
        let _fixture = ConfigFixture::new("fanout-budget", &body);
        let hosts = discover_hosts();

        let retained: usize = hosts
            .iter()
            .map(|h| {
                h.alias.len()
                    + h.hostname.as_ref().map_or(0, |s| s.len())
                    + h.user.as_ref().map_or(0, |s| s.len())
            })
            .sum();
        assert!(
            retained <= MAX_TOTAL_PAYLOAD_BYTES + MAX_FIELD_LEN,
            "retained payload {retained} must stay within the budget even with field fan-out"
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
