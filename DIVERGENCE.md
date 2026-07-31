# what's different

herdr-mx = upstream [herdr](https://github.com/ogulcancelik/herdr) + the changes on this page. nothing else.

currently tracking: **upstream v0.7.5** (released 2026-07-21). policy: every upstream release is merged within days, mx releases are tagged `v<upstream>-mx.<n>`, and anything on this page is offered upstream when it fits — when a feature lands upstream it leaves this page. when *everything* lands upstream, herdr-mx retires.

## the big one: multi-remote client

upstream herdr attaches to one server at a time (`herdr --remote <host>` per terminal). herdr-mx makes the client a **fleet console**:

- **one sidebar, every machine** — register secondary local or SSH-backed herdr servers; their workspaces and agents appear in the same sidebar as your main session, with combined status summaries (blocked / working / done across hosts at a glance).
- **add-remote that provisions itself** — point it at any ssh host; the host row appears in the sidebar immediately and herdr-mx installs the matching server binary in the background, streaming a multiline stage log under the host banner. transient failures keep retrying with backoff; terminal ones (ssh auth, unknown host, impossible seed) pin a readable error on the row, retryable from the host menu or its status glyph. parsed ssh options (ports, identities, jump hosts) are honored.
- **offline cross-OS seeding, transitively** — the opt-in "fat" build (`just bundle`, `herdr bundle list|pack`) embeds macOS + Linux (x86_64/aarch64, static musl) binaries in one file, so a fresh host of a *different* OS is seeded at exact version parity with no release download on the remote. Cross-platform seeding repacks a fat bundle *for the remote's platform* on the fly (the carried binary becomes the native image; every other platform, including the seeding host's own, rides along compressed), so a mac-seeded linux host can in turn seed another mac offline.
- **per-remote lifecycle** — host context menu (add space / disable / disconnect / rename), per-remote auto-update-to-this-client toggle, live host version+protocol readout, one-click force-reinstall update with a multiline install log.
- **full workspace menu on every host** — the client sidebar's workspace context menu matches the server-rendered one, including the worktree rows: new worktree, open worktree… (picker), delete worktree checkout…, and group expand/collapse — all executed on the owning server over the API.
- **fast over distance** — semantic-frame delta streaming with compression for ~30fps remote panes, last-frame-first switching, accurate per-host ping/throughput in the banner.
- **isolation** — a secondary host going down never touches your main session.

## quality-of-life on top

- **sidebar settings TUI** — configurable agent segments and sidebar lines, applied instantly, with tab names shown in the multi-remote sidebar.
- **fleet-scale rendering** — model updates coalesced to one render per frame, cached sidebar shell, hover painted as a per-frame overlay; the client stays smooth with many remotes attached (upstream's single-remote client never hits these paths).
- **client overlay framework** — unified drag-to-move client menus, keyboard navigation, drag-reorder with preview, collapsed status-only sidebar mode.
- **clipboard image hardening (macOS)** — sandboxed/unreadable screenshot locations warn instead of silently failing; staged image paths paste un-bracketed so they attach; interactive panes spawn as login shells so `~/.zprofile` applies.

## intentionally changed from upstream

| area | upstream | herdr-mx | why |
|---|---|---|---|
| `herdr update` / update channels | herdr.dev manifests | disabled; brew/mise/releases | a stock-herdr download would silently remove multi-remote |
| version string | `0.7.3` | `0.7.3-mx.1` | so bug reports route to the right tracker |
| protocol version | `17` | `1017` (1000 + upstream) | mx appends its own wire variants, so an mx↔stock pairing at the same number would decode garbage; the offset fails clean at the handshake |
| settings popup | 76×22 base | 96×32 base | room for the sidebar settings TUI |
| windows build | preview beta | unavailable | the multi-remote client doesn't compile on windows yet ([#63](https://github.com/drod3763/herdr-mx/issues/63)) |
| ssh connection reuse (#888) | ControlMaster/ControlPersist via generated ssh config | not applied | mx removed ControlMaster after it spawned a duplicate herdr (#13); `[remote.transport]` (e.g. autossh) covers reconnecting bridges. re-evaluate with a repro under upstream's `manage_ssh_config` gate |
| `[remote].manage_ssh_config` keepalive (#355) | generated ssh config with `ServerAliveInterval` fallbacks | accepted but not consumed | deferred with the ControlMaster skip above; mx transport templates own reconnect behavior |
| sidebar row layouts (`[ui.sidebar.*].rows`, `rows_by_agent`, `row_gap`, and 0.7.5's inline `{ token, fg, bold, dim }` styles) | token-row renderer for expanded sidebar entries | accepted, kept in config/API schema, not rendered | the mx sidebar renders its own `lines` segment layout with the settings TUI; unifying onto upstream rows/tokens is tracked as a follow-up issue |
| API event subscription client (`ApiClient::subscribe_value`) | removed in 0.7.5 when CLI waits moved server-side | kept | the multi-remote client streams workspace/agent summary events over the JSON socket |
| `custom_status` sidebar segment | removed upstream in 0.7.4 (state labels + metadata tokens replace it) | segment retired | integration-reported labels render through the status segment via `state_labels`; the separate custom-status data source no longer exists |

## not yet re-applied as of upstream v0.7.5

- cline phantom-working guard (#37): upstream's manifest-based detection still defaults cline to "working"; the mx fix needs a `manifests/cline.toml` override (never shipped — still open).
- fish-shell remote bootstrap (#396) from the #60→#62 merge.
- upstream's non-POSIX-login-shell remote install fix (upstream #1203, xonsh) landed in the ControlMaster install path mx removed; audit the mx transport seeding path for the same multiline `sh -c` assumption.
- upstream sidebar renderer fixes tied to its token rows (collapsed row numbering by list position, per-agent row heights) don't map onto the mx segment renderer; revisit with the rows/tokens unification issue.
