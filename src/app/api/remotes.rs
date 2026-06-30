use crate::api::schema::{
    RemoteAddParams, RemoteRemoveParams, RemoteRenameParams, RemoteSetAutoUpdateParams,
    RemoteSetEnabledParams, ResponseResult,
};
use crate::app::App;

use super::responses::{encode_error, encode_success};

impl App {
    pub(super) fn handle_remote_list(&mut self, id: String) -> String {
        encode_success(
            id,
            ResponseResult::RemoteList {
                remotes: self.state.remote_registry.remotes.clone(),
            },
        )
    }

    pub(super) fn handle_remote_add(&mut self, id: String, params: RemoteAddParams) -> String {
        match self.state.remote_registry.add_excluding_targets(
            params.name,
            params.target,
            params.keybindings,
            &main_server_remote_targets(),
        ) {
            Ok(remote) => {
                self.state.mark_session_dirty();
                encode_success(id, ResponseResult::RemoteAdded { remote })
            }
            Err(err) => encode_error(id, err.code(), err.message()),
        }
    }

    pub(super) fn handle_remote_remove(
        &mut self,
        id: String,
        params: RemoteRemoveParams,
    ) -> String {
        match self.state.remote_registry.remove(&params.remote_id) {
            Ok(remote_id) => {
                self.state.mark_session_dirty();
                encode_success(id, ResponseResult::RemoteRemoved { remote_id })
            }
            Err(err) => encode_error(id, err.code(), err.message()),
        }
    }

    pub(super) fn handle_remote_rename(
        &mut self,
        id: String,
        params: RemoteRenameParams,
    ) -> String {
        match self
            .state
            .remote_registry
            .rename(&params.remote_id, params.name)
        {
            Ok(remote) => {
                self.state.mark_session_dirty();
                encode_success(id, ResponseResult::RemoteRenamed { remote })
            }
            Err(err) => encode_error(id, err.code(), err.message()),
        }
    }

    pub(super) fn handle_remote_set_enabled(
        &mut self,
        id: String,
        params: RemoteSetEnabledParams,
    ) -> String {
        match self
            .state
            .remote_registry
            .set_enabled(&params.remote_id, params.enabled)
        {
            Ok(remote) => {
                self.state.mark_session_dirty();
                encode_success(id, ResponseResult::RemoteEnabledChanged { remote })
            }
            Err(err) => encode_error(id, err.code(), err.message()),
        }
    }

    /// #11: read-only enumeration of connectable `Host` aliases from the user's `~/.ssh/config`
    /// (following `Include`s, skipping wildcard/pattern hosts), with resolved `HostName`/`User` for
    /// display. Discovery only — never writes the ssh config and does not touch session state, so it
    /// does NOT `mark_session_dirty`. The client turns chosen aliases into `remote.add` calls.
    pub(super) fn handle_remote_ssh_config_hosts(&mut self, id: String) -> String {
        encode_success(
            id,
            ResponseResult::SshConfigHosts {
                hosts: crate::ssh_config::discover_hosts(),
            },
        )
    }

    /// #11: deferred variant of `remote.ssh_config_hosts`. `discover_hosts()` is bounded but does
    /// blocking filesystem IO (up to 256 files / 65k dir-entry scans), and it touches no `App` state,
    /// so the real socket path runs it on a worker thread and answers the request channel directly —
    /// keeping the synchronous app loop free for input, rendering, and other API/remote-lifecycle
    /// work. Mirrors the deferred worktree APIs, but needs no completion event since there is no
    /// state mutation to fold back onto the loop. Returns `true` (always handled).
    pub(crate) fn handle_deferred_remote_ssh_config_hosts(
        &mut self,
        request: crate::api::schema::Request,
        respond_to: std::sync::mpsc::Sender<String>,
    ) -> bool {
        let id = request.id;
        std::thread::spawn(move || {
            let hosts = crate::ssh_config::discover_hosts();
            let response = encode_success(id, ResponseResult::SshConfigHosts { hosts });
            let _ = respond_to.send(response);
        });
        true
    }

    /// #61: persist a remote's per-remote auto-update flag. Mirrors `handle_remote_set_enabled`;
    /// reuses the `RemoteEnabledChanged` success body (it just carries the updated definition — the
    /// client re-syncs the flag off the periodic `remote.list`, not this response).
    pub(super) fn handle_remote_set_auto_update(
        &mut self,
        id: String,
        params: RemoteSetAutoUpdateParams,
    ) -> String {
        match self
            .state
            .remote_registry
            .set_auto_update(&params.remote_id, params.auto_update)
        {
            Ok(remote) => {
                self.state.mark_session_dirty();
                encode_success(id, ResponseResult::RemoteEnabledChanged { remote })
            }
            Err(err) => encode_error(id, err.code(), err.message()),
        }
    }
}

fn main_server_remote_targets() -> Vec<crate::remote_registry::RemoteTargetSnapshot> {
    if let Ok(target) = std::env::var(crate::remote::MAIN_REMOTE_TARGET_ENV_VAR) {
        return crate::remote_registry::RemoteTargetSnapshot::parse(&target)
            .ok()
            .into_iter()
            .collect();
    }

    vec![crate::remote_registry::RemoteTargetSnapshot::Local {
        session: crate::session::active_name(),
    }]
}

#[cfg(test)]
mod tests {
    use crate::api::schema::{ErrorResponse, Request};
    use crate::app::App;
    use crate::config::Config;
    use std::ffi::OsString;

    fn test_app() -> App {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        App::new(
            &Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        )
    }

    fn call(app: &mut App, json: &str) -> serde_json::Value {
        let request: Request = serde_json::from_str(json).unwrap();
        let response = app.handle_api_request(request);
        serde_json::from_str(&response).unwrap()
    }

    fn error_code(app: &mut App, json: &str) -> String {
        let request: Request = serde_json::from_str(json).unwrap();
        let response = app.handle_api_request(request);
        let error: ErrorResponse = serde_json::from_str(&response).unwrap();
        error.error.code
    }

    fn capture_snapshot(app: &App) -> crate::persist::SessionSnapshot {
        crate::persist::capture(
            &app.state.workspaces,
            &app.state.terminals,
            &app.terminal_runtimes,
            app.state.active,
            app.state.selected,
            app.state.sidebar_width,
            app.state.sidebar_section_split,
            app.state.collapsed_space_keys.clone(),
            app.state.remote_registry.clone(),
            &app.state.pane_id_aliases,
        )
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    struct SetEnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl SetEnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for SetEnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn remote_add_lists_definition_without_connection_state() {
        let mut app = test_app();

        let add = call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"user@x","keybindings":"local"}}"#,
        );

        assert_eq!(add["result"]["type"], "remote_added");
        assert_eq!(add["result"]["remote"]["id"], "remote-1");
        assert_eq!(add["result"]["remote"]["name"], "x");
        assert_eq!(add["result"]["remote"]["target"]["type"], "ssh");
        assert_eq!(add["result"]["remote"]["target"]["target"], "user@x");
        assert!(add["result"]["remote"].get("connection_state").is_none());
        assert!(add["result"]["remote"].get("socket").is_none());

        let list = call(
            &mut app,
            r#"{"id":"list","method":"remote.list","params":{}}"#,
        );

        assert_eq!(list["result"]["type"], "remote_list");
        assert_eq!(list["result"]["remotes"].as_array().unwrap().len(), 1);
        assert_eq!(list["result"]["remotes"][0]["name"], "x");
        assert!(list["result"]["remotes"][0]
            .get("connection_state")
            .is_none());
        assert!(list["result"]["remotes"][0].get("socket").is_none());

        let snapshot = capture_snapshot(&app);
        assert!(app.state.session_dirty);
        assert_eq!(snapshot.remote_registry.remotes.len(), 1);
        assert_eq!(snapshot.remote_registry.remotes[0].name, "x");
    }

    #[test]
    fn remote_add_rejects_duplicate_names_and_targets() {
        let mut app = test_app();

        call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"user@x"}}"#,
        );

        assert_eq!(
            error_code(
                &mut app,
                r#"{"id":"dup_name","method":"remote.add","params":{"name":"x","target":"user@y"}}"#,
            ),
            "duplicate_remote_name"
        );
        assert_eq!(
            error_code(
                &mut app,
                r#"{"id":"dup_target","method":"remote.add","params":{"name":"y","target":"user@x"}}"#,
            ),
            "duplicate_remote_target"
        );
    }

    #[test]
    fn remote_add_rejects_current_main_local_target() {
        let _session_env = EnvVarGuard::remove(crate::session::SESSION_ENV_VAR);
        let _main_remote_env = EnvVarGuard::remove(crate::remote::MAIN_REMOTE_TARGET_ENV_VAR);
        let mut app = test_app();

        assert_eq!(
            error_code(
                &mut app,
                r#"{"id":"add","method":"remote.add","params":{"name":"local","target":"localhost"}}"#
            ),
            "duplicate_remote_target"
        );
    }

    #[test]
    fn remote_remove_and_rename_update_only_the_registry() {
        let mut app = test_app();

        let add = call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"local:dev"}}"#,
        );
        let remote_id = add["result"]["remote"]["id"].as_str().unwrap();
        let rename = format!(
            r#"{{"id":"rename","method":"remote.rename","params":{{"remote_id":"{remote_id}","name":"dev"}}}}"#
        );

        let renamed = call(&mut app, &rename);

        assert_eq!(renamed["result"]["type"], "remote_renamed");
        assert_eq!(renamed["result"]["remote"]["id"], remote_id);
        assert_eq!(renamed["result"]["remote"]["name"], "dev");
        assert_eq!(renamed["result"]["remote"]["target"]["type"], "local");
        assert_eq!(renamed["result"]["remote"]["target"]["session"], "dev");

        let remove = format!(
            r#"{{"id":"remove","method":"remote.remove","params":{{"remote_id":"{remote_id}"}}}}"#
        );
        let removed = call(&mut app, &remove);

        assert_eq!(removed["result"]["type"], "remote_removed");
        assert_eq!(removed["result"]["remote_id"], remote_id);

        let list = call(
            &mut app,
            r#"{"id":"list","method":"remote.list","params":{}}"#,
        );
        assert!(list["result"]["remotes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn remote_set_enabled_flips_marks_dirty_and_lists() {
        let mut app = test_app();

        let add = call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"user@x"}}"#,
        );
        let remote_id = add["result"]["remote"]["id"].as_str().unwrap().to_string();
        app.state.session_dirty = false;

        let disable = format!(
            r#"{{"id":"disable","method":"remote.set_enabled","params":{{"remote_id":"{remote_id}","enabled":false}}}}"#
        );
        let response = call(&mut app, &disable);

        assert_eq!(response["result"]["type"], "remote_enabled_changed");
        assert_eq!(response["result"]["remote"]["id"], remote_id);
        assert_eq!(response["result"]["remote"]["disabled"], true);
        assert!(app.state.session_dirty);

        let snapshot = capture_snapshot(&app);
        assert_eq!(snapshot.remote_registry.remotes.len(), 1);
        assert!(snapshot.remote_registry.remotes[0].disabled);

        let list = call(
            &mut app,
            r#"{"id":"list","method":"remote.list","params":{}}"#,
        );
        assert_eq!(list["result"]["remotes"][0]["disabled"], true);
    }

    #[test]
    fn remote_set_enabled_unknown_id_returns_not_found() {
        let mut app = test_app();
        assert_eq!(
            error_code(
                &mut app,
                r#"{"id":"set","method":"remote.set_enabled","params":{"remote_id":"missing","enabled":false}}"#,
            ),
            "remote_not_found"
        );
    }

    #[test]
    fn remote_set_auto_update_persists_marks_dirty_and_lists() {
        // #61: toggling auto-update flips the persisted flag, marks the session dirty, and the flag
        // round-trips through `remote.list`.
        let mut app = test_app();
        let add = call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"user@x"}}"#,
        );
        let remote_id = add["result"]["remote"]["id"].as_str().unwrap().to_string();
        app.state.session_dirty = false;

        let enable = format!(
            r#"{{"id":"au","method":"remote.set_auto_update","params":{{"remote_id":"{remote_id}","auto_update":true}}}}"#
        );
        let response = call(&mut app, &enable);
        assert_eq!(response["result"]["type"], "remote_enabled_changed");
        assert_eq!(response["result"]["remote"]["id"], remote_id);
        assert_eq!(response["result"]["remote"]["auto_update"], true);
        assert!(app.state.session_dirty);

        let snapshot = capture_snapshot(&app);
        assert!(snapshot.remote_registry.remotes[0].auto_update);

        let list = call(
            &mut app,
            r#"{"id":"list","method":"remote.list","params":{}}"#,
        );
        assert_eq!(list["result"]["remotes"][0]["auto_update"], true);
    }

    #[test]
    fn remote_set_auto_update_unknown_id_returns_not_found() {
        let mut app = test_app();
        assert_eq!(
            error_code(
                &mut app,
                r#"{"id":"set","method":"remote.set_auto_update","params":{"remote_id":"missing","auto_update":true}}"#,
            ),
            "remote_not_found"
        );
    }

    #[test]
    fn ssh_config_hosts_enumerates_aliases_without_marking_dirty() {
        // #11: the read-only discovery method returns the config's concrete aliases (with display
        // fields) and must not dirty the session. Point it at a temp config via the env override.
        // Share the ssh_config tests' lock so the process-global `HERDR_SSH_CONFIG_PATH`/`HOME`
        // mutations can't race those tests under plain `cargo test`.
        let _env_lock = crate::ssh_config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("herdr-api-ssh-cfg");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config");
        std::fs::write(
            &config_path,
            "Host prod\n  HostName 10.0.0.5\n  User deploy\n\nHost *\n  User everyone\n",
        )
        .unwrap();
        let _guard = SetEnvGuard::set(crate::ssh_config::SSH_CONFIG_PATH_ENV_VAR, &config_path);

        let mut app = test_app();
        app.state.session_dirty = false;

        let response = call(
            &mut app,
            r#"{"id":"hosts","method":"remote.ssh_config_hosts","params":{}}"#,
        );

        assert_eq!(response["result"]["type"], "ssh_config_hosts");
        let hosts = response["result"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1, "wildcard host must be excluded: {hosts:?}");
        assert_eq!(hosts[0]["alias"], "prod");
        assert_eq!(hosts[0]["hostname"], "10.0.0.5");
        assert_eq!(hosts[0]["user"], "deploy");
        assert!(!app.state.session_dirty, "discovery must not dirty session");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deferred_ssh_config_hosts_answers_off_loop_via_channel() {
        // #11 (codex iter 4): the real socket path defers discovery to a worker thread and answers
        // the request channel directly, so it never blocks the synchronous app loop. The handler
        // returns true (handled) and a full response lands on the channel.
        let _env_lock = crate::ssh_config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("herdr-api-ssh-cfg-deferred");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config");
        std::fs::write(&config_path, "Host prod\n  HostName 10.0.0.5\n").unwrap();
        let _guard = SetEnvGuard::set(crate::ssh_config::SSH_CONFIG_PATH_ENV_VAR, &config_path);

        let mut app = test_app();
        let (tx, rx) = std::sync::mpsc::channel();
        let request: Request = serde_json::from_str(
            r#"{"id":"hosts","method":"remote.ssh_config_hosts","params":{}}"#,
        )
        .unwrap();
        assert!(app.handle_deferred_remote_ssh_config_hosts(request, tx));

        let raw = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("deferred discovery should answer the channel");
        let response: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(response["result"]["type"], "ssh_config_hosts");
        assert_eq!(response["result"]["hosts"][0]["alias"], "prod");
        assert!(!app.state.session_dirty, "discovery must not dirty session");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enabled_remote_list_json_omits_disabled_key() {
        let mut app = test_app();
        call(
            &mut app,
            r#"{"id":"add","method":"remote.add","params":{"name":"x","target":"user@x"}}"#,
        );

        let list = call(
            &mut app,
            r#"{"id":"list","method":"remote.list","params":{}}"#,
        );
        assert!(list["result"]["remotes"][0].get("disabled").is_none());
    }
}
