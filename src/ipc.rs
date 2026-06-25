use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub(crate) type LocalListener = interprocess::local_socket::Listener;
pub(crate) type LocalStream = interprocess::local_socket::Stream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketFileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    marker: Vec<u8>,
}

pub(crate) fn connect_local_stream(path: &Path) -> io::Result<LocalStream> {
    #[cfg(unix)]
    {
        use interprocess::local_socket::{prelude::*, GenericFilePath};

        let name = path.to_fs_name::<GenericFilePath>()?;
        LocalStream::connect(name)
    }

    #[cfg(windows)]
    {
        use interprocess::local_socket::{prelude::*, GenericNamespaced};

        let name = path.to_string_lossy().to_string();
        let name = name.to_ns_name::<GenericNamespaced>()?;
        LocalStream::connect(name)
    }
}

pub(crate) fn bind_local_listener(path: &Path) -> io::Result<LocalListener> {
    #[cfg(unix)]
    {
        use interprocess::local_socket::{prelude::*, GenericFilePath, ListenerOptions};

        let name = path.to_fs_name::<GenericFilePath>()?;
        // Force a restrictive umask so the socket inode is born owner-only (0o600) rather
        // than being created with the process default umask and chmod'd afterward. The
        // post-bind `restrict_socket_permissions` call remains the authoritative mode, but
        // this closes the brief TOCTOU window where another local user could connect.
        let _umask = UmaskGuard::restrictive();
        ListenerOptions::new()
            .name(name)
            .reclaim_name(false)
            .create_sync()
    }

    #[cfg(windows)]
    {
        use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions};

        let name = path.to_string_lossy().to_string();
        let name = name.to_ns_name::<GenericNamespaced>()?;
        let listener = ListenerOptions::new()
            .name(name)
            .reclaim_name(false)
            .create_sync()?;
        fs::write(path, windows_socket_marker())?;
        Ok(listener)
    }
}

pub(crate) fn prepare_socket_path(
    path: &Path,
    busy_message: impl FnOnce(&Path) -> String,
) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        return Ok(());
    }

    match connect_local_stream(path) {
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, busy_message(path)));
        }
        Err(err) if stale_socket_connect_error(err.kind()) => {}
        Err(err) => return Err(err),
    }

    if let Err(err) = fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err);
        }
    }

    Ok(())
}

fn stale_socket_connect_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound | io::ErrorKind::TimedOut
    ) || (cfg!(windows) && kind == io::ErrorKind::WouldBlock)
}

pub(crate) fn socket_file_identity(path: &Path) -> io::Result<SocketFileIdentity> {
    #[cfg(windows)]
    {
        Ok(SocketFileIdentity {
            marker: fs::read(path)?,
        })
    }

    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)?;
        Ok(SocketFileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

pub(crate) fn remove_socket_file_if_owned(
    path: &Path,
    identity: &SocketFileIdentity,
) -> io::Result<()> {
    let current = match socket_file_identity(path) {
        Ok(current) => current,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    if current != *identity {
        return Ok(());
    }

    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(windows)]
fn windows_socket_marker() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}:{now}", std::process::id())
}

#[cfg(unix)]
pub(crate) fn restrict_socket_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
}

#[cfg(windows)]
pub(crate) fn restrict_socket_permissions(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// RAII guard that installs a restrictive `umask` for its lifetime so files and sockets
/// created while it is held are born without group/other access (`mode & 0o177 == 0`).
///
/// `umask(2)` is process-global, so a guard must be held only across the individual
/// create/bind call it protects — never around unrelated work that might create files
/// expected to be group/other readable. Socket binds happen at startup and on
/// remote-connect, so contention with other threads is negligible.
#[cfg(unix)]
pub(crate) struct UmaskGuard {
    previous: libc::mode_t,
}

#[cfg(unix)]
impl UmaskGuard {
    pub(crate) fn restrictive() -> Self {
        // SAFETY: `umask` cannot fail and always returns the previous mask. We restore it on drop.
        let previous = unsafe { libc::umask(0o177) };
        Self { previous }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restore the mask captured at construction.
        unsafe {
            libc::umask(self.previous);
        }
    }
}

/// Windows has no `umask`; socket permissions are handled by `restrict_socket_permissions`
/// (also a no-op there). The guard exists so callers stay platform-agnostic.
#[cfg(windows)]
pub(crate) struct UmaskGuard;

#[cfg(windows)]
impl UmaskGuard {
    pub(crate) fn restrictive() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    fn bind_local_listener_creates_owner_only_socket() {
        use std::os::unix::fs::PermissionsExt;

        // Force a fully-permissive process umask so a socket created without the guard
        // WOULD show group/other bits — isolating the guard as the thing under test.
        // SAFETY: nextest runs each test in its own process; we restore the mask below.
        let previous = unsafe { libc::umask(0) };

        let dir = std::env::temp_dir().join(format!("herdr-ipc-umask-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test.sock");
        let _ = fs::remove_file(&path);

        let listener = bind_local_listener(&path).expect("bind listener");
        let mode = fs::metadata(&path)
            .expect("stat socket")
            .permissions()
            .mode();

        // SAFETY: restore the umask captured above.
        unsafe {
            libc::umask(previous);
        }
        drop(listener);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(
            mode & 0o177,
            0,
            "socket must be born owner-only, got mode {mode:o}"
        );
    }

    #[test]
    fn stale_socket_connect_errors_keep_unix_would_block_strict() {
        assert!(stale_socket_connect_error(io::ErrorKind::ConnectionRefused));
        assert!(stale_socket_connect_error(io::ErrorKind::NotFound));
        assert!(stale_socket_connect_error(io::ErrorKind::TimedOut));
        assert_eq!(
            stale_socket_connect_error(io::ErrorKind::WouldBlock),
            cfg!(windows)
        );
    }

    #[cfg(windows)]
    #[test]
    fn remove_socket_file_if_owned_compares_windows_marker_contents() {
        let path = temp_socket_marker_path("same-len-marker");
        let _ = fs::remove_file(&path);

        fs::write(&path, b"marker-aa").expect("write first marker");
        let identity = socket_file_identity(&path).expect("read first identity");
        fs::write(&path, b"marker-bb").expect("replace with same-length marker");

        remove_socket_file_if_owned(&path, &identity).expect("remove owned marker");

        assert!(path.exists(), "same-length replacement marker must survive");

        let _ = fs::remove_file(&path);
    }

    #[cfg(windows)]
    fn temp_socket_marker_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("herdr-{name}-{}.sock", std::process::id()))
    }
}
