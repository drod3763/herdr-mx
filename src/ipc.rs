use std::fs;
use std::io;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[cfg(unix)]
use interprocess::local_socket::traits::Stream as _;

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

pub(crate) fn local_stream_peer_closed(stream: &mut LocalStream) -> io::Result<bool> {
    probe_stream_closed(stream)
}

#[cfg(unix)]
fn probe_stream_closed(stream: &mut LocalStream) -> io::Result<bool> {
    stream.set_nonblocking(true)?;
    let mut probe = [0u8; 1];
    let status = match stream.read(&mut probe) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(true),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(err) if is_connection_closed_error(&err) => Ok(true),
        Err(err) => Err(err),
    };
    stream.set_nonblocking(false)?;
    status
}

#[cfg(windows)]
fn probe_stream_closed(stream: &mut LocalStream) -> io::Result<bool> {
    use std::os::windows::io::{AsHandle, AsRawHandle};

    let LocalStream::NamedPipe(pipe) = stream;
    let ok = unsafe {
        windows_sys::Win32::System::Pipes::PeekNamedPipe(
            pipe.as_handle().as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        return Ok(false);
    }

    let err = io::Error::last_os_error();
    if is_connection_closed_error(&err) || windows_named_pipe_closed_error(&err) {
        return Ok(true);
    }
    Err(err)
}

pub(crate) fn is_connection_closed_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WriteZero
    )
}

#[cfg(windows)]
fn windows_named_pipe_closed_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(6 | 109 | 232 | 233))
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

/// Serializes every `UmaskGuard` so the process-global `umask` is only ever changed by one guard
/// at a time. Without this, two overlapping guarded binds could interleave — one guard restoring
/// the original permissive umask while another is still mid-`create_sync()` — recreating the very
/// TOCTOU window the guard exists to close (and potentially leaving the umask stuck).
#[cfg(unix)]
static UMASK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard that installs a restrictive `umask` for its lifetime so files and sockets created
/// while it is held are born without group/other access (`mode & 0o177 == 0`).
///
/// Construction acquires [`UMASK_LOCK`] and holds it for the guard's lifetime, so the
/// set-umask → create → restore-umask sequence is atomic with respect to all other guards. Hold a
/// guard only across the individual create/bind call it protects — the lock also serializes other
/// guarded creates, so wrapping unrelated work would needlessly block them.
#[cfg(unix)]
pub(crate) struct UmaskGuard {
    previous: libc::mode_t,
    // Dropped after the custom `Drop` restores the umask, releasing the lock last.
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(unix)]
impl UmaskGuard {
    pub(crate) fn restrictive() -> Self {
        let lock = UMASK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: `umask` cannot fail and always returns the previous mask. We restore it on drop,
        // while still holding the lock, so no other guard observes the transient state.
        let previous = unsafe { libc::umask(0o177) };
        Self {
            previous,
            _lock: lock,
        }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restore the mask captured at construction. Runs before `_lock` is dropped, so the
        // restore is still serialized.
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
    use interprocess::local_socket::traits::Listener as _;
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

    #[cfg(unix)]
    #[test]
    fn umask_guard_serializes_concurrent_creates() {
        use std::os::unix::fs::PermissionsExt;

        // Permissive umask so any create that escaped the guard (e.g. a raced restore in another
        // thread) would be born group/other-accessible. The guard's lock must serialize all of
        // these so every file is 0600 regardless of interleaving.
        // SAFETY: nextest isolates each test in its own process; restored after the joins.
        let previous = unsafe { libc::umask(0) };
        let dir = std::env::temp_dir().join(format!("herdr-ipc-umask-conc-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let path = dir.join(format!("f{i}"));
                    let _ = fs::remove_file(&path);
                    let _guard = UmaskGuard::restrictive();
                    fs::File::create(&path).expect("create file under guard");
                    fs::metadata(&path).expect("stat").permissions().mode()
                })
            })
            .collect();
        let modes: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // SAFETY: restore the umask captured above and confirm no guard left it stuck.
        let after = unsafe { libc::umask(previous) };
        let _ = fs::remove_dir_all(&dir);

        for mode in modes {
            assert_eq!(
                mode & 0o177,
                0,
                "file born group/other-accessible under concurrent guards, mode {mode:o}"
            );
        }
        assert_eq!(after & 0o777, 0, "process umask left stuck at {after:o}");
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
    #[test]
    fn idle_named_pipe_peer_is_not_treated_as_closed() {
        let path = temp_socket_marker_path("idle-pipe");
        let listener = bind_local_listener(&path).unwrap();
        let _client = connect_local_stream(&path).unwrap();
        let mut server = listener.accept().unwrap();

        assert!(!local_stream_peer_closed(&mut server).unwrap());

        let _ = fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    fn disconnected_named_pipe_peer_is_treated_as_closed() {
        let path = temp_socket_marker_path("disconnected-pipe");
        let listener = bind_local_listener(&path).unwrap();
        let client = connect_local_stream(&path).unwrap();
        let mut server = listener.accept().unwrap();

        drop(client);

        assert!(local_stream_peer_closed(&mut server).unwrap());

        let _ = fs::remove_file(path);
    }

    #[cfg(windows)]
    fn temp_socket_marker_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("herdr-{name}-{}.sock", std::process::id()))
    }
}
