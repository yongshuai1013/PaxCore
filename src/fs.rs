//! Guest filesystem: rootfs path translation and the fd table.
//!
//! Guest paths are resolved lexically inside the rootfs prefix --
//! ".." is clamped at the guest root, so a guest can never escape.
//! The stat64 layout below was verified by compiling an offsetof
//! probe with the NDK clang (bionic struct stat == kernel stat64):
//! dev@0 ino32@12 mode@16 nlink@20 uid@24 gid@28 rdev@32
//! size@48 blksize@56 blocks@64 atime@72 mtime@80 ctime@88 ino64@96.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub enum FdKind {
    StdIn,
    StdOut,
    StdErr,
    File(File),
    Dir(PathBuf),
    Pipe(PipeEnd),
    /// /dev/binder: serviced entirely by the in-core binder
    /// driver (crate::binder) through the ioctl path.
    Binder,
    /// A character device registered by mknod. Behaviour is
    /// chosen by (major, minor) in Fd::read / Fd::write:
    /// (1,3) null, (1,5) zero, (5,1)/(5,0) console/tty,
    /// everything else an inert sink/source.
    CharDev { major: u32, minor: u32 },
    /// /dev/ashmem: an anonymous shared-memory region. The
    /// backing is created empty, sized by ASHMEM_SET_SIZE, and
    /// aliased by MAP_SHARED mmaps of this fd. MAP_PRIVATE
    /// mmaps take the snapshot path (zero-filled), which
    /// matches how Dalvik consumes its heap region.
    Ashmem {
        size: usize,
        backing: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    },
    /// A connected AF_UNIX stream endpoint. rx drains what the
    /// peer wrote; tx carries this end's writes (the two
    /// PipeShared queues of the pair cross over).
    UnixStream { rx: PipeEnd, tx: PipeEnd },
    /// An AF_UNIX socket after socket() but before bind().
    UnixSocket,
    /// An AF_UNIX socket bound to a filesystem path. The
    /// pending queue is shared with the core-wide registry
    /// (crate::syscall::UnixCore) that connect() looks up.
    UnixListener {
        path: String,
        pending: std::rc::Rc<
            std::cell::RefCell<std::collections::VecDeque<(PipeEnd, PipeEnd)>>,
        >,
    },
}

/// Build the two ends of a connected AF_UNIX stream pair.
/// PipeEnd::new_pair gives (read_end, write_end) over ONE
/// shared queue, so a stream pair needs two queues: endpoint
/// A reads queue 2 and writes queue 1, B is the mirror. The
/// queues' live-end counts give EOF (peer closed its write
/// end) and EPIPE (peer closed its read end) for free.
pub fn unix_stream_pair() -> (FdKind, FdKind) {
    let (q1_read, q1_write) = PipeEnd::new_pair();
    let (q2_read, q2_write) = PipeEnd::new_pair();
    let end_a = FdKind::UnixStream {
        rx: q2_read,
        tx: q1_write,
    };
    let end_b = FdKind::UnixStream {
        rx: q1_read,
        tx: q2_write,
    };
    (end_a, end_b)
}

/// Shared pipe buffer with live-end counts. Counts are kept by
/// PipeEnd's Clone/Drop so every fd lifecycle path (dup, fork,
/// close, process exit dropping its whole table) stays correct
/// without the call sites having to remember.
pub struct PipeShared {
    pub q: std::sync::Mutex<std::collections::VecDeque<u8>>,
    pub writers: std::sync::atomic::AtomicUsize,
    pub readers: std::sync::atomic::AtomicUsize,
}

pub struct PipeEnd {
    pub shared: std::sync::Arc<PipeShared>,
    pub write: bool,
}

impl PipeEnd {
    pub fn new_pair() -> (PipeEnd, PipeEnd) {
        use std::sync::atomic::AtomicUsize;
        let shared = std::sync::Arc::new(PipeShared {
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
            writers: AtomicUsize::new(1),
            readers: AtomicUsize::new(1),
        });
        (
            PipeEnd {
                shared: shared.clone(),
                write: false,
            },
            PipeEnd { shared, write: true },
        )
    }
    pub fn writers(&self) -> usize {
        self.shared.writers.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn readers(&self) -> usize {
        self.shared.readers.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn queued(&self) -> usize {
        self.shared.q.lock().unwrap().len()
    }
}

impl Clone for PipeEnd {
    fn clone(&self) -> PipeEnd {
        use std::sync::atomic::Ordering::SeqCst;
        if self.write {
            self.shared.writers.fetch_add(1, SeqCst);
        } else {
            self.shared.readers.fetch_add(1, SeqCst);
        }
        PipeEnd {
            shared: self.shared.clone(),
            write: self.write,
        }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::SeqCst;
        if self.write {
            self.shared.writers.fetch_sub(1, SeqCst);
        } else {
            self.shared.readers.fetch_sub(1, SeqCst);
        }
    }
}

pub struct Fd {
    pub kind: FdKind,
    /// Directory iteration cursor (entry index) for Dir fds.
    pub dir_pos: usize,
    /// Snapshot of directory entries, taken on first getdents64.
    pub dir_entries: Option<Vec<(String, u64, u8)>>,
    /// File status flags from open()/fcntl(F_SETFL); bit
    /// O_NONBLOCK (0x800) is the one the syscall layer acts on
    /// (EAGAIN instead of parking).
    pub status_flags: u32,
    /// FD_CLOEXEC, from fcntl(F_SETFD). Recorded, not acted on
    /// (exec does not close fds yet).
    pub cloexec: bool,
    /// Guest absolute path this fd was opened from, when known.
    /// MAP_SHARED keys its cross-process backing store on it:
    /// GB's property workspace fd is dup'd into services after
    /// the path itself is unlinked, so the path has to travel
    /// with the fd, not be re-derived from the filesystem.
    pub path: Option<String>,
}

impl Fd {
    pub fn new(kind: FdKind) -> Fd {
        Fd {
            kind,
            dir_pos: 0,
            dir_entries: None,
            status_flags: 0,
            cloexec: false,
            path: None,
        }
    }
    pub fn nonblock(&self) -> bool {
        self.status_flags & 0x800 != 0
    }
}

pub struct GuestFs {
    pub root: PathBuf,
    /// Guest-visible cwd, normalized absolute ("/" or "/a/b").
    pub cwd: String,
    pub fds: HashMap<i32, Fd>,
    /// Device nodes created by mknod: guest absolute path ->
    /// (mode, dev) exactly as the guest passed them. There is
    /// no host node behind these; open() consults this table
    /// before the host tree.
    pub devices: HashMap<String, (u32, u32)>,
}

impl GuestFs {
    pub fn new(root: String) -> GuestFs {
        let mut fds: HashMap<i32, Fd> = HashMap::new();
        fds.insert(0, Fd::new(FdKind::StdIn));
        fds.insert(1, Fd::new(FdKind::StdOut));
        fds.insert(2, Fd::new(FdKind::StdErr));
        GuestFs {
            root: PathBuf::from(root),
            cwd: "/".to_string(),
            fds,
            devices: HashMap::new(),
        }
    }

    /// Normalize a guest path (relative to cwd) to absolute form.
    pub fn resolve(&self, path: &str) -> String {
        self.resolve_from(&self.cwd.clone(), path)
    }

    /// Normalize a guest path relative to a given guest directory.
    pub fn resolve_from(&self, base: &str, path: &str) -> String {
        let joined = if path.starts_with('/') {
            path.to_string()
        } else if base == "/" {
            format!("/{path}")
        } else {
            format!("{base}/{path}")
        };
        let mut parts: Vec<&str> = Vec::new();
        for c in joined.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                _ => parts.push(c),
            }
        }
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    }

    pub fn host_path(&self, guest_abs: &str) -> PathBuf {
        let rel = guest_abs.trim_start_matches('/');
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    pub fn alloc_fd(&mut self, fd: Fd) -> i32 {
        let mut n = 3i32;
        while self.fds.contains_key(&n) {
            n += 1;
        }
        self.fds.insert(n, fd);
        n
    }
}

pub fn read_guest_str(mem: &crate::mem::Mem, ptr: u32) -> String {
    let mut s = Vec::new();
    let mut a = ptr;
    while (a as usize) < mem.len() && mem.byte(a) != 0 {
        s.push(mem.byte(a));
        a += 1;
    }
    String::from_utf8_lossy(&s).into_owned()
}

pub fn put(mem: &mut crate::mem::Mem, addr: u32, bytes: &[u8]) {
    mem.write_slice(addr, bytes);
}

pub fn put32(mem: &mut crate::mem::Mem, addr: u32, v: u32) {
    put(mem, addr, &v.to_le_bytes());
}
pub fn put64(mem: &mut crate::mem::Mem, addr: u32, v: u64) {
    put(mem, addr, &v.to_le_bytes());
}

/// Fill a kernel stat64 (104 bytes) at `addr` from host metadata.
pub fn fill_stat64(mem: &mut crate::mem::Mem, addr: u32, md: &std::fs::Metadata) {
    mem.zero_range(addr, 104);
    let mut mode = md.mode();
    if md.file_type().is_symlink() {
        // mode() already carries S_IFLNK for symlink metadata.
    } else {
        mode = (mode & !0o170000) | file_type_bits(md);
    }
    put64(mem, addr, md.dev());
    put32(mem, addr + 12, md.ino() as u32);
    put32(mem, addr + 16, mode);
    put32(mem, addr + 20, md.nlink() as u32);
    put32(mem, addr + 24, 1000); // guest uid
    put32(mem, addr + 28, 1000); // guest gid
    put64(mem, addr + 32, md.rdev());
    put64(mem, addr + 48, md.size());
    put32(mem, addr + 56, 4096);
    put64(mem, addr + 64, md.blocks());
    put32(mem, addr + 72, md.atime() as u32);
    put32(mem, addr + 76, md.atime_nsec() as u32);
    put32(mem, addr + 80, md.mtime() as u32);
    put32(mem, addr + 84, md.mtime_nsec() as u32);
    put32(mem, addr + 88, md.ctime() as u32);
    put32(mem, addr + 92, md.ctime_nsec() as u32);
    put64(mem, addr + 96, md.ino());
}

fn file_type_bits(md: &std::fs::Metadata) -> u32 {
    let ft = md.file_type();
    if ft.is_dir() {
        0o040000
    } else if ft.is_file() {
        0o100000
    } else if ft.is_symlink() {
        0o120000
    } else {
        0o100000
    }
}

impl Fd {
    pub fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.kind {
            FdKind::CharDev { major: 1, minor: 5 } => {
                // /dev/zero: endless zeroes.
                out.fill(0);
                Ok(out.len())
            }
            FdKind::Ashmem { .. } => Ok(0), // regions are mmap-only
            FdKind::CharDev { .. } => Ok(0), // null & co: EOF
            FdKind::UnixStream { rx, .. } => {
                let mut q = rx.shared.q.lock().unwrap();
                let n = q.len().min(out.len());
                for slot in out.iter_mut().take(n) {
                    *slot = q.pop_front().unwrap();
                }
                Ok(n)
            }
            FdKind::File(f) => f.read(out),
            FdKind::StdIn => Ok(0), // EOF (host stdin not wired in M1)
            FdKind::Pipe(end) if !end.write => {
                // The syscall layer guarantees data is queued (or
                // EOF applies); drain up to the buffer size.
                let mut q = end.shared.q.lock().unwrap();
                let n = q.len().min(out.len());
                for slot in out.iter_mut().take(n) {
                    *slot = q.pop_front().unwrap();
                }
                Ok(n)
            }
            _ => Err(std::io::Error::from_raw_os_error(9)),
        }
    }
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match &mut self.kind {
            FdKind::CharDev { major: 5, minor: 0 | 1 } => {
                // /dev/tty, /dev/console: the host's stdout.
                std::io::stdout().write(data)
            }
            FdKind::CharDev { major: 1, minor: 11 } => {
                // /dev/kmsg: the guest kernel log -- mirror it
                // to the host's stderr so init's own diagnostics
                // stay visible while debugging the boot.
                std::io::stderr().write(data)
            }
            FdKind::Ashmem { .. } => Ok(data.len()), // sink
            FdKind::CharDev { major: 250, .. } => {
                // /dev/log/*: the Android logger devices.
                // Entries carry a binary header (pid, time,
                // priority, tag); mirror the raw bytes to the
                // host's stderr -- assert messages from the
                // framework libraries land here, and without
                // these nodes the abort that follows them is
                // completely silent.
                std::io::stderr().write(data)
            }
            FdKind::CharDev { .. } => Ok(data.len()), // sink
            FdKind::UnixStream { tx, .. } => {
                if tx.readers() == 0 {
                    return Err(std::io::Error::from_raw_os_error(32)); // EPIPE
                }
                let mut q = tx.shared.q.lock().unwrap();
                let room = 65_536usize.saturating_sub(q.len());
                let n = room.min(data.len());
                q.extend(data[..n].iter().copied());
                Ok(n)
            }
            FdKind::File(f) => f.write(data),
            FdKind::StdOut => std::io::stdout().write(data),
            FdKind::StdErr => std::io::stderr().write(data),
            FdKind::Pipe(end) if end.write => {
                if end.readers() == 0 {
                    // EPIPE (a real kernel would also SIGPIPE;
                    // the error return is what guests check).
                    return Err(std::io::Error::from_raw_os_error(32));
                }
                // The syscall layer guarantees room for at least
                // one byte; accept what fits in the 64K buffer.
                let mut q = end.shared.q.lock().unwrap();
                let room = 65_536usize.saturating_sub(q.len());
                let n = room.min(data.len());
                q.extend(data[..n].iter().copied());
                Ok(n)
            }
            _ => Err(std::io::Error::from_raw_os_error(9)),
        }
    }
    pub fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match &mut self.kind {
            FdKind::File(f) => f.seek(pos),
            _ => Err(std::io::Error::from_raw_os_error(29)),
        }
    }
}
