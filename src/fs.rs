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
}

impl Fd {
    pub fn new(kind: FdKind) -> Fd {
        Fd {
            kind,
            dir_pos: 0,
            dir_entries: None,
        }
    }
}

pub struct GuestFs {
    pub root: PathBuf,
    /// Guest-visible cwd, normalized absolute ("/" or "/a/b").
    pub cwd: String,
    pub fds: HashMap<i32, Fd>,
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
