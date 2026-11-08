//! Guest syscall layer (ARM EABI: nr in r7, args r0..r5, ret r0).
//! This is the seam where the "kernel" lives: today it is stdio and
//! exit; the binder driver, ashmem and the virtual devices will be
//! services behind this same dispatch, synthesized at the moment of
//! the guest's call -- the timing guarantee the ptrace supervisor
//! cannot give, true here by construction.
//!
//! M1: rootfs file service + the small POSIX surface static busybox
//! needs. Process-model calls (fork/exec/wait) stay loudly ENOSYS;
//! they are the M2 milestone.

use crate::cpu::Cpu;
use crate::mem::Mem;
use crate::fs::{fill_stat64, put, put32, put64, read_guest_str, Fd, FdKind, GuestFs};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::time::{SystemTime, UNIX_EPOCH};

/// One signal disposition, as installed by rt_sigaction. The
/// table lives behind an Rc so CLONE_SIGHAND threads share it.
#[derive(Clone, Copy, Default)]
pub struct SigAction {
    pub handler: u32, // 0 = default, 1 = ignore, else guest pc
    pub flags: u32,
    pub restorer: u32,
    pub mask: u64,
}

pub struct SigShared {
    pub actions: [SigAction; 65],
    /// Group-directed pending signals (kill(2) to the tgid).
    /// Lives here rather than on one member's `pending` so
    /// any thread of the group can consume them -- GB
    /// Dalvik's Signal Catcher thread waits in rt_sigtimedwait
    /// for process-directed SIGQUIT/SIGUSR1 that the main
    /// thread never touches.
    pub group_pending: u64,
}

impl Default for SigShared {
    fn default() -> SigShared {
        SigShared {
            actions: std::array::from_fn(|_| SigAction::default()),
            group_pending: 0,
        }
    }
}

/// Core-wide AF_UNIX listener registry: bound filesystem path
/// -> the pending-connection queue that the listener's accept()
/// drains and connect() pushes into. Shared by every task in
/// the run (like the binder core), because init binds sockets
/// that unrelated processes connect to.
pub struct UnixCore {
    pub listeners: std::collections::HashMap<
        String,
        std::rc::Rc<
            std::cell::RefCell<
                std::collections::VecDeque<(
                    crate::fs::PipeEnd,
                    crate::fs::PipeEnd,
                )>,
            >,
        >,
    >,
}

pub enum Outcome {
    Continue,
    /// kill/tkill/tgkill: the scheduler owns the process table
    /// and decides where the signal lands.
    SendSignal { tgid: u32, tid: Option<u32>, sig: u32 },
    /// rt_sigreturn: the scheduler restores the interrupted
    /// context from the signal frame on the guest stack.
    SigReturn,
    /// fork(2)/vfork(190): the scheduler clones the whole
    /// process; this layer only reports the request.
    Fork,
    /// execve(11): parsed arguments; the scheduler performs the
    /// image replacement (it owns the process) and reports load
    /// failures back as the syscall's error return.
    Exec {
        path: String,
        argv: Vec<String>,
        envp: Vec<String>,
    },
    /// wait4(114): reaping needs the scheduler's process table,
    /// so the request is handed out with its raw arguments.
    Wait4 { pid: i32, status_ptr: u32, options: u32 },
    /// A pipe read/write cannot proceed right now (empty buffer
    /// with the other end alive, or full buffer). r0 is left
    /// untouched; the scheduler parks the process and re-issues
    /// this syscall when it is scheduled again.
    WouldBlock,
    /// A binder BINDER_WRITE_READ consumed its write side but
    /// has nothing to deliver on the read side. The scheduler
    /// parks the process (without counting it toward the pipe
    /// EAGAIN streak) and re-issues the ioctl once the binder
    /// core has inbox work for it; the guest's write_consumed
    /// field makes the re-issue skip the write side.
    BinderWait,
    /// clone(120) with its raw arguments (ARM order: flags,
    /// stack, parent_tid, tls, child_tid). Thread creation and
    /// its sharing flags are the scheduler's business.
    Clone {
        flags: u32,
        stack: u32,
        ptid: u32,
        tls: u32,
        ctid: u32,
    },
    /// exit(1): terminate only the calling thread.
    ExitThread(u32),
    /// exit_group(248): terminate the whole thread group.
    ExitGroup(u32),
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EAGAIN: i32 = 11;
const EFAULT: i32 = 14;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ERANGE: i32 = 34;
const ENOSYS: i32 = 38;

const AT_FDCWD: i32 = -100;
const MAP_BASE: u32 = 0x0200_0000;

/// Address-space bookkeeping: the program break, the mmap
/// bump pointer and the live mmap interval list (base, len),
/// page aligned. GB binaries are prelinked: the linker
/// demands exact load addresses via mmap hints, so hint-less
/// bump allocation alone cannot serve it -- the intervals
/// also decide whether a hinted address is free and what
/// MAP_FIXED / munmap replace.
///
/// This state describes the shared memory, so CLONE_VM
/// threads must share ONE instance. A per-thread copy
/// diverges silently: one thread's stale brk value makes a
/// later brk "grow" re-zero heap pages another thread is
/// actively using (GB Dalvik lost its Signal Catcher's
/// bootstrap block exactly this way).
pub struct AddrSpace {
    pub brk: u32,
    pub mmap_next: u32,
    pub maps: Vec<(u32, u32)>,
}

pub struct Syscalls {
    pub fs: GuestFs,
    pub log_unimplemented: bool,
    seen: std::collections::HashSet<u32>,
    pub asp: std::rc::Rc<std::cell::RefCell<AddrSpace>>,
    rng: u64,
    /// This process's pid / parent pid (scheduler-assigned).
    pub pid: u32,
    pub ppid: u32,
    /// Thread-group id (what getpid reports). Equals pid except
    /// in threads created with CLONE_THREAD.
    pub tgid: u32,
    /// set_tid_address target: cleared (with a futex wake, which
    /// our re-issue futex model performs implicitly) when this
    /// thread exits.
    pub tid_addr: u32,
    /// Guest path of the current program image (what
    /// /proc/self/exe resolves to). Set at startup and on exec.
    pub exe_path: String,
    /// Signal dispositions + group pending signals, shared by
    /// CLONE_SIGHAND threads.
    pub sighand: std::rc::Rc<std::cell::RefCell<SigShared>>,
    /// This thread's blocked-signal mask (bit i = signal i+1).
    pub sig_mask: u64,
    /// This thread's own pending signals.
    pub pending: u64,
    /// flock() state: guest path -> (holding fd, exclusive).
    /// Per-process table; the dex-cache locker is the only
    /// consumer so far and it locks its own fresh file.
    pub flocks: std::collections::HashMap<String, (i32, bool)>,
    /// The in-core binder driver, shared by every task in the
    /// run (binder IPC crosses process boundaries by design).
    pub binder: std::rc::Rc<std::cell::RefCell<crate::binder::BinderCore>>,
    /// File creation mask (umask syscall); consulted by the
    /// host-backed file creation paths only loosely -- the
    /// guest-visible value is what init reads back.
    pub umask: u32,
    /// The core-wide AF_UNIX listener registry.
    pub unix: std::rc::Rc<std::cell::RefCell<UnixCore>>,
    /// The core-wide MAP_SHARED backing registry: host file
    /// path -> shared bytes. Every process mapping the same
    /// file MAP_SHARED aliases the same store (GB's property
    /// workspace crosses process boundaries this way). Entries
    /// initialize from the host file on first use and are never
    /// written back -- the registry is the run's page cache.
    pub areas:
        std::rc::Rc<std::cell::RefCell<std::collections::HashMap<String, SharedBytes>>>,
}

/// One shared file area's backing store.
pub type SharedBytes = std::rc::Rc<std::cell::RefCell<Vec<u8>>>;

fn err(code: i32) -> u32 {
    (-code) as u32
}

fn io_err(e: &std::io::Error) -> u32 {
    err(e.raw_os_error().unwrap_or(5))
}

fn now_unix() -> (u64, u32) {
    if let Ok(s) = std::env::var("PAXCORE_FROZEN_TIME") {
        if let Ok(secs) = s.parse::<u64>() {
            return (secs, 123_456_789);
        }
    }
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_nanos())
}

fn fill_stat64_stdio(mem: &mut Mem, addr: u32) {
    let a = addr as usize;
    mem.zero_range(addr, 104);
    let a = addr as usize;
    let _ = a;
    put32(mem, addr + 16, 0o020000 | 0o600); // S_IFCHR | rw-------
    put32(mem, addr + 24, 1000);
    put32(mem, addr + 28, 1000);
    put32(mem, addr + 56, 4096);
}

impl Syscalls {
    pub fn new(rootfs: String, image_end: u32) -> Syscalls {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_nanos() as u64) ^ 0x9e37_79b9_7f4a_7c15)
            .unwrap_or(0x2545_f491);
        Syscalls {
            exe_path: String::new(),
            fs: GuestFs::new(rootfs),
            log_unimplemented: true,
            seen: std::collections::HashSet::new(),
            asp: std::rc::Rc::new(std::cell::RefCell::new(AddrSpace {
                brk: (image_end + 0xFFF) & !0xFFF,
                mmap_next: MAP_BASE,
                maps: Vec::new(),
            })),
            rng: seed | 1,
            pid: 100,
            ppid: 99,
            tgid: 100,
            tid_addr: 0,
            sighand: std::rc::Rc::new(std::cell::RefCell::new(SigShared::default())),
            sig_mask: 0,
            pending: 0,
            flocks: std::collections::HashMap::new(),
            binder: std::rc::Rc::new(std::cell::RefCell::new(crate::binder::BinderCore::new())),
            umask: 0o022,
            unix: std::rc::Rc::new(std::cell::RefCell::new(UnixCore {
                listeners: std::collections::HashMap::new(),
            })),
            areas: std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new())),
        }
    }

    /// Reset the address-space bookkeeping after a successful
    /// execve image replacement. The fd table, cwd, pid and rng
    /// deliberately survive (POSIX: open fds stay open across
    /// exec unless CLOEXEC, which we do not track yet).
    pub fn reset_exec(&mut self, image_end: u32) {
        let mut asp = self.asp.borrow_mut();
        asp.brk = (image_end + 0xFFF) & !0xFFF;
        asp.mmap_next = MAP_BASE;
        asp.maps.clear();
    }

    /// Is [base, base+len) disjoint from every live interval?
    fn range_free(&self, base: u32, len: u32) -> bool {
        let end = base.wrapping_add(len);
        self.asp
            .borrow()
            .maps
            .iter()
            .all(|&(b, l)| b.wrapping_add(l) <= base || b >= end)
    }

    /// Drop [base, base+len) from the interval list, trimming
    /// partial overlaps the way munmap/MAP_FIXED replacement do.
    fn unmap_range(&mut self, base: u32, len: u32) {
        let end = base.wrapping_add(len);
        let mut asp = self.asp.borrow_mut();
        let mut out = Vec::with_capacity(asp.maps.len());
        for &(b, l) in &asp.maps {
            let e = b.wrapping_add(l);
            if e <= base || b >= end {
                out.push((b, l));
            } else {
                if b < base {
                    out.push((b, base - b));
                }
                if e > end {
                    out.push((end, e - end));
                }
            }
        }
        asp.maps = out;
    }

    /// Duplicate this syscall state for a fork child. Open files
    /// are try_clone()d, which shares the host open file
    /// description -- file offsets stay shared across parent and
    /// child, exactly the POSIX fork semantics. Directory fds copy
    /// their cursor/snapshot (a later divergence from POSIX,
    /// accepted for now: guests rarely share dir reads across a
    /// fork, and the snapshot is identical at fork time).
    pub fn fork_clone(&self, child_pid: u32) -> Syscalls {
        let mut fds = std::collections::HashMap::new();
        for (num, fd) in &self.fs.fds {
            let kind = match &fd.kind {
                crate::fs::FdKind::StdIn => crate::fs::FdKind::StdIn,
                crate::fs::FdKind::StdOut => crate::fs::FdKind::StdOut,
                crate::fs::FdKind::StdErr => crate::fs::FdKind::StdErr,
                crate::fs::FdKind::File(f) => match f.try_clone() {
                    Ok(c) => crate::fs::FdKind::File(c),
                    Err(_) => continue,
                },
                crate::fs::FdKind::Dir(p) => crate::fs::FdKind::Dir(p.clone()),
                crate::fs::FdKind::Pipe(e) => crate::fs::FdKind::Pipe(e.clone()),
                crate::fs::FdKind::Binder => crate::fs::FdKind::Binder,
                crate::fs::FdKind::CharDev { major, minor } => crate::fs::FdKind::CharDev {
                    major: *major,
                    minor: *minor,
                },
                crate::fs::FdKind::UnixStream { rx, tx } => crate::fs::FdKind::UnixStream {
                    rx: rx.clone(),
                    tx: tx.clone(),
                },
                crate::fs::FdKind::UnixSocket => crate::fs::FdKind::UnixSocket,
                crate::fs::FdKind::UnixListener { path, pending } => {
                    crate::fs::FdKind::UnixListener {
                        path: path.clone(),
                        pending: pending.clone(),
                    }
                }
                crate::fs::FdKind::Ashmem { size, backing } => crate::fs::FdKind::Ashmem {
                    size: *size,
                    backing: backing.clone(),
                },
            };
            fds.insert(
                *num,
                crate::fs::Fd {
                    kind,
                    dir_pos: fd.dir_pos,
                    dir_entries: fd.dir_entries.clone(),
                    status_flags: fd.status_flags,
                    cloexec: fd.cloexec,
                    path: fd.path.clone(),
                },
            );
        }
        Syscalls {
            exe_path: self.exe_path.clone(),
            fs: crate::fs::GuestFs {
                root: self.fs.root.clone(),
                cwd: self.fs.cwd.clone(),
                fds,
                devices: self.fs.devices.clone(),
            },
            log_unimplemented: self.log_unimplemented,
            seen: self.seen.clone(),
            asp: std::rc::Rc::new(std::cell::RefCell::new(AddrSpace {
                brk: self.asp.borrow().brk,
                mmap_next: self.asp.borrow().mmap_next,
                maps: self.asp.borrow().maps.clone(),
            })),
            rng: self.rng,
            pid: child_pid,
            ppid: self.pid,
            tgid: child_pid,
            tid_addr: 0,
            sighand: std::rc::Rc::new(std::cell::RefCell::new(SigShared {
                actions: self.sighand.borrow().actions,
                group_pending: 0,
            })),
            sig_mask: self.sig_mask,
            pending: 0,
            flocks: self.flocks.clone(),
            binder: self.binder.clone(),
            umask: self.umask,
            unix: self.unix.clone(),
            areas: self.areas.clone(),
        }
    }

    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn do_open(&mut self, base: Option<String>, path: &str, flags: u32) -> u32 {
        let guest_abs = match &base {
            Some(b) => self.fs.resolve_from(b, path),
            None => self.fs.resolve(path),
        };
        let ret = self.do_open_inner(base, path, flags);
        if (ret as i32) >= 0 {
            if let Some(f) = self.fs.fds.get_mut(&(ret as i32)) {
                // O_NONBLOCK given at open time becomes the
                // fd's initial status flag (fcntl can change
                // it later).
                if flags & 0x800 != 0 {
                    f.status_flags |= 0x800;
                }
                // The path travels with the fd: MAP_SHARED
                // keys on it, and GB's property workspace fd
                // must still identify its area after init
                // unlinks the path.
                f.path = Some(guest_abs);
            }
        }
        ret
    }

    fn do_open_inner(&mut self, base: Option<String>, path: &str, flags: u32) -> u32 {
        let guest_abs = match &base {
            Some(b) => self.fs.resolve_from(b, path),
            None => self.fs.resolve(path),
        };
        // Devices the core services itself.
        if guest_abs == "/dev/binder" {
            let fd = Fd::new(FdKind::Binder);
            return self.fs.alloc_fd(fd) as u32;
        }
        if guest_abs == "/dev/urandom" {
            if let Ok(f) = std::fs::File::open("/dev/urandom") {
                let fd = Fd::new(FdKind::File(f));
                return self.fs.alloc_fd(fd) as u32;
            }
        }
        // /dev/ashmem: anonymous shared memory (see fs.rs).
        if guest_abs == "/dev/ashmem" {
            let fd = Fd::new(FdKind::Ashmem {
                size: 0,
                backing: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            });
            return self.fs.alloc_fd(fd) as u32;
        }
        // The Android logger devices (kernel driver nodes on
        // real hardware; init's ueventd would create them).
        if guest_abs.starts_with("/dev/log/") {
            let fd = Fd::new(FdKind::CharDev {
                major: 250,
                minor: 0,
            });
            return self.fs.alloc_fd(fd) as u32;
        }
        // Nodes registered by mknod (GB dev_t encoding:
        // major = dev >> 8, minor = dev & 0xff).
        if let Some(&(_mode, dev)) = self.fs.devices.get(&guest_abs) {
            let fd = Fd::new(FdKind::CharDev {
                major: dev >> 8,
                minor: dev & 0xFF,
            });
            return self.fs.alloc_fd(fd) as u32;
        }
        let host = self.fs.host_path(&guest_abs);
        let md = std::fs::metadata(&host);
        let o_creat = flags & 0x40 != 0;
        if md.is_err() && !o_creat {
            return err(ENOENT);
        }
        let is_dir = md.map(|m| m.is_dir()).unwrap_or(false);
        if is_dir {
            let fd = Fd::new(FdKind::Dir(host));
            return self.fs.alloc_fd(fd) as u32;
        }
        let mut opts = std::fs::OpenOptions::new();
        match flags & 0x3 {
            0 => {
                opts.read(true);
            }
            1 => {
                opts.write(true);
            }
            _ => {
                opts.read(true).write(true);
            }
        }
        if o_creat {
            opts.create(true);
        }
        if flags & 0x200 != 0 {
            opts.truncate(true);
        }
        if flags & 0x400 != 0 {
            opts.append(true);
        }
        match opts.open(&host) {
            Ok(f) => {
                let fd = Fd::new(FdKind::File(f));
                self.fs.alloc_fd(fd) as u32
            }
            Err(e) => io_err(&e),
        }
    }

    fn dir_guest_path(&self, fd: i32) -> Option<String> {
        match self.fs.fds.get(&fd).map(|f| &f.kind) {
            Some(FdKind::Dir(host)) => {
                let rel = host.strip_prefix(&self.fs.root).ok()?;
                let s = rel.to_string_lossy();
                Some(if s.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{s}")
                })
            }
            _ => None,
        }
    }

    fn do_stat(&mut self, mem: &mut Mem, fd_or: Option<i32>, path: &str, buf: u32, follow: bool) -> u32 {
        let md = if let Some(fd) = fd_or {
            match self.fs.fds.get(&fd).map(|f| &f.kind) {
                Some(FdKind::File(f)) => match f.metadata() {
                    Ok(m) => m,
                    Err(e) => return io_err(&e),
                },
                Some(FdKind::Dir(host)) => match std::fs::metadata(host) {
                    Ok(m) => m,
                    Err(e) => return io_err(&e),
                },
                Some(_) => {
                    // stdio: fake character device
                    if (buf as usize) + 104 > mem.len() {
                        return err(EFAULT);
                    }
                    fill_stat64_stdio(mem, buf);
                    return 0;
                }
                None => return err(EBADF),
            }
        } else {
            let guest_abs = self.fs.resolve(path);
            let host = self.fs.host_path(&guest_abs);
            let r = if follow {
                std::fs::metadata(&host)
            } else {
                std::fs::symlink_metadata(&host)
            };
            match r {
                Ok(m) => m,
                Err(e) => return io_err(&e),
            }
        };
        if (buf as usize) + 104 > mem.len() {
            return err(EFAULT);
        }
        fill_stat64(mem, buf, &md);
        0
    }

    pub fn handle(&mut self, cpu: &mut Cpu, mem: &mut Mem) -> Outcome {
        let nr = cpu.r[7];
        if (nr == 37 || nr == 126) && std::env::var_os("PAXCORE_BINDER_DEBUG").is_some() {
            eprintln!(
                "[syscall] nr={nr} from pc=0x{:08x} lr=0x{:08x} (pid {})",
                cpu.r[15], cpu.r[14], self.tgid
            );
        }
        if std::env::var_os("PAXCORE_TRACE").is_some()
            || std::env::var_os("PAXCORE_SYSCALLS").is_some()
        {
            let path_note = match nr {
                5 | 10 | 12 | 33 | 39 | 85 | 195 | 196 => {
                    format!(" path={:?}", read_guest_str(mem, cpu.r[0]))
                }
                322 | 334 => format!(" path={:?}", read_guest_str(mem, cpu.r[1])),
                _ => String::new(),
            };
            eprintln!(
                "[syscall] nr={nr} args={:#x} {:#x} {:#x} {:#x}{path_note}",
                cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3]
            );
        }
        let (a0, a1, a2, a3, a4) = (cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3], cpu.r[4]);
        if nr == 54
            && matches!(
                self.fs.fds.get(&(a0 as i32)).map(|f| &f.kind),
                Some(FdKind::Binder)
            )
        {
            // ioctl on /dev/binder: served by the in-core driver
            // (it can park, so it bypasses the u32 chain).
            return self.binder_ioctl(cpu, mem, a1, a2);
        }
        let ret: u32 = match nr {
            1 => return Outcome::ExitThread(a0),  // exit (thread)
            248 => return Outcome::ExitGroup(a0), // exit_group
            2 | 190 => return Outcome::Fork,      // fork / vfork
            120 => {
                // clone(flags, stack, ptid, tls, ctid) [ARM order]
                return Outcome::Clone {
                    flags: a0,
                    stack: a1,
                    ptid: a2,
                    tls: a3,
                    ctid: a4,
                };
            }
            173 | 119 => return Outcome::SigReturn, // rt_sigreturn / sigreturn
            37 => {
                // kill(pid, sig): pid > 0 names a thread group,
                // 0 our own group, -1 also our own group (no
                // broadcast in a single-user world), < -1 the
                // group |pid|.
                let tgid = if a0 == 0 || a0 == u32::MAX {
                    self.tgid
                } else if (a0 as i32) < -1 {
                    (-(a0 as i32)) as u32
                } else {
                    a0
                };
                return Outcome::SendSignal {
                    tgid,
                    tid: None,
                    sig: a1,
                };
            }
            177 => {
                // rt_sigtimedwait(set, info, timeout, size):
                // consume a pending signal from the wait set
                // (this thread's own pending word, or the
                // group's shared one). GB Dalvik's Signal
                // Catcher thread lives here waiting for
                // SIGQUIT/SIGUSR1; on ENOSYS it read an
                // uninitialized signal number and "reacted" to
                // garbage forever. Nothing pending parks the
                // thread via the re-issue mechanism; a zero
                // timeout polls and fails with EAGAIN.
                if a3 != 8 {
                    return done(cpu, err(EINVAL));
                }
                let set = mem.read_u32(a0) as u64
                    | ((mem.read_u32(a0 + 4) as u64) << 32);
                let avail = (self.pending
                    | self.sighand.borrow().group_pending)
                    & set;
                if avail != 0 {
                    let sig = avail.trailing_zeros() + 1;
                    let bit = 1u64 << (sig - 1);
                    if self.pending & bit != 0 {
                        self.pending &= !bit;
                    } else {
                        self.sighand.borrow_mut().group_pending &= !bit;
                    }
                    if a1 != 0 {
                        // siginfo_t: signo at +0, errno at +4,
                        // code at +8 (SI_USER = -1 for kill()).
                        mem.write_slice(a1, &[0u8; 32]);
                        put32(mem, a1, sig);
                        put32(mem, a1 + 8, (-1i32) as u32);
                    }
                    return done(cpu, sig);
                }
                if a2 != 0 && mem.read_u32(a2) == 0 && mem.read_u32(a2 + 4) == 0 {
                    return done(cpu, err(EAGAIN));
                }
                return Outcome::WouldBlock;
            }
            130 => {
                // tkill(tid, sig)
                return Outcome::SendSignal {
                    tgid: 0,
                    tid: Some(a0),
                    sig: a1,
                };
            }
            268 => {
                // tgkill(tgid, tid, sig)
                return Outcome::SendSignal {
                    tgid: a0,
                    tid: Some(a1),
                    sig: a2,
                };
            }
            240 => {
                // futex: WAIT/WAIT_BITSET block via the
                // scheduler's re-issue mechanism when the value
                // matches (waiters re-check on every re-issue, so
                // WAKE can honestly report 0: nobody is woken by
                // us, everybody re-checks). A mismatched value is
                // -EAGAIN, exactly what the guest's loop expects.
                // The timeout pointer is ignored for now (an
                // accepted approximation: timed futex waits can
                // over-sleep until the value changes).
                let op = a1 & 0x7F;
                if op == 0 || op == 9 {
                    if (a0 as usize) + 4 <= mem.len() {
                        let cur = mem.read_u32(a0);
                        if cur != a2 {
                            return done(cpu, err(11)); // EAGAIN
                        }
                        return Outcome::WouldBlock;
                    }
                    return done(cpu, err(EFAULT));
                }
                return done(cpu, 0);
            }
            11 => {
                // execve(path, argv, envp)
                let path = self.fs.resolve(&read_guest_str(mem, a0));
                let argv = read_str_array(mem, a1);
                let envp = read_str_array(mem, a2);
                return Outcome::Exec { path, argv, envp };
            }
            114 => {
                // wait4(pid, status_ptr, options, rusage)
                return Outcome::Wait4 {
                    pid: a0 as i32,
                    status_ptr: a1,
                    options: a2,
                };
            }
            3 => {
                // read(fd, buf, count)
                // Pipe pre-check: an empty pipe with a live writer
                // blocks (WouldBlock); with no writer it is EOF.
                if let Some(fd) = self.fs.fds.get(&(a0 as i32)) {
                    if let crate::fs::FdKind::Pipe(end) = &fd.kind {
                        if !end.write && end.queued() == 0 {
                            if end.writers() > 0 {
                                if fd.nonblock() {
                                    return done(cpu, err(EAGAIN));
                                }
                                return Outcome::WouldBlock;
                            }
                            return done(cpu, 0);
                        }
                    }
                    if let crate::fs::FdKind::UnixStream { rx, .. } = &fd.kind {
                        if rx.queued() == 0 {
                            if rx.writers() > 0 {
                                if fd.nonblock() {
                                    return done(cpu, err(EAGAIN));
                                }
                                return Outcome::WouldBlock;
                            }
                            return done(cpu, 0); // peer closed: EOF
                        }
                    }
                }
                let fd = match self.fs.fds.get_mut(&(a0 as i32)) {
                    Some(f) => f,
                    None => return done(cpu, err(EBADF)),
                };
                if matches!(fd.kind, FdKind::Dir(_)) {
                    return done(cpu, err(EISDIR));
                }
                let (buf, count) = (a1 as usize, a2 as usize);
                if buf + count > mem.len() {
                    return done(cpu, err(EFAULT));
                }
                let mut tmp = vec![0u8; count];
                match fd.read(&mut tmp) {
                    Ok(n) => {
                        mem.write_slice(buf as u32, &tmp[..n]);
                        n as u32
                    }
                    Err(e) => io_err(&e),
                }
            }
            4 => {
                // write(fd, buf, count)
                // Pipe pre-check: a full pipe buffer blocks.
                if let Some(fd) = self.fs.fds.get(&(a0 as i32)) {
                    if let crate::fs::FdKind::Pipe(end) = &fd.kind {
                        if end.write && end.queued() >= 65_536 && end.readers() > 0 {
                            if fd.nonblock() {
                                return done(cpu, err(EAGAIN));
                            }
                            return Outcome::WouldBlock;
                        }
                    }
                    if let crate::fs::FdKind::UnixStream { tx, .. } = &fd.kind {
                        if tx.queued() >= 65_536 && tx.readers() > 0 {
                            if fd.nonblock() {
                                return done(cpu, err(EAGAIN));
                            }
                            return Outcome::WouldBlock;
                        }
                    }
                }
                let (buf, count) = (a1 as usize, a2 as usize);
                if buf + count > mem.len() {
                    return done(cpu, err(EFAULT));
                }
                let data = { let mut v = vec![0u8; count]; mem.read_slice(buf as u32, &mut v); v };
                match self.fs.fds.get_mut(&(a0 as i32)) {
                    Some(fd) => match fd.write(&data) {
                        Ok(n) => n as u32,
                        Err(e) => io_err(&e),
                    },
                    None => err(EBADF),
                }
            }
            281 => {
                // socket(domain, type, protocol): AF_UNIX stream
                // only for now (init's property/control sockets;
                // other domains fail with EAFNOSUPPORT).
                if a0 == 1 && a1 & 0xF == 1 {
                    let fd = Fd::new(FdKind::UnixSocket);
                    self.fs.alloc_fd(fd) as u32
                } else {
                    err(97) // EAFNOSUPPORT
                }
            }
            282 => {
                // bind(fd, sockaddr_un, addrlen)
                let path = match read_sockaddr_un(mem, a1, a2) {
                    Some(p) => self.fs.resolve(&p),
                    None => return done(cpu, err(EINVAL)),
                };
                match self.fs.fds.get(&(a0 as i32)) {
                    Some(f) if matches!(f.kind, FdKind::UnixSocket) => {}
                    Some(_) => return done(cpu, err(EINVAL)),
                    None => return done(cpu, err(EBADF)),
                }
                let pending = std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::VecDeque::new(),
                ));
                {
                    let mut core = self.unix.borrow_mut();
                    if core.listeners.contains_key(&path) {
                        return done(cpu, err(98)); // EADDRINUSE
                    }
                    core.listeners.insert(path.clone(), pending.clone());
                }
                // A placeholder in the host tree so path-based
                // ops (chmod/stat) see the socket like a real
                // bound /dev/socket/* node.
                let host = self.fs.host_path(&path);
                if let Some(parent) = host.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::File::create(&host);
                if let Some(f) = self.fs.fds.get_mut(&(a0 as i32)) {
                    f.kind = FdKind::UnixListener { path, pending };
                }
                0
            }
            284 => {
                // listen(fd, backlog): bind() already produced
                // the listener state; just validate.
                match self.fs.fds.get(&(a0 as i32)) {
                    Some(f) if matches!(f.kind, FdKind::UnixListener { .. }) => 0,
                    Some(_) => err(EINVAL),
                    None => err(EBADF),
                }
            }
            285 => {
                // accept(fd, ...): pop a pending connection, or
                // park until one arrives (pipe-style WouldBlock).
                let pending = match self.fs.fds.get(&(a0 as i32)) {
                    Some(f) => match &f.kind {
                        FdKind::UnixListener { pending, .. } => {
                            std::rc::Rc::clone(pending)
                        }
                        _ => return done(cpu, err(EINVAL)),
                    },
                    None => return done(cpu, err(EBADF)),
                };
                let popped = pending.borrow_mut().pop_front();
                match popped {
                    Some((rx, tx)) => {
                        let fd = Fd::new(FdKind::UnixStream { rx, tx });
                        self.fs.alloc_fd(fd) as u32
                    }
                    None => {
                        if self
                            .fs
                            .fds
                            .get(&(a0 as i32))
                            .map(|f| f.nonblock())
                            .unwrap_or(false)
                        {
                            err(EAGAIN)
                        } else {
                            return Outcome::WouldBlock;
                        }
                    }
                }
            }
            283 => {
                // connect(fd, sockaddr_un, addrlen)
                let path = match read_sockaddr_un(mem, a1, a2) {
                    Some(p) => self.fs.resolve(&p),
                    None => return done(cpu, err(EINVAL)),
                };
                let pending = {
                    let core = self.unix.borrow();
                    match core.listeners.get(&path) {
                        Some(q) => q.clone(),
                        None => return done(cpu, err(111)), // ECONNREFUSED
                    }
                };
                let (client, server) = crate::fs::unix_stream_pair();
                let (rx, tx) = match server {
                    FdKind::UnixStream { rx, tx } => (rx, tx),
                    _ => unreachable!(),
                };
                pending.borrow_mut().push_back((rx, tx));
                match self.fs.fds.get_mut(&(a0 as i32)) {
                    Some(f) if matches!(f.kind, FdKind::UnixSocket) => {
                        f.kind = client;
                        0
                    }
                    _ => err(EBADF),
                }
            }
            288 => {
                // socketpair(domain, type, protocol, sv[2])
                if a0 != 1 || a1 & 0xF != 1 || a3 == 0 {
                    return done(cpu, err(EINVAL));
                }
                let (end_a, end_b) = crate::fs::unix_stream_pair();
                let fd_a = self.fs.alloc_fd(Fd::new(end_a));
                let fd_b = self.fs.alloc_fd(Fd::new(end_b));
                put32(mem, a3, fd_a as u32);
                put32(mem, a3 + 4, fd_b as u32);
                0
            }
            5 => {
                // open(path, flags, mode): flags is a1. (This
                // arm long passed a2 -- the mode -- as flags;
                // most opens survived because mode 0666 happens
                // to contain the O_CREAT bit and existing files
                // ignore access bits, but any O_CREAT open with
                // mode 0600 -- GB init's /dev/__properties__ --
                // silently failed with ENOENT.)
                let p = read_guest_str(mem, a0);
                self.do_open(None, &p, a1)
            }
            6 => {
                // close
                if self.fs.fds.remove(&(a0 as i32)).is_some() {
                    0
                } else {
                    err(EBADF)
                }
            }
            10 => {
                let p = read_guest_str(mem, a0);
                let host = self.fs.host_path(&self.fs.resolve(&p));
                match std::fs::remove_file(&host) {
                    Ok(()) => 0,
                    Err(e) => io_err(&e),
                }
            }
            12 => {
                let p = read_guest_str(mem, a0);
                let abs = self.fs.resolve(&p);
                let host = self.fs.host_path(&abs);
                match std::fs::metadata(&host) {
                    Ok(m) if m.is_dir() => {
                        self.fs.cwd = abs;
                        0
                    }
                    Ok(_) => err(ENOTDIR),
                    Err(e) => io_err(&e),
                }
            }
            13 => {
                // time(tloc)
                let (secs, _) = now_unix();
                if a0 != 0 {
                    put32(mem, a0, secs as u32);
                }
                secs as u32
            }
            19 => {
                // lseek(fd, off32, whence)
                let pos = match a2 {
                    0 => SeekFrom::Start(a1 as i32 as u64),
                    1 => SeekFrom::Current(a1 as i32 as i64),
                    _ => SeekFrom::End(a1 as i32 as i64),
                };
                match self.fs.fds.get_mut(&(a0 as i32)) {
                    Some(fd) => match fd.seek(pos) {
                        Ok(p) => p as u32,
                        Err(e) => io_err(&e),
                    },
                    None => err(EBADF),
                }
            }
            20 => self.tgid,    // getpid
            // id numbers verified against the NDK unistd-eabi.h
            24 | 199 => 1000,   // getuid / getuid32
            47 | 200 => 1000,   // getgid / getgid32
            49 | 201 => 1000,   // geteuid / geteuid32
            50 | 202 => 1000,   // getegid / getegid32
            213 | 214 => 0,     // setuid32 / setgid32: pretend success
            // setreuid32 / setregid32 / setresuid32 / setresgid32
            // (numbers from the NDK unistd-eabi.h): zygote drops
            // privileges with these before preloading classes;
            // PaxCore's credential world is a single uid, so
            // accept and succeed like the pair above.
            203 | 204 | 208 | 210 => 0,
            // getpriority (96): kernel-style scale where 20 is
            // nice 0; bionic's wrapper maps it back. Zygote's
            // preload path queries it and carries on either way.
            96 => 20,
            // madvise (220): pure performance advice; accepting
            // it changes no semantics.
            220 => 0,
            64 => self.ppid,    // getppid
            224 => self.pid,    // gettid (no threads yet: tid == pid)
            _ => self.handle2(cpu, mem, nr),
        };
        cpu.r[0] = ret;
        if std::env::var_os("PAXCORE_TRACE").is_some()
            || std::env::var_os("PAXCORE_SYSCALLS").is_some()
        {
            eprintln!("[syscall] nr={nr} -> 0x{ret:08x}");
        }
        Outcome::Continue
    }
}

fn done(cpu: &mut Cpu, v: u32) -> Outcome {
    cpu.r[0] = v;
    Outcome::Continue
}

/// Kernel sigaction (ARM) serialization: handler, flags,
/// restorer, mask as two u32s -- 20 bytes at `addr`.
/// Parse a sockaddr_un from guest memory: family u16 at +0
/// (must be AF_UNIX=1), NUL-terminated path at +2 bounded by
/// addrlen. Returns the guest path, or None for abstract
/// sockets and malformed addresses (unsupported here).
fn read_sockaddr_un(mem: &Mem, addr: u32, addrlen: u32) -> Option<String> {
    let a = addr as usize;
    if a + 2 > mem.len() || mem.read_u16(addr) != 1 {
        return None;
    }
    let max = (addrlen as usize).min(108);
    let mut bytes = Vec::new();
    for i in 0..max {
        let b = mem.byte((a + 2 + i) as u32);
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    if bytes.is_empty() {
        return None; // abstract-namespace socket: unsupported
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_sigaction(mem: &Mem, addr: u32) -> SigAction {
    let a = addr as usize;
    let w = |o: usize| mem.read_u32((a + o) as u32);
    SigAction {
        handler: w(0),
        flags: w(4),
        restorer: w(8),
        mask: (w(12) as u64) | ((w(16) as u64) << 32),
    }
}

fn write_sigaction(mem: &mut Mem, addr: u32, act: &SigAction) {
    put32(mem, addr, act.handler);
    put32(mem, addr + 4, act.flags);
    put32(mem, addr + 8, act.restorer);
    put64(mem, addr + 12, act.mask);
}

/// Read a guest NULL-terminated array of string pointers (argv /
/// envp for execve). Defensive: a null array pointer yields an
/// empty vec, unreadable entries end the list.
fn read_str_array(mem: &Mem, ptr: u32) -> Vec<String> {
    let mut out = Vec::new();
    if ptr == 0 {
        return out;
    }
    for i in 0..256usize {
        let a = ptr as usize + i * 4;
        if a + 4 > mem.len() {
            break;
        }
        let p = mem.read_u32(a as u32);
        if p == 0 {
            break;
        }
        out.push(read_guest_str(mem, p));
    }
    out
}

impl Syscalls {
    fn handle2(&mut self, cpu: &mut Cpu, mem: &mut Mem, nr: u32) -> u32 {
        let (a0, a1, a2, a3, a4) = (cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3], cpu.r[4]);
        match nr {
            42 | 331 => {
                // pipe / pipe2(fds, flags): flags ignored
                // (O_CLOEXEC is not tracked yet).
                let (rd_end, wr_end) = crate::fs::PipeEnd::new_pair();
                let rfd = self.fs.alloc_fd(crate::fs::Fd::new(crate::fs::FdKind::Pipe(rd_end)));
                let wfd = self.fs.alloc_fd(crate::fs::Fd::new(crate::fs::FdKind::Pipe(wr_end)));
                put32(mem, a0, rfd as u32);
                put32(mem, a0.wrapping_add(4), wfd as u32);
                0
            }
            33 => {
                // access(path, mode)
                let p = read_guest_str(mem, a0);
                let host = self.fs.host_path(&self.fs.resolve(&p));
                if host.exists() { 0 } else { err(ENOENT) }
            }
            39 => {
                let p = read_guest_str(mem, a0);
                let host = self.fs.host_path(&self.fs.resolve(&p));
                match std::fs::create_dir(&host) {
                    Ok(()) => 0,
                    Err(e) => io_err(&e),
                }
            }
            14 => {
                // mknod(path, mode, dev): character/block nodes
                // go into the fs device registry (open serves
                // them from the core); anything else becomes an
                // empty host file, like a real mknod of a
                // regular file.
                let p = read_guest_str(mem, a0);
                let abs = self.fs.resolve(&p);
                if self.fs.devices.contains_key(&abs) {
                    err(EEXIST)
                } else if a1 & 0o170000 == 0o020000 || a1 & 0o170000 == 0o060000 {
                    self.fs.devices.insert(abs, (a1, a2));
                    0
                } else {
                    let host = self.fs.host_path(&abs);
                    match std::fs::File::create_new(&host) {
                        Ok(_) => 0,
                        Err(e) => io_err(&e),
                    }
                }
            }
            21 => {
                // mount(source, target, fstype, flags, data):
                // the guest fs is a single host-backed tree, so
                // mounts are accepted and recorded nowhere --
                // the target directories already serve. (GB
                // init mounts tmpfs/devpts/proc/sysfs here and
                // only needs the calls to not fail.)
                0
            }
            60 => {
                // umask(new): returns the previous mask.
                let old = self.umask;
                self.umask = a0 & 0o777;
                old
            }
            172 => {
                // prctl(option, ...): thread names (PR_SET_NAME
                // =15 / PR_GET_NAME=16) are the only options GB
                // userland exercises at this stage (bionic's
                // pthread_setname_np via Dalvik thread init);
                // accept everything, report an empty name.
                if a0 == 16 && a1 != 0 {
                    mem.write_slice(a1, &[0u8; 16]);
                }
                0
            }
            41 => {
                // dup(fd)
                match self.clone_fd(a0 as i32) {
                    Some(fd) => self.fs.alloc_fd(fd) as u32,
                    None => err(EBADF),
                }
            }
            45 => {
                // brk(addr): the break lives in the shared
                // AddrSpace; every thread of the group must
                // observe (and move) the same value.
                let mut asp = self.asp.borrow_mut();
                if a0 != 0 && a0 >= (asp.brk & !0xFFF) && a0 < MAP_BASE {
                    if a0 > asp.brk {
                        let (s, e) = (asp.brk as usize, a0 as usize);
                        if e <= mem.len() {
                            mem.zero_range(s as u32, e - s);
                        }
                    }
                    asp.brk = a0;
                }
                asp.brk
            }
            54 => {
                // ioctl(fd, request, arg)
                if let Some(fd) = self.fs.fds.get_mut(&(a0 as i32)) {
                    if let FdKind::Ashmem { size, backing } = &mut fd.kind {
                        // Numbers from the guest's own
                        // linux/ashmem.h (_IOC with type 0x77).
                        return match a1 {
                            0x41007701 => 0, // SET_NAME (accepted)
                            0x81007702 => {
                                // GET_NAME
                                let mut buf = [0u8; 256];
                                buf[..10].copy_from_slice(b"dev/ashmem");
                                mem.write_slice(a2, &buf);
                                0
                            }
                            0x40047703 => {
                                // SET_SIZE
                                *size = a2 as usize;
                                backing.borrow_mut().resize(*size, 0);
                                0
                            }
                            0x00007704 => *size as u32, // GET_SIZE
                            0x40047705 => 0,            // SET_PROT_MASK
                            0x00007706 => 0x7,          // GET_PROT_MASK: RWX
                            0x40087707 => 0, // PIN: ASHMEM_NOT_PURGED
                            0x40087708 => 0, // UNPIN: ASHMEM_NOT_PURGED
                            0x00007709 => 1, // GET_PIN_STATUS: pinned
                            0x0000770A => 0, // PURGE_ALL_CACHES
                            _ => err(ENOTTY),
                        };
                    }
                }
                match a1 {
                    0x5401 => err(ENOTTY), // TCGETS: not a tty
                    0x5413 => {
                        // TIOCGWINSZ: report 24x80
                        if (a2 as usize) + 8 <= mem.len() {
                            put(mem, a2, &24u16.to_le_bytes());
                            put(mem, a2 + 2, &80u16.to_le_bytes());
                            put(mem, a2 + 4, &0u16.to_le_bytes());
                            put(mem, a2 + 6, &0u16.to_le_bytes());
                            0
                        } else {
                            err(EFAULT)
                        }
                    }
                    0x541B => {
                        // FIONREAD: 0 bytes waiting
                        if (a2 as usize) + 4 <= mem.len() {
                            put32(mem, a2, 0);
                            0
                        } else {
                            err(EFAULT)
                        }
                    }
                    _ => err(ENOTTY),
                }
            }
            143 => {
                // flock(fd, op): LOCK_SH=1, LOCK_EX=2, LOCK_UN=8,
                // LOCK_NB=4. Locks are keyed by the fd's guest
                // path in a per-process table. GB libdvm locks
                // the dex cache file before optimizing; ENOSYS
                // here made every jar load fail with "Can't lock
                // dex cache". Blocking requests are granted when
                // free (the core is cooperatively scheduled, so
                // no holder can release while we would wait);
                // a contended NB request fails with EWOULDBLOCK.
                let fd = a0 as i32;
                let path = match self.fs.fds.get(&fd) {
                    Some(f) => f.path.clone().unwrap_or_default(),
                    None => return err(EBADF),
                };
                if path.is_empty() {
                    return 0; // pipes/devices: nothing to lock
                }
                let op = a1;
                if op & 8 != 0 {
                    // LOCK_UN
                    if matches!(self.flocks.get(&path), Some(&(h, _)) if h == fd) {
                        self.flocks.remove(&path);
                    }
                    0
                } else if op & 3 == 1 || op & 3 == 2 {
                    let excl = op & 3 == 2;
                    match self.flocks.get(&path) {
                        Some(&(h, hex)) if h != fd && (excl || hex) => {
                            err(EAGAIN) // EWOULDBLOCK == EAGAIN
                        }
                        _ => {
                            self.flocks.insert(path, (fd, excl));
                            0
                        }
                    }
                } else {
                    err(EINVAL)
                }
            }
            55 | 221 => {
                // fcntl / fcntl64
                if !self.fs.fds.contains_key(&(a0 as i32)) {
                    return err(EBADF);
                }
                match a1 {
                    0 => {
                        // F_DUPFD: arg is the minimum fd
                        match self.clone_fd(a0 as i32) {
                            Some(fd) => {
                                let mut n = a2 as i32;
                                while self.fs.fds.contains_key(&n) {
                                    n += 1;
                                }
                                self.fs.fds.insert(n, fd);
                                n as u32
                            }
                            None => err(EBADF),
                        }
                    }
                    1 => {
                        // F_GETFD
                        self.fs.fds[&(a0 as i32)].cloexec as u32
                    }
                    2 => {
                        // F_SETFD
                        if let Some(f) = self.fs.fds.get_mut(&(a0 as i32)) {
                            f.cloexec = a2 & 1 != 0;
                        }
                        0
                    }
                    3 => {
                        // F_GETFL
                        self.fs.fds[&(a0 as i32)].status_flags
                    }
                    4 => {
                        // F_SETFL: O_NONBLOCK lives here; GB
                        // init's signal drain depends on it
                        // (a blocking read would park forever).
                        if let Some(f) = self.fs.fds.get_mut(&(a0 as i32)) {
                            f.status_flags = a2;
                        }
                        0
                    }
                    _ => 0,
                }
            }
            63 => {
                // dup2(old, new)
                if a0 == a1 {
                    return a1;
                }
                match self.clone_fd(a0 as i32) {
                    Some(fd) => {
                        self.fs.fds.insert(a1 as i32, fd);
                        a1
                    }
                    None => err(EBADF),
                }
            }
            _ => self.handle3(cpu, mem, nr),
        }
    }

    /// ioctl() on a /dev/binder fd.
    fn binder_ioctl(&mut self, cpu: &mut Cpu, mem: &mut Mem, req: u32, arg: u32) -> Outcome {
        use crate::binder as B;
        let pid = self.tgid;
        match req {
            B::BINDER_VERSION => {
                put32(mem, arg, 7);
                done(cpu, 0)
            }
            B::BINDER_SET_MAX_THREADS | B::BINDER_SET_IDLE_TIMEOUT | B::BINDER_SET_IDLE_PRIORITY => {
                done(cpu, 0)
            }
            B::BINDER_SET_CONTEXT_MGR => {
                if self.binder.borrow_mut().set_context_mgr(pid) {
                    done(cpu, 0)
                } else {
                    done(cpu, err(16)) // EBUSY: already registered
                }
            }
            B::BINDER_THREAD_EXIT => {
                self.binder.borrow_mut().proc(pid).looper = false;
                done(cpu, 0)
            }
            B::BINDER_WRITE_READ => self.binder_write_read(cpu, mem, arg),
            _ => done(cpu, err(ENOTTY)),
        }
    }

    /// BINDER_WRITE_READ. The guest struct (24 bytes):
    /// +0 write_size, +4 write_consumed, +8 write_buffer,
    /// +12 read_size, +16 read_consumed, +20 read_buffer.
    /// The write side is processed first (resuming from the
    /// incoming write_consumed, which is how a parked call
    /// re-issued by the scheduler avoids re-sending commands);
    /// then the read side drains whatever the core has queued.
    /// With an empty inbox the call parks as Outcome::BinderWait.
    fn binder_write_read(&mut self, cpu: &mut Cpu, mem: &mut Mem, bwr: u32) -> Outcome {
        let pid = self.tgid;
        let ws = mem.read_u32(bwr);
        let wc0 = mem.read_u32(bwr + 4);
        let wb = mem.read_u32(bwr + 8);
        let rs = mem.read_u32(bwr + 12);
        let rb = mem.read_u32(bwr + 20);
        if ws > wc0 {
            let n = (ws - wc0) as usize;
            let mut bytes = vec![0u8; n];
            mem.read_slice(wb + wc0, &mut bytes);
            let consumed = {
                let mref = &*mem;
                let mut fetch = |td: &[u8]| -> (Vec<u8>, Vec<u32>) {
                    let dptr = u32::from_le_bytes([td[32], td[33], td[34], td[35]]);
                    let optr = u32::from_le_bytes([td[36], td[37], td[38], td[39]]);
                    let dsz = u32::from_le_bytes([td[24], td[25], td[26], td[27]]) as usize;
                    let osz = u32::from_le_bytes([td[28], td[29], td[30], td[31]]) as usize;
                    let mut data = vec![0u8; dsz];
                    if dsz > 0 {
                        mref.read_slice(dptr, &mut data);
                    }
                    let mut offs = Vec::with_capacity(osz / 4);
                    for k in 0..osz / 4 {
                        offs.push(mref.read_u32(optr + 4 * k as u32));
                    }
                    (data, offs)
                };
                self.binder
                    .borrow_mut()
                    .process_write(pid, &bytes, &mut fetch)
            };
            put32(mem, bwr + 4, wc0 + consumed as u32);
        }
        if rs == 0 {
            return done(cpu, 0);
        }
        let drained = self.binder.borrow_mut().drain(pid, mem, rb, rs);
        if drained > 0 {
            put32(mem, bwr + 16, drained);
            return done(cpu, 0);
        }
        // Nothing to deliver: park until the core has inbox work.
        put32(mem, bwr + 16, 0);
        Outcome::BinderWait
    }

    fn clone_fd(&self, n: i32) -> Option<Fd> {
        let src = self.fs.fds.get(&n)?;
        let kind = match &src.kind {
            FdKind::StdIn => FdKind::StdIn,
            FdKind::StdOut => FdKind::StdOut,
            FdKind::StdErr => FdKind::StdErr,
            FdKind::Dir(p) => FdKind::Dir(p.clone()),
            FdKind::Pipe(e) => FdKind::Pipe(e.clone()),
            FdKind::Binder => FdKind::Binder,
            FdKind::CharDev { major, minor } => FdKind::CharDev {
                major: *major,
                minor: *minor,
            },
            FdKind::UnixStream { rx, tx } => FdKind::UnixStream {
                rx: rx.clone(),
                tx: tx.clone(),
            },
            FdKind::UnixSocket => FdKind::UnixSocket,
            FdKind::UnixListener { path, pending } => FdKind::UnixListener {
                path: path.clone(),
                pending: pending.clone(),
            },
            FdKind::File(f) => match f.try_clone() {
                Ok(c) => FdKind::File(c),
                Err(_) => return None,
            },
            FdKind::Ashmem { size, backing } => FdKind::Ashmem {
                size: *size,
                backing: backing.clone(),
            },
        };
        let mut out = Fd::new(kind);
        out.status_flags = src.status_flags;
        // dup()/dup2()/F_DUPFD clear FD_CLOEXEC on the new fd
        // (GB init relies on this: it dups the property
        // workspace fd into each service it spawns).
        out.cloexec = false;
        out.path = src.path.clone();
        Some(out)
    }
}

impl Syscalls {
    #[allow(clippy::too_many_arguments)]
    fn handle3(&mut self, cpu: &mut Cpu, mem: &mut Mem, nr: u32) -> u32 {
        let (a0, a1, a2, a3, a4) = (cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3], cpu.r[4]);
        match nr {
            78 => {
                // gettimeofday(tv, tz)
                let (secs, nanos) = now_unix();
                if a0 != 0 {
                    put32(mem, a0, secs as u32);
                    put32(mem, a0 + 4, nanos / 1000);
                }
                0
            }
            85 => {
                // readlink(path, buf, bufsize)
                let p = read_guest_str(mem, a0);
                let host = self.fs.host_path(&self.fs.resolve(&p));
                match std::fs::read_link(&host) {
                    Ok(target) => {
                        let s = target.to_string_lossy();
                        let n = s.len().min(a2 as usize);
                        if (a1 as usize) + n > mem.len() {
                            return err(EFAULT);
                        }
                        put(mem, a1, &s.as_bytes()[..n]);
                        n as u32
                    }
                    Err(e) => io_err(&e),
                }
            }
            122 => {
                // uname(utsname): 6 fields of 65 bytes
                if (a0 as usize) + 390 > mem.len() {
                    return err(EFAULT);
                }
                let fields = ["Linux", "paxcore", "2.6.29", "paxcore-1", "armv7l", ""];
                mem.zero_range(a0, 65 * 6);
                for (i, f) in fields.iter().enumerate() {
                    let base = a0 as usize + i * 65;
                    mem.write_slice(base as u32, f.as_bytes());
                }
                0
            }
            125 => 0, // mprotect: permissions not enforced in the flat model
            140 => {
                // _llseek(fd, hi, lo, result*, whence)
                let off = ((a1 as i64) << 32) | (a2 as u64 as i64);
                let pos = match a4 {
                    0 => SeekFrom::Start(off as u64),
                    1 => SeekFrom::Current(off),
                    _ => SeekFrom::End(off),
                };
                match self.fs.fds.get_mut(&(a0 as i32)) {
                    Some(fd) => match fd.seek(pos) {
                        Ok(p) => {
                            put64(mem, a3, p);
                            0
                        }
                        Err(e) => io_err(&e),
                    },
                    None => err(EBADF),
                }
            }
            145 | 146 => {
                // readv / writev: scatter/gather over the fd table.
                let is_write = nr == 146;
                let iov = a1 as usize;
                let iovcnt = a2 as i32;
                if iovcnt < 0 || iov + (iovcnt as usize) * 8 > mem.len() {
                    return err(EFAULT);
                }
                let mut total = 0usize;
                for i in 0..iovcnt as usize {
                    let base = mem.read_u32((iov + i * 8) as u32) as usize;
                    let len = mem.read_u32((iov + i * 8 + 4) as u32) as usize;
                    if base + len > mem.len() {
                        return err(EFAULT);
                    }
                    if is_write {
                        let data = { let mut v = vec![0u8; len]; mem.read_slice(base as u32, &mut v); v };
                        match self.fs.fds.get_mut(&(a0 as i32)) {
                            Some(fd) => match fd.write(&data) {
                                Ok(n) => total += n,
                                Err(e) => {
                                    return if total > 0 { total as u32 } else { io_err(&e) }
                                }
                            },
                            None => return err(EBADF),
                        }
                    } else {
                        match self.fs.fds.get_mut(&(a0 as i32)) {
                            Some(fd) => {
                                let mut tmp = vec![0u8; len];
                                match fd.read(&mut tmp) {
                                    Ok(n) => {
                                        mem.write_slice(base as u32, &tmp[..n]);
                                        total += n;
                                        if n < len {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        return if total > 0 {
                                            total as u32
                                        } else {
                                            io_err(&e)
                                        }
                                    }
                                }
                            }
                            None => return err(EBADF),
                        }
                    }
                }
                total as u32
            }
            142 => {
                // _newselect: report every requested fd ready
                let mut count = 0u32;
                for set_ptr in [a1, a2, a3] {
                    if set_ptr != 0 && (set_ptr as usize) + 4 <= mem.len() {
                        let w = u32::from_le_bytes(
                            mem.read_u32(set_ptr).to_le_bytes()
                                .as_slice()
                                .try_into()
                                .unwrap(),
                        );
                        count += w.count_ones();
                    }
                }
                count
            }
            162 => 0, // nanosleep: no wall-clock delay in M1
            168 => {
                // poll(fds, nfds, timeout): honest per-kind
                // readiness (the old "everything is ready" lie
                // made init's event loop spin on empty sockets).
                // The timeout is not honoured; callers re-check
                // conditions, and WouldBlock parks real waits.
                let base = a0 as usize;
                let nfds = a1 as usize;
                if base + nfds * 8 > mem.len() {
                    return err(EFAULT);
                }
                let mut ready = 0u32;
                for i in 0..nfds {
                    let ent = base + i * 8;
                    let fdno = mem.read_u32(ent as u32) as i32;
                    let events = mem.read_u16((ent + 4) as u32);
                    let mut rev: u16 = 0;
                    match self.fs.fds.get(&fdno).map(|f| &f.kind) {
                        None => rev = 0x20, // POLLNVAL
                        Some(FdKind::StdIn) => rev = 0x1,
                        Some(FdKind::StdOut) | Some(FdKind::StdErr) => rev = 0x4,
                        Some(FdKind::File(_)) | Some(FdKind::Dir(_)) => rev = 0x5,
                        Some(FdKind::CharDev { .. }) => rev = 0x5,
                        Some(FdKind::Ashmem { .. }) => rev = 0x5,
                        Some(FdKind::Binder) => {
                            if self.binder.borrow().has_inbox(self.tgid) {
                                rev = 0x1;
                            }
                        }
                        Some(FdKind::Pipe(end)) => {
                            if end.write {
                                if end.readers() == 0 {
                                    rev = 0x8; // POLLERR
                                } else if end.queued() < 65_536 {
                                    rev = 0x4;
                                }
                            } else if end.queued() > 0 {
                                rev = 0x1;
                            } else if end.writers() == 0 {
                                rev = 0x11; // POLLIN|POLLHUP (EOF)
                            }
                        }
                        Some(FdKind::UnixStream { rx, tx }) => {
                            if rx.queued() > 0 {
                                rev |= 0x1;
                            }
                            if rx.writers() == 0 {
                                rev |= 0x11; // readable EOF + HUP
                            }
                            if tx.readers() == 0 {
                                rev |= 0x8;
                            } else if tx.queued() < 65_536 {
                                rev |= 0x4;
                            }
                        }
                        Some(FdKind::UnixListener { pending, .. }) => {
                            if !pending.borrow().is_empty() {
                                rev = 0x1;
                            }
                        }
                        Some(FdKind::UnixSocket) => {}
                    }
                    rev &= events | 0x18; // events mask + ERR/HUP always
                    mem.write_u16((ent + 6) as u32, rev);
                    if rev != 0 {
                        ready += 1;
                    }
                }
                ready
            }
            174 => {
                // rt_sigaction(sig, act, oldact, size): kernel
                // sigaction layout on ARM is handler, flags,
                // restorer, mask[2] (20 bytes).
                let sig = a0 as usize;
                if sig == 0 || sig > 64 {
                    err(EINVAL)
                } else if a1 != 0 && (sig == 9 || sig == 19) {
                    err(EINVAL) // SIGKILL / SIGSTOP cannot be caught
                } else {
                    if a2 != 0 {
                        let old = self.sighand.borrow().actions[sig];
                        write_sigaction(mem, a2, &old);
                    }
                    if a1 != 0 {
                        let act = read_sigaction(mem, a1);
                        self.sighand.borrow_mut().actions[sig] = act;
                    }
                    0
                }
            }
            126 => {
                // sigprocmask (legacy): same mask state as the
                // rt_ form, but the set is one 32-bit word.
                // GB-era bionic calls this during app_process
                // startup and aborts on ENOSYS.
                if a2 != 0 {
                    put32(mem, a2, self.sig_mask as u32);
                }
                if a1 != 0 {
                    let v = mem.read_u32(a1) as u64;
                    match a0 {
                        0 => self.sig_mask |= v,  // SIG_BLOCK
                        1 => self.sig_mask &= !v, // SIG_UNBLOCK
                        _ => self.sig_mask = v,    // SIG_SETMASK
                    }
                }
                0
            }
            175 => {
                // rt_sigprocmask(how, set, oldset, size)
                if a2 != 0 {
                    put64(mem, a2, self.sig_mask);
                }
                if a1 != 0 {
                    let v = u64::from_le_bytes(
                        mem.read_u64(a1).to_le_bytes(),
                    );
                    // SIGKILL(9) and SIGSTOP(19) can never block.
                    let v = v & !(1u64 << 8) & !(1u64 << 18);
                    match a0 {
                        0 => self.sig_mask |= v,  // SIG_BLOCK
                        1 => self.sig_mask &= !v, // SIG_UNBLOCK
                        _ => self.sig_mask = v,    // SIG_SETMASK
                    }
                }
                0
            }
            256 => {
                // set_tid_address(tidptr)
                self.tid_addr = a0;
                self.pid
            }
            338 => 0,       // set_robust_list: accepted, no futex death
            // (futex 240 is intercepted in handle(): it can
            // return Outcome::WouldBlock, which this u32 chain
            // cannot express.)
            183 => {
                // getcwd(buf, size)
                let need = self.fs.cwd.len() + 1;
                if (a1 as usize) < need {
                    return err(ERANGE);
                }
                if (a0 as usize) + need > mem.len() {
                    return err(EFAULT);
                }
                put(mem, a0, self.fs.cwd.as_bytes());
                mem.set_byte(a0 + (need - 1) as u32, 0);
                need as u32
            }
            _ => self.handle4(cpu, mem, nr),
        }
    }
}

impl Syscalls {
    fn handle4(&mut self, cpu: &mut Cpu, mem: &mut Mem, nr: u32) -> u32 {
        let (a0, a1, a2, a3, a4, a5) = (
            cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3], cpu.r[4], cpu.r[5],
        );
        match nr {
            192 => {
                // mmap2(addr, len, prot, flags, fd, pgoffset).
                // A non-null addr is honored when the range is
                // free (Linux hint semantics); MAP_FIXED forces
                // it. Honoring hints is load-bearing for GB:
                // its libraries are prelinked and the linker
                // reserves each at its assigned address
                // (liblog.so at 0xafa00000) and aborts if the
                // mapping lands anywhere else.
                let len = (a1 + 0xFFF) & !0xFFF;
                if len == 0 {
                    return err(22); // EINVAL
                }
                let fixed = a3 & 0x10 != 0;
                let want = a0 & !0xFFF;
                let base = if fixed && want != 0 {
                    self.unmap_range(want, len);
                    mem.remove_shared(want, len);
                    want
                } else if want != 0 && self.range_free(want, len) {
                    want
                } else {
                    let mut b = self.asp.borrow().mmap_next;
                    while !self.range_free(b, len) {
                        match self
                            .asp
                            .borrow()
                            .maps
                            .iter()
                            .find(|&&(mb, ml)| {
                                let me = mb.wrapping_add(ml);
                                me > b && mb < b.wrapping_add(len)
                            })
                            .copied()
                        {
                            Some((mb, ml)) => {
                                b = (mb.wrapping_add(ml) + 0xFFF) & !0xFFF;
                            }
                            None => break,
                        }
                    }
                    self.asp.borrow_mut().mmap_next = b.wrapping_add(len);
                    b
                };
                self.asp.borrow_mut().maps.push((base, len));
                mem.zero_range(base, len as usize);
                let anon = a3 & 0x20 != 0 || a4 as i32 == -1;
                if a3 & 0x01 != 0 {
                    // MAP_SHARED: the range aliases a backing
                    // store shared by every process mapping the
                    // same area, instead of a private snapshot.
                    if anon {
                        let backing: SharedBytes =
                            std::rc::Rc::new(std::cell::RefCell::new(vec![0u8; len as usize]));
                        mem.add_shared(base, len, 0, backing);
                        return base;
                    }
                    if let Some(fd) = self.fs.fds.get(&(a4 as i32)) {
                        if let FdKind::Ashmem { backing, .. } = &fd.kind {
                            let backing = backing.clone();
                            let off = (a5 as usize) * 4096;
                            let mut b = backing.borrow_mut();
                            let need = off + a1 as usize;
                            if b.len() < need {
                                b.resize(need, 0);
                            }
                            drop(b);
                            mem.add_shared(base, len, off, backing);
                            return base;
                        }
                    }
                    let fpath = match self.fs.fds.get(&(a4 as i32)) {
                        Some(fd) if matches!(fd.kind, FdKind::File(_)) => fd.path.clone(),
                        _ => None,
                    };
                    if let Some(gpath) = fpath {
                        let host = self.fs.host_path(&gpath);
                        let key = host.to_string_lossy().into_owned();
                        let backing: SharedBytes = {
                            let mut areas = self.areas.borrow_mut();
                            areas
                                .entry(key)
                                .or_insert_with(|| {
                                    let data = std::fs::read(&host).unwrap_or_default();
                                    std::rc::Rc::new(std::cell::RefCell::new(data))
                                })
                                .clone()
                        };
                        let off = (a5 as usize) * 4096;
                        {
                            let mut b = backing.borrow_mut();
                            let need = off + a1 as usize;
                            if b.len() < need {
                                b.resize(need, 0);
                            }
                        }
                        mem.add_shared(base, len, off, backing);
                        return base;
                    }
                    // Shared on a non-file fd: fall through to
                    // the snapshot path (nothing to alias).
                }
                if !anon {
                    if let Some(fd) = self.fs.fds.get_mut(&(a4 as i32)) {
                        if let FdKind::File(f) = &mut fd.kind {
                            let off = (a5 as u64) * 4096;
                            if f.seek(SeekFrom::Start(off)).is_ok() {
                                let want = a1 as usize;
                                let mut n = 0usize;
                                let mut tmpbuf = vec![0u8; want];
                                while n < want {
                                    match f.read(&mut tmpbuf[n..want]) {
                                        Ok(0) => break,
                                        Ok(k) => n += k,
                                        Err(_) => break,
                                    }
                                }
                                mem.write_slice(base, &tmpbuf[..n]);
                            }
                        }
                    } else {
                        return err(EBADF);
                    }
                }
                if let Some(fd) = self.fs.fds.get(&(a4 as i32)) {
                    if matches!(fd.kind, FdKind::Binder) {
                        // The binder receive arena: the driver
                        // writes transaction payloads here.
                        let pid = self.tgid;
                        self.binder.borrow_mut().set_arena(pid, base, len);
                    }
                }
                base
            }
            91 => {
                // munmap(addr, len): drop the interval and
                // clear the bytes so a later mapping never
                // observes stale contents.
                let len = (a1 + 0xFFF) & !0xFFF;
                let base = a0 & !0xFFF;
                if len == 0 {
                    return err(22); // EINVAL
                }
                self.unmap_range(base, len);
                // Drop shared windows FIRST: unmapping must
                // not zero the backing (other processes may
                // still have it mapped), only the private
                // bytes shadowed underneath.
                mem.remove_shared(base, len);
                mem.zero_range(base, len as usize);
                0
            }
            93 | 94 => {
                // ftruncate / ftruncate64(fd, len[, len_hi])
                let len = if nr == 93 {
                    a1 as u64
                } else {
                    (a1 as u64) | ((a2 as u64) << 32)
                };
                match self.fs.fds.get_mut(&(a0 as i32)).map(|f| &mut f.kind) {
                    Some(FdKind::File(f)) => match f.set_len(len) {
                        Ok(()) => 0,
                        Err(e) => io_err(&e),
                    },
                    Some(_) => err(EINVAL),
                    None => err(EBADF),
                }
            }
            144 => {
                // msync: shared backings are always current
                // in-core; there is nothing to flush.
                0
            }
            195 => {
                let p = read_guest_str(mem, a0);
                self.do_stat(mem, None, &p, a1, true)
            }
            196 => {
                let p = read_guest_str(mem, a0);
                self.do_stat(mem, None, &p, a1, false)
            }
            197 => self.do_stat(mem, Some(a0 as i32), "", a1, true),
            217 => self.do_getdents(mem, a0 as i32, a1, a2),
            67 => {
                // sigaction (legacy, non-RT): ARM nr 67 is the
                // old sigaction syscall -- an earlier arm here
                // mislabeled it readlink (that's nr 85, handled
                // above) and fed init EINVAL for its SIGCHLD
                // install. Legacy kernel layout: handler@0,
                // mask@4 (one word), flags@8, restorer@12.
                let sig = a0 as usize;
                if sig == 0 || sig > 64 {
                    err(EINVAL)
                } else if a1 != 0 && (sig == 9 || sig == 19) {
                    err(EINVAL)
                } else {
                    if a2 != 0 {
                        let old = self.sighand.borrow().actions[sig];
                        put32(mem, a2, old.handler);
                        put32(mem, a2 + 4, old.mask as u32);
                        put32(mem, a2 + 8, old.flags);
                        put32(mem, a2 + 12, old.restorer);
                    }
                    if a1 != 0 {
                        let act = SigAction {
                            handler: mem.read_u32(a1),
                            mask: mem.read_u32(a1 + 4) as u64,
                            flags: mem.read_u32(a1 + 8),
                            restorer: mem.read_u32(a1 + 12),
                        };
                        self.sighand.borrow_mut().actions[sig] = act;
                    }
                    0
                }
            }
            15 => {
                // chmod(path, mode)
                let p = read_guest_str(mem, a0);
                let abs = self.fs.resolve(&p);
                if self.fs.devices.contains_key(&abs) {
                    0 // device node: no host file to chmod
                } else {
                    let host = self.fs.host_path(&abs);
                    match std::fs::set_permissions(
                        &host,
                        std::os::unix::fs::PermissionsExt::from_mode(a1 & 0o7777),
                    ) {
                        Ok(()) => 0,
                        Err(e) => io_err(&e),
                    }
                }
            }
            79 => 0, // settimeofday: accepted (guest clock is the host's)
            83 => {
                // symlink(target, linkpath)
                let target = read_guest_str(mem, a0);
                let link = read_guest_str(mem, a1);
                let host = self.fs.host_path(&self.fs.resolve(&link));
                match std::os::unix::fs::symlink(&target, &host) {
                    Ok(()) => 0,
                    Err(e) => io_err(&e),
                }
            }
            212 => 0, // chown32: stat reports fixed guest ids anyway
            57 => 0,  // setpgid: process groups are not modeled (yet)
            75 => 0,  // setrlimit: limits are not enforced
            263 => {
                // clock_gettime(clk, ts*)
                let (secs, nanos) = now_unix();
                if (a1 as usize) + 8 > mem.len() {
                    return err(EFAULT);
                }
                put32(mem, a1, secs as u32);
                put32(mem, a1 + 4, nanos);
                0
            }
            322 => {
                // openat(dirfd, path, flags, mode)
                let p = read_guest_str(mem, a1);
                if p.starts_with('/') || a0 as i32 == AT_FDCWD {
                    self.do_open(None, &p, a2)
                } else {
                    match self.dir_guest_path(a0 as i32) {
                        Some(base) => self.do_open(Some(base), &p, a2),
                        None => err(EBADF),
                    }
                }
            }
            334 => {
                // faccessat(dirfd, path, mode)
                let p = read_guest_str(mem, a1);
                let abs = if p.starts_with('/') || a0 as i32 == AT_FDCWD {
                    self.fs.resolve(&p)
                } else {
                    match self.dir_guest_path(a0 as i32) {
                        Some(base) => self.fs.resolve_from(&base, &p),
                        None => return err(EBADF),
                    }
                };
                let host = self.fs.host_path(&abs);
                if host.exists() { 0 } else { err(ENOENT) }
            }
            384 => {
                // getrandom(buf, len, flags)
                let (buf, len) = (a0 as usize, a1 as usize);
                if buf + len > mem.len() {
                    return err(EFAULT);
                }
                for i in 0..len {
                    if i % 8 == 0 {
                        self.next_rand();
                    }
                    mem.set_byte((buf + i) as u32, (self.rng >> ((i % 8) * 8)) as u8);
                }
                len as u32
            }
            0x0f0002 => 0, // ARM cacheflush: interpreter fetches from mem
            0x0f0005 => {
                // ARM set_tls
                cpu.tls = a0;
                0
            }
            _ => {
                if self.log_unimplemented && self.seen.insert(nr) {
                    eprintln!("[paxcore] unimplemented syscall {nr}, returning ENOSYS");
                }
                err(ENOSYS)
            }
        }
    }

    fn do_getdents(&mut self, mem: &mut Mem, fdnum: i32, buf: u32, count: u32) -> u32 {
        let fd = match self.fs.fds.get_mut(&fdnum) {
            Some(f) => f,
            None => return err(EBADF),
        };
        let dir_host = match &fd.kind {
            FdKind::Dir(p) => p.clone(),
            _ => return err(ENOTDIR),
        };
        if fd.dir_entries.is_none() {
            let mut entries: Vec<(String, u64, u8)> = Vec::new();
            let self_ino = std::fs::metadata(&dir_host)
                .map(|m| m.ino())
                .unwrap_or(2);
            entries.push((".".to_string(), self_ino, 4));
            entries.push(("..".to_string(), 2, 4));
            if let Ok(rd) = std::fs::read_dir(&dir_host) {
                let mut names: Vec<_> = rd.filter_map(|e| e.ok()).collect();
                names.sort_by_key(|e| e.file_name());
                for e in names {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let ino = e.ino();
                    let dt = match e.file_type() {
                        Ok(t) if t.is_dir() => 4,
                        Ok(t) if t.is_symlink() => 10,
                        Ok(_) => 8,
                        Err(_) => 0,
                    };
                    entries.push((name, ino, dt));
                }
            }
            fd.dir_entries = Some(entries);
        }
        let entries = fd.dir_entries.as_ref().unwrap();
        let base = buf as usize;
        if base + count as usize > mem.len() {
            return err(EFAULT);
        }
        let mut written = 0usize;
        let mut idx = fd.dir_pos;
        while idx < entries.len() {
            let (name, ino, dt) = &entries[idx];
            let reclen = (19 + name.len() + 1 + 7) & !7;
            if written + reclen > count as usize {
                if written == 0 {
                    return err(EINVAL);
                }
                break;
            }
            let off = base + written;
            put64(mem, (off) as u32, *ino);
            put64(mem, (off + 8) as u32, (idx + 1) as u64);
            put(mem, (off + 16) as u32, &(reclen as u16).to_le_bytes());
            mem.set_byte((off + 18) as u32, *dt);
            put(mem, (off + 19) as u32, name.as_bytes());
            mem.set_byte((off + 19 + name.len()) as u32, 0);
            written += reclen;
            idx += 1;
        }
        fd.dir_pos = idx;
        written as u32
    }
}
