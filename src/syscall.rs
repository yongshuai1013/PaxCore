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
}

impl Default for SigShared {
    fn default() -> SigShared {
        SigShared {
            actions: std::array::from_fn(|_| SigAction::default()),
        }
    }
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

pub struct Syscalls {
    pub fs: GuestFs,
    pub log_unimplemented: bool,
    seen: std::collections::HashSet<u32>,
    brk: u32,
    mmap_next: u32,
    /// Live mmap intervals (base, len), page aligned. GB
    /// binaries are prelinked: the linker demands exact load
    /// addresses via mmap hints, so hint-less bump allocation
    /// alone cannot serve it -- the intervals also decide
    /// whether a hinted address is free and what MAP_FIXED /
    /// munmap replace.
    maps: Vec<(u32, u32)>,
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
}

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
            brk: (image_end + 0xFFF) & !0xFFF,
            mmap_next: MAP_BASE,
            maps: Vec::new(),
            rng: seed | 1,
            pid: 100,
            ppid: 99,
            tgid: 100,
            tid_addr: 0,
            sighand: std::rc::Rc::new(std::cell::RefCell::new(SigShared::default())),
            sig_mask: 0,
            pending: 0,
        }
    }

    /// Reset the address-space bookkeeping after a successful
    /// execve image replacement. The fd table, cwd, pid and rng
    /// deliberately survive (POSIX: open fds stay open across
    /// exec unless CLOEXEC, which we do not track yet).
    pub fn reset_exec(&mut self, image_end: u32) {
        self.brk = (image_end + 0xFFF) & !0xFFF;
        self.mmap_next = MAP_BASE;
        self.maps.clear();
    }

    /// Is [base, base+len) disjoint from every live interval?
    fn range_free(&self, base: u32, len: u32) -> bool {
        let end = base.wrapping_add(len);
        self.maps
            .iter()
            .all(|&(b, l)| b.wrapping_add(l) <= base || b >= end)
    }

    /// Drop [base, base+len) from the interval list, trimming
    /// partial overlaps the way munmap/MAP_FIXED replacement do.
    fn unmap_range(&mut self, base: u32, len: u32) {
        let end = base.wrapping_add(len);
        let mut out = Vec::with_capacity(self.maps.len());
        for &(b, l) in &self.maps {
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
        self.maps = out;
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
            };
            fds.insert(
                *num,
                crate::fs::Fd {
                    kind,
                    dir_pos: fd.dir_pos,
                    dir_entries: fd.dir_entries.clone(),
                },
            );
        }
        Syscalls {
            exe_path: self.exe_path.clone(),
            fs: crate::fs::GuestFs {
                root: self.fs.root.clone(),
                cwd: self.fs.cwd.clone(),
                fds,
            },
            log_unimplemented: self.log_unimplemented,
            seen: self.seen.clone(),
            brk: self.brk,
            mmap_next: self.mmap_next,
            maps: self.maps.clone(),
            rng: self.rng,
            pid: child_pid,
            ppid: self.pid,
            tgid: child_pid,
            tid_addr: 0,
            sighand: std::rc::Rc::new(std::cell::RefCell::new(SigShared {
                actions: self.sighand.borrow().actions,
            })),
            sig_mask: self.sig_mask,
            pending: 0,
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
        if std::env::var_os("PAXCORE_TRACE").is_some() {
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
                                return Outcome::WouldBlock;
                            }
                            return done(cpu, 0);
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
            5 => {
                let p = read_guest_str(mem, a0);
                self.do_open(None, &p, a2)
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
            64 => self.ppid,    // getppid
            224 => self.pid,    // gettid (no threads yet: tid == pid)
            _ => self.handle2(cpu, mem, nr),
        };
        cpu.r[0] = ret;
        if std::env::var_os("PAXCORE_TRACE").is_some() {
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
            41 => {
                // dup(fd)
                match self.clone_fd(a0 as i32) {
                    Some(fd) => self.fs.alloc_fd(fd) as u32,
                    None => err(EBADF),
                }
            }
            45 => {
                // brk(addr)
                if a0 != 0 && a0 >= (self.brk & !0xFFF) && a0 < MAP_BASE {
                    if a0 > self.brk {
                        let (s, e) = (self.brk as usize, a0 as usize);
                        if e <= mem.len() {
                            mem.zero_range(s as u32, e - s);
                        }
                    }
                    self.brk = a0;
                }
                self.brk
            }
            54 => {
                // ioctl(fd, request, arg)
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
                    1 | 3 => 0, // F_GETFD / F_GETFL
                    2 | 4 => 0, // F_SETFD / F_SETFL
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

    fn clone_fd(&self, n: i32) -> Option<Fd> {
        let src = self.fs.fds.get(&n)?;
        let kind = match &src.kind {
            FdKind::StdIn => FdKind::StdIn,
            FdKind::StdOut => FdKind::StdOut,
            FdKind::StdErr => FdKind::StdErr,
            FdKind::Dir(p) => FdKind::Dir(p.clone()),
            FdKind::Pipe(e) => FdKind::Pipe(e.clone()),
            FdKind::File(f) => match f.try_clone() {
                Ok(c) => FdKind::File(c),
                Err(_) => return None,
            },
        };
        Some(Fd::new(kind))
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
                // poll(fds, nfds, timeout): everything is ready
                let base = a0 as usize;
                let nfds = a1 as usize;
                if base + nfds * 8 > mem.len() {
                    return err(EFAULT);
                }
                for i in 0..nfds {
                    let ev_off = base + i * 8 + 6;
                    let ev = mem.read_u16((ev_off - 2) as u32);
                    mem.set_byte(ev_off as u32, (ev & 0x5) as u8); // POLLIN|POLLOUT subset
                    mem.set_byte((ev_off + 1) as u32, 0);
                }
                nfds as u32
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
                    want
                } else if want != 0 && self.range_free(want, len) {
                    want
                } else {
                    let mut b = self.mmap_next;
                    while !self.range_free(b, len) {
                        match self.maps.iter().find(|&&(mb, ml)| {
                            let me = mb.wrapping_add(ml);
                            me > b && mb < b.wrapping_add(len)
                        }) {
                            Some(&(mb, ml)) => {
                                b = (mb.wrapping_add(ml) + 0xFFF) & !0xFFF;
                            }
                            None => break,
                        }
                    }
                    self.mmap_next = b.wrapping_add(len);
                    b
                };
                self.maps.push((base, len));
                mem.zero_range(base, len as usize);
                let anon = a3 & 0x20 != 0 || a4 as i32 == -1;
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
                mem.zero_range(base, len as usize);
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
                // readlink(path, buf, bufsiz)
                let p = read_guest_str(mem, a0);
                let target = if p == "/proc/self/exe" || p == "/proc/thread-self/exe" {
                    Some(self.exe_path.clone())
                } else {
                    let host = self.fs.host_path(&p);
                    std::fs::read_link(&host)
                        .ok()
                        .map(|t| t.to_string_lossy().into_owned())
                };
                match target {
                    Some(t) => {
                        let n = t.len().min(a2 as usize);
                        put(mem, a1, &t.as_bytes()[..n]);
                        n as u32
                    }
                    None => err(22), // EINVAL: not a symlink
                }
            }
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
