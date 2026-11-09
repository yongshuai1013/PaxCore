mod binder;
mod block;
mod cpu;
mod elf;
mod fs;
mod mem;
mod syscall;
mod thumb;

use mem::Mem;

use cpu::{Cpu, Step};
use std::time::Instant;

fn max_steps() -> u64 {
    std::env::var("PAXCORE_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000_000)
}

fn put32(mem: &mut Mem, addr: u32, val: u32) {
    mem.write_u32(addr, val);
}

/// Guest stack top for the initial process.
const STACK_TOP: u32 = 0x1000_0000;

/// Build the Linux initial stack: argc, argv[], NULL, envp[], NULL,
/// auxv pairs, AT_NULL -- with strings above. Returns the stack ptr.
/// auxv entries a dynamically-linked program needs to hand
/// control to its interpreter: where the main program's headers
/// are, where the interpreter was loaded, and where the main
/// program really starts.
pub struct DynAux {
    pub phdr: u32,
    pub phent: u32,
    pub phnum: u32,
    pub base: u32,
    pub entry: u32,
    pub execfn: String,
}

pub struct ProgramImage {
    /// Where execution actually starts (the interpreter's entry
    /// for dynamic programs, the program's own otherwise).
    pub start_entry: u32,
    pub image_end: u32,
    pub dyn_aux: Option<DynAux>,
}

/// Load a program and its interpreter (if any) into guest
/// memory. The interpreter is resolved inside the guest root,
/// exactly like a kernel resolving PT_INTERP at exec time.
fn load_program(bytes: &[u8], mem: &mut Mem, root: &str) -> Result<ProgramImage, String> {
    let main = elf::load(bytes, mem)?;
    if let Some(interp_path) = &main.interp {
        let fs = crate::fs::GuestFs::new(root.to_string());
        let host = fs.host_path(interp_path);
        let ibytes = std::fs::read(&host)
            .map_err(|e| format!("cannot load interpreter {interp_path}: {e}"))?;
        let il = elf::load(&ibytes, mem)?;
        // AT_BASE is the interpreter's image base (its lowest
        // LOAD vaddr). Deriving it from the phdr address breaks
        // when the interpreter's headers sit outside every LOAD
        // (the GB linker's first LOAD is empty), which once made
        // the linker mistake itself for the main program and
        // re-run its own init forever.
        let base = il.min_vaddr;
        return Ok(ProgramImage {
            start_entry: il.entry,
            image_end: main.image_end,
            dyn_aux: Some(DynAux {
                phdr: main.phdr,
                phent: main.phent,
                phnum: main.phnum,
                base,
                entry: main.raw_entry,
                execfn: String::new(),
            }),
        });
    }
    Ok(ProgramImage {
        start_entry: main.entry,
        image_end: main.image_end,
        dyn_aux: None,
    })
}

fn build_stack(
    mem: &mut Mem,
    argv: &[String],
    env: &[String],
    dyn_aux: Option<&DynAux>,
) -> u32 {
    let mut sp = STACK_TOP & !15;
    // Random bytes for AT_RANDOM.
    sp -= 16;
    let random_ptr = sp;
    let seed = std::env::var("PAXCORE_SEED")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x1234_5678_9abc_def0)
        });
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    for i in 0..16 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        mem.set_byte(random_ptr + i as u32, (x >> 32) as u8);
    }
    let mut push_str = |mem: &mut Mem, sp: &mut u32, s: &str| -> u32 {
        *sp -= (s.len() as u32 + 1 + 3) & !3;
        let p = *sp;
        mem.write_slice(p, s.as_bytes());
        mem.set_byte(p + s.len() as u32, 0);
        p
    };
    let mut arg_ptrs: Vec<u32> = Vec::new();
    for a in argv {
        arg_ptrs.push(push_str(mem, &mut sp, a));
    }
    let mut env_ptrs: Vec<u32> = Vec::new();
    for e in env {
        env_ptrs.push(push_str(mem, &mut sp, e));
    }
    let execfn_ptr = match dyn_aux {
        Some(d) if !d.execfn.is_empty() => push_str(mem, &mut sp, &d.execfn),
        _ => 0,
    };
    let n_aux = 9 + if dyn_aux.is_some() { 6 } else { 0 };
    let words = 1 + arg_ptrs.len() + 1 + env_ptrs.len() + 1 + 2 * n_aux + 2;
    sp -= (words as u32) * 4;
    sp &= !7;
    let mut w = sp;
    put32(mem, w, argv.len() as u32);
    w += 4;
    for p in &arg_ptrs {
        put32(mem, w, *p);
        w += 4;
    }
    put32(mem, w, 0);
    w += 4;
    for p in &env_ptrs {
        put32(mem, w, *p);
        w += 4;
    }
    put32(mem, w, 0);
    w += 4;
    let aux: [(u32, u32); 9] = [
        (6, 4096),        // AT_PAGESZ
        (11, 1000),       // AT_UID
        (12, 1000),       // AT_EUID
        (13, 1000),       // AT_GID
        (14, 1000),       // AT_EGID
        (16, 0x0000_0000),// AT_HWCAP (filled by caller if needed)
        (17, 100),        // AT_CLKTCK
        (23, 0),          // AT_SECURE
        (25, random_ptr), // AT_RANDOM
    ];
    for (k, v) in aux {
        put32(mem, w, k);
        put32(mem, w + 4, v);
        w += 8;
    }
    if let Some(d) = dyn_aux {
        for (k, v) in [
            (3, d.phdr),      // AT_PHDR
            (4, d.phent),     // AT_PHENT
            (5, d.phnum),     // AT_PHNUM
            (7, d.base),      // AT_BASE
            (9, d.entry),     // AT_ENTRY
            (31, execfn_ptr), // AT_EXECFN
        ] {
            put32(mem, w, k);
            put32(mem, w + 4, v);
            w += 8;
        }
    }
    put32(mem, w, 0);
    put32(mem, w + 4, 0);
    sp
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut rootfs = std::env::var("PAXCORE_ROOTFS").unwrap_or_else(|_| "rootfs".into());
    if args.len() >= 2 && args[0] == "--rootfs" {
        rootfs = args[1].clone();
        args.drain(0..2);
    }
    if args.is_empty() {
        eprintln!("usage: paxcore [--rootfs DIR] <guest.elf> [guest args...]");
        std::process::exit(2);
    }
    let guest_path = args[0].clone();
    let guest_argv: Vec<String> = args.clone();
    let bytes = std::fs::read(&guest_path).expect("read guest ELF");
    let mut mem = Mem::new();
    let mut loaded = load_program(&bytes, &mut mem, &rootfs).expect("load guest program");
    if let Some(d) = &mut loaded.dyn_aux {
        if d.execfn.is_empty() {
            d.execfn = guest_argv[0].clone();
        }
    }
    let mut guest_env: Vec<String> = vec![
        "PATH=/bin:/usr/bin".into(),
        "HOME=/".into(),
        "TERM=dumb".into(),
    ];
    // Extra guest environment for bring-up runs (services
    // normally get theirs from init): PAXCORE_GUEST_ENV holds
    // ';'-separated KEY=VAL pairs.
    if let Ok(extra) = std::env::var("PAXCORE_GUEST_ENV") {
        for kv in extra.split(';') {
            if kv.contains('=') {
                guest_env.push(kv.to_string());
            }
        }
    }
    let sp = build_stack(
        &mut mem,
        &guest_argv,
        &guest_env,
        loaded.dyn_aux.as_ref(),
    );
    let mut cpu = Cpu::new(loaded.start_entry & !1, sp);
    cpu.thumb = loaded.start_entry & 1 == 1;
    let watch: Option<u32> = std::env::var("PAXCORE_WATCH")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    let mut watch_val: u32 = 0;
    // PAXCORE_POKE=<target>:<value>:<trigger_addr>:<trigger_value>
    // (all hex): once the trigger word holds the trigger value
    // and the target word is still 0, write the value into the
    // target (once). Diagnostic only: tests whether a single
    // missing guest-memory write is sufficient to explain a
    // hang, before hunting why the guest never wrote it.
    let poke: Option<(u32, u32, u32, u32)> = std::env::var("PAXCORE_POKE")
        .ok()
        .and_then(|s| {
            let p: Vec<u32> = s
                .split(':')
                .filter_map(|x| {
                    u32::from_str_radix(x.trim().trim_start_matches("0x"), 16).ok()
                })
                .collect();
            if p.len() == 4 {
                Some((p[0], p[1], p[2], p[3]))
            } else {
                None
            }
        });
    let mut poke_done = false;
    let mut sys = syscall::Syscalls::new(rootfs.clone(), loaded.image_end);
    sys.exe_path = match guest_path.strip_prefix(&rootfs) {
        Some(rest) => format!("/{}", rest.trim_start_matches('/')),
        None => guest_argv[0].clone(),
    };
    // Block decode cache (JIT stage 2a): ARM mode only, and off
    // whenever tracing or watching is requested so those stay
    // instruction-exact. PAXCORE_NOCACHE=1 forces the legacy path
    // for differential testing. Each process owns a cache, flushed
    // after every syscall (a syscall may map or replace code).
    let cache_on = !cpu.trace
        && watch.is_none()
        && cpu.watch_pc.is_none()
        && std::env::var_os("PAXCORE_NOCACHE").is_none();
    let init = Process {
        pid: 100,
        ppid: 99,
        tgid: 100,
        cpu,
        mem: std::rc::Rc::new(std::cell::RefCell::new(mem)),
        sys,
        blocks: std::collections::HashMap::new(),
        zombie: None,
        wait_req: None,
        retry_syscall: false,
        block_streak: 0,
        cleartid: 0,
        blocks_dirty: false,
        binder_wait: false,
    };
    let mut sched = Scheduler {
        procs: vec![init],
        next_pid: 101,
        total_steps: 0,
    };
    let t0 = Instant::now();
    let code = sched.run(cache_on, watch, &mut watch_val, poke, &mut poke_done);
    let dt = t0.elapsed();
    eprintln!(
        "[paxcore] guest exit({code}) after {} instructions in {:.3}s ({:.1} MIPS on this host)",
        sched.total_steps,
        dt.as_secs_f64(),
        sched.total_steps as f64 / dt.as_secs_f64() / 1e6
    );
    std::process::exit(code as i32 & 0xff);
}

/// Guest memory, shared between the threads of a group
/// (CLONE_VM) and private to fork children (which get a sparse
/// copy in a fresh cell).
type SharedMem = std::rc::Rc<std::cell::RefCell<Mem>>;

/// One guest process or thread: its own CPU, (possibly shared)
/// memory, syscall state and block cache.
struct Process {
    pid: u32,
    ppid: u32,
    /// Thread-group id: the leader's pid. Equal to pid for
    /// ordinary processes; threads share their creator's tgid.
    tgid: u32,
    cpu: Cpu,
    mem: SharedMem,
    sys: syscall::Syscalls,
    blocks: block::BlockCache,
    /// Some(exit_code) once the process has terminated and is
    /// waiting to be reaped by its parent.
    zombie: Option<u32>,
    /// A wait4 the process is blocked in: (pid arg, status ptr,
    /// options). Completed by the scheduler when a matching child
    /// turns zombie.
    wait_req: Option<(i32, u32, u32)>,
    /// A pipe syscall returned WouldBlock: the arguments are
    /// still in the registers, so the scheduler re-issues the
    /// syscall itself before running any more guest code.
    retry_syscall: bool,
    /// Consecutive WouldBlock re-issues; a very large streak
    /// means the peer is never coming, so the syscall is failed
    /// with EAGAIN instead of spinning forever.
    block_streak: u32,
    /// CLONE_CHILD_CLEARTID address: zeroed when this thread
    /// exits (waiters observe it through futex re-issue).
    cleartid: u32,
    /// Set when this process ran a syscall that may have written
    /// shared memory; the scheduler then flushes the block caches
    /// of every process sharing this address space.
    blocks_dirty: bool,
    /// Parked in a binder BINDER_WRITE_READ with an empty inbox:
    /// skipped by the picker until the binder core queues work
    /// for its group (or a signal becomes deliverable).
    binder_wait: bool,
}

enum SliceEnd {
    Budget,
    Fork(usize),
    Wait4(usize, i32, u32, u32),
    Exec(usize, String, Vec<String>, Vec<String>),
    WouldBlock(usize),
    BinderWait(usize),
    Clone(usize, u32, u32, u32, u32, u32),
    SendSignal(usize, u32, Option<u32>, u32),
    SigReturn(usize),
    SignalKill(usize, u32),
    ExitThread(usize, u32),
    ExitGroup(usize, u32),
}

struct Scheduler {
    procs: Vec<Process>,
    next_pid: u32,
    total_steps: u64,
}

const SLICE_STEPS: u64 = 100_000;
const ECHILD_NEG: u32 = (-10i32) as u32;

impl Scheduler {
    fn run(
        &mut self,
        cache_on: bool,
        watch: Option<u32>,
        watch_val: &mut u32,
        poke: Option<(u32, u32, u32, u32)>,
        poke_done: &mut bool,
    ) -> u32 {
        let mut cursor = 0usize;
        // PAXCORE_PCSAMPLE=<steps>: periodically dump every
        // process's pc/lr so a long guest phase (e.g. zygote
        // class preloading) can be told apart from a spin --
        // progressing work walks many functions, a loop sits
        // in a handful.
        let sample_every: u64 = std::env::var("PAXCORE_PCSAMPLE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut next_sample = sample_every;
        loop {
            if sample_every > 0 && self.total_steps >= next_sample {
                next_sample += sample_every;
                eprintln!("[paxcore] pcsample @{}", self.total_steps);
                for p in &self.procs {
                    eprintln!(
                        "[paxcore]   pid {} steps {} pc 0x{:08x} lr 0x{:08x} r0 0x{:08x} r1 0x{:08x} r2 0x{:08x} r3 0x{:08x} r4 0x{:08x} r5 0x{:08x} r6 0x{:08x} r7 0x{:08x} r8 0x{:08x} r9 0x{:08x} r10 0x{:08x} r11 0x{:08x} r12 0x{:08x} sp 0x{:08x}",
                        p.pid,
                        p.cpu.steps,
                        p.cpu.r[15],
                        p.cpu.r[14],
                        p.cpu.r[0],
                        p.cpu.r[1],
                        p.cpu.r[2],
                        p.cpu.r[3],
                        p.cpu.r[4],
                        p.cpu.r[5],
                        p.cpu.r[6],
                        p.cpu.r[7],
                        p.cpu.r[8],
                        p.cpu.r[9],
                        p.cpu.r[10],
                        p.cpu.r[11],
                        p.cpu.r[12],
                        p.cpu.r[13]
                    );
                }
            }
            if self.total_steps >= max_steps() {
                eprintln!("[paxcore] step limit reached");
                for p in &self.procs {
                    eprintln!(
                        "[paxcore]   pid {} tgid {} steps {} zombie {:?} pc 0x{:08x}",
                        p.pid, p.tgid, p.cpu.steps, p.zombie, p.cpu.r[15]
                    );
                    {
                        let asp = p.sys.asp.borrow();
                        let mut line = format!(
                            "[paxcore]   maps pid {} brk 0x{:08x}:",
                            p.pid, asp.brk
                        );
                        for (b, l) in &asp.maps {
                            line += &format!(" [0x{:08x}+0x{:x}]", b, l);
                        }
                        eprintln!("{line}");
                    }
                    if let Ok(spec) = std::env::var("PAXCORE_DUMP") {
                        let mut it = spec.split(':');
                        if let (Some(range), Some(path)) = (it.next(), it.next()) {
                            let mut ab = range.split('-');
                            let s = u32::from_str_radix(ab.next().unwrap_or("0"), 16)
                                .unwrap_or(0);
                            let e = u32::from_str_radix(ab.next().unwrap_or("0"), 16)
                                .unwrap_or(0);
                            let mut buf = vec![0u8; (e - s) as usize];
                            p.mem.borrow().read_slice(s, &mut buf);
                            let _ = std::fs::write(
                                format!("{}-{}", path, p.pid),
                                &buf,
                            );
                        }
                    }
                }
                std::process::exit(124);
            }
            // Pick the next runnable process (round-robin).
            let mut picked: Option<usize> = None;
            for k in 0..self.procs.len() {
                let i = (cursor + k) % self.procs.len();
                let p = &self.procs[i];
                if p.zombie.is_some() || p.wait_req.is_some() {
                    continue;
                }
                if p.binder_wait {
                    // Parked on an empty binder inbox: runnable
                    // again once the core queues work for its
                    // group, or a signal is deliverable.
                    let core = p.sys.binder.borrow();
                    let has_work = core.has_inbox(p.tgid);
                    drop(core);
                    let sig_ready = (p.sys.pending
                        | p.sys.sighand.borrow().group_pending)
                        & !p.sys.sig_mask
                        != 0;
                    if !has_work && !sig_ready {
                        continue;
                    }
                }
                picked = Some(i);
                break;
            }
            let idx = match picked {
                Some(i) => i,
                None => {
                    // Nobody runnable: either only zombies remain
                    // (their parents are gone; reap silently and
                    // finish with the initial process's fate) or
                    // every live process is parked on binder --
                    // a booted system at idle, which is a success
                    // state for a VM core, not a deadlock. Anything
                    // else is a genuine wait deadlock.
                    if self.procs.iter().all(|p| p.zombie.is_some()) {
                        return self.procs[0].zombie.unwrap_or(0);
                    }
                    if self
                        .procs
                        .iter()
                        .filter(|p| p.zombie.is_none())
                        .all(|p| p.binder_wait)
                    {
                        eprintln!(
                            "[paxcore] system idle: all live processes are waiting on binder"
                        );
                        return 0;
                    }
                    panic!("[paxcore] scheduler deadlock: all processes blocked in wait4");
                }
            };
            cursor = idx + 1;
            let slice_end = self.run_slice(idx, cache_on, watch, watch_val, poke, poke_done);
            // A syscall inside the slice may have written shared
            // memory (or mapped new code): drop decoded blocks of
            // the whole address-space group before anyone runs on.
            if self.procs[idx].blocks_dirty {
                self.procs[idx].blocks_dirty = false;
                let mem = self.procs[idx].mem.clone();
                for p in &mut self.procs {
                    if std::rc::Rc::ptr_eq(&p.mem, &mem) {
                        p.blocks.clear();
                    }
                }
            }
            match slice_end {
                SliceEnd::Budget => {}
                SliceEnd::Fork(parent_idx) => {
                    self.do_fork(parent_idx);
                    // Child runs first (as on Linux): a newborn
                    // thread/process must consume its start-up
                    // arguments before the parent can recycle
                    // the memory they live in. GB Dalvik's
                    // thread bootstrap info sits in a heap block
                    // the parent's allocator trims within a few
                    // thousand steps; round-robin latency made
                    // the Signal Catcher read a zeroed function
                    // pointer and jump to address 0.
                    cursor = self.procs.len() - 1;
                }
                SliceEnd::Wait4(idx, pid, status_ptr, options) => {
                    self.do_wait(idx, pid, status_ptr, options);
                }
                SliceEnd::Exec(idx, path, argv, envp) => {
                    self.do_exec(idx, &path, &argv, &envp);
                }
                SliceEnd::BinderWait(idx) => {
                    let p = &mut self.procs[idx];
                    p.binder_wait = true;
                    p.retry_syscall = true;
                }
                SliceEnd::WouldBlock(idx) => {
                    let p = &mut self.procs[idx];
                    p.block_streak += 1;
                    if p.block_streak > 2_000_000 {
                        eprintln!(
                            "[paxcore] pid {} pipe syscall blocked {} times; failing with EAGAIN",
                            p.pid, p.block_streak
                        );
                        p.cpu.r[0] = (-11i32) as u32; // -EAGAIN
                        p.retry_syscall = false;
                        p.block_streak = 0;
                    }
                }
                SliceEnd::ExitThread(idx, code) => {
                    if let Some(final_code) = self.terminate_thread(idx, code) {
                        dump_mem(&self.procs[0].mem.borrow());
                        return final_code;
                    }
                }
                SliceEnd::ExitGroup(idx, code) => {
                    if let Some(final_code) = self.finish_group(idx, code) {
                        dump_mem(&self.procs[0].mem.borrow());
                        return final_code;
                    }
                }
                SliceEnd::Clone(idx, flags, stack, ptid, tls, ctid) => {
                    self.do_clone(idx, flags, stack, ptid, tls, ctid);
                    // Child runs first: see the Fork arm.
                    cursor = self.procs.len() - 1;
                }
                SliceEnd::SendSignal(idx, tgid, tid, sig) => {
                    self.do_send_signal(idx, tgid, tid, sig);
                }
                SliceEnd::SigReturn(idx) => self.do_sigreturn(idx),
                SliceEnd::SignalKill(idx, sig) => {
                    if let Some(final_code) =
                        self.finish_group_status(idx, sig & 0x7F, 128 + sig)
                    {
                        dump_mem(&self.procs[0].mem.borrow());
                        return final_code;
                    }
                }
            }
        }
    }

    fn run_slice(
        &mut self,
        idx: usize,
        cache_on: bool,
        watch: Option<u32>,
        watch_val: &mut u32,
        poke: Option<(u32, u32, u32, u32)>,
        poke_done: &mut bool,
    ) -> SliceEnd {
        let start_steps = self.procs[idx].cpu.steps;
        // Re-issue a pipe syscall that blocked last slice: the
        // arguments are still sitting in the registers.
        if self.procs[idx].retry_syscall {
            let outcome = {
                let p = &mut self.procs[idx];
                let mut guard = p.mem.borrow_mut();
                p.sys.handle(&mut p.cpu, &mut guard)
            };
            self.procs[idx].blocks_dirty = true;
            match outcome {
                syscall::Outcome::Continue => {
                    self.procs[idx].retry_syscall = false;
                    self.procs[idx].block_streak = 0;
                    self.procs[idx].binder_wait = false;
                }
                syscall::Outcome::WouldBlock => return SliceEnd::WouldBlock(idx),
                syscall::Outcome::BinderWait => return SliceEnd::BinderWait(idx),
                syscall::Outcome::ExitThread(code) => {
                    return SliceEnd::ExitThread(idx, code);
                }
                syscall::Outcome::ExitGroup(code) => {
                    return SliceEnd::ExitGroup(idx, code);
                }
                syscall::Outcome::Fork => return SliceEnd::Fork(idx),
                syscall::Outcome::Clone {
                    flags,
                    stack,
                    ptid,
                    tls,
                    ctid,
                } => return SliceEnd::Clone(idx, flags, stack, ptid, tls, ctid),
                syscall::Outcome::SendSignal { tgid, tid, sig } => {
                    return SliceEnd::SendSignal(idx, tgid, tid, sig);
                }
                syscall::Outcome::SigReturn => return SliceEnd::SigReturn(idx),
                syscall::Outcome::Exec { path, argv, envp } => {
                    return SliceEnd::Exec(idx, path, argv, envp);
                }
                syscall::Outcome::Wait4 {
                    pid,
                    status_ptr,
                    options,
                } => return SliceEnd::Wait4(idx, pid, status_ptr, options),
            }
        }
        if let Some(sig) = self.deliver_pending(idx) {
            return SliceEnd::SignalKill(idx, sig);
        }
        loop {
            if self.procs[idx].cpu.steps - start_steps >= SLICE_STEPS {
                self.total_steps += self.procs[idx].cpu.steps - start_steps;
                return SliceEnd::Budget;
            }
            let pre_pc = self.procs[idx].cpu.r[15];
            let pre_thumb = self.procs[idx].cpu.thumb;
            let step_result = {
                let p = &mut self.procs[idx];
                let mut guard = p.mem.borrow_mut();
                if cache_on && !p.cpu.thumb {
                    match p.cpu.run_block(&mut guard, &mut p.blocks) {
                        Some(s) => {
                            p.blocks.clear();
                            s
                        }
                        None => Step::Continue,
                    }
                } else {
                    p.cpu.step(&mut guard)
                }
            };
            if pre_thumb
                && !self.procs[idx].cpu.thumb
                && std::env::var_os("PAXCORE_WATCHMODE").is_some()
            {
                let c = &self.procs[idx].cpu;
                eprintln!(
                    "[modeflip] T->A by insn at pc=0x{pre_pc:08x}: newpc=0x{:08x} lr=0x{:08x} r0=0x{:08x} r1=0x{:08x} r2=0x{:08x} r3=0x{:08x} r4=0x{:08x} (step {})",
                    c.r[15], c.r[14], c.r[0], c.r[1], c.r[2], c.r[3], c.r[4], c.steps
                );
            }
            match step_result {
                Step::Continue => {
                    if let Some(w) = watch {
                        let p = &self.procs[idx];
                        let guard = p.mem.borrow();
                        let v = guard.read_u32(w);
                        if v != *watch_val {
                            eprintln!(
                                "[watch] 0x{w:08x}: 0x{watch_val:08x} -> 0x{v:08x} after insn at pc=0x{pre_pc:08x} (step {})",
                                p.cpu.steps
                            );
                            *watch_val = v;
                        }
                    }
                    if let Some((taddr, tval, gaddr, gval)) = poke {
                        if !*poke_done {
                            let p = &self.procs[idx];
                            let mut guard = p.mem.borrow_mut();
                            if guard.read_u32(gaddr) == gval
                                && guard.read_u32(taddr) == 0
                            {
                                guard.write_u32(taddr, tval);
                                *poke_done = true;
                                eprintln!(
                                    "[poke] 0x{taddr:08x} := 0x{tval:08x} (trigger hit, pid {} step {})",
                                    p.pid, p.cpu.steps
                                );
                            }
                        }
                    }
                }
                Step::Syscall => {
                    let outcome = {
                        let p = &mut self.procs[idx];
                        p.blocks.clear();
                        p.blocks_dirty = true;
                        let mut guard = p.mem.borrow_mut();
                        p.sys.handle(&mut p.cpu, &mut guard)
                    };
                    match outcome {
                        syscall::Outcome::Continue => {
                            self.procs[idx].block_streak = 0;
                            if let Some(sig) = self.deliver_pending(idx) {
                                self.total_steps +=
                                    self.procs[idx].cpu.steps - start_steps;
                                return SliceEnd::SignalKill(idx, sig);
                            }
                        }
                        syscall::Outcome::SendSignal { tgid, tid, sig } => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::SendSignal(idx, tgid, tid, sig);
                        }
                        syscall::Outcome::SigReturn => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::SigReturn(idx);
                        }
                        syscall::Outcome::WouldBlock => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            self.procs[idx].retry_syscall = true;
                            return SliceEnd::WouldBlock(idx);
                        }
                        syscall::Outcome::BinderWait => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            self.procs[idx].retry_syscall = true;
                            return SliceEnd::BinderWait(idx);
                        }
                        syscall::Outcome::ExitThread(code) => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::ExitThread(idx, code);
                        }
                        syscall::Outcome::ExitGroup(code) => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::ExitGroup(idx, code);
                        }
                        syscall::Outcome::Clone {
                            flags,
                            stack,
                            ptid,
                            tls,
                            ctid,
                        } => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::Clone(idx, flags, stack, ptid, tls, ctid);
                        }
                        syscall::Outcome::Fork => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::Fork(idx);
                        }
                        syscall::Outcome::Exec { path, argv, envp } => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::Exec(idx, path, argv, envp);
                        }
                        syscall::Outcome::Wait4 {
                            pid,
                            status_ptr,
                            options,
                        } => {
                            self.total_steps += self.procs[idx].cpu.steps - start_steps;
                            return SliceEnd::Wait4(idx, pid, status_ptr, options);
                        }
                    }
                }
            }
        }
    }

    /// execve: replace the process image. The new image is built
    /// in scratch memory first, so a failed load (missing file,
    /// not an ELF) leaves the old image untouched and the syscall
    /// simply returns the error, as on a real kernel.
    fn do_exec(&mut self, idx: usize, path: &str, argv: &[String], envp: &[String]) {
        const ENOENT_NEG: u32 = (-2i32) as u32;
        const ENOEXEC_NEG: u32 = (-8i32) as u32;
        let host = self.procs[idx].sys.fs.host_path(path);
        let bytes = match std::fs::read(&host) {
            Ok(b) => b,
            Err(_) => {
                self.procs[idx].cpu.r[0] = ENOENT_NEG;
                return;
            }
        };
        let mut mem = Mem::new();
        let rootfs = self.procs[idx].sys.fs.root.clone().to_string_lossy().into_owned();
        let mut loaded = match load_program(&bytes, &mut mem, &rootfs) {
            Ok(l) => l,
            Err(_) => {
                self.procs[idx].cpu.r[0] = ENOEXEC_NEG;
                return;
            }
        };
        // exec semantics: every other thread of the group is
        // killed, caught signal dispositions reset to default
        // (SIG_IGN survives), pending signals are dropped.
        let tgid = self.procs[idx].tgid;
        let others: Vec<usize> = self
            .procs
            .iter()
            .enumerate()
            .filter(|(i, p)| *i != idx && p.tgid == tgid)
            .map(|(i, _)| i)
            .collect();
        for i in others.into_iter().rev() {
            self.procs.remove(i);
        }
        {
            let shared = self.procs[idx].sys.sighand.clone();
            let mut sh = shared.borrow_mut();
            for act in sh.actions.iter_mut() {
                if act.handler != 0 && act.handler != 1 {
                    *act = syscall::SigAction::default();
                }
            }
            sh.group_pending = 0;
        }
        self.procs[idx].sys.pending = 0;
        self.procs[idx].cleartid = 0;
        let argv_owned: Vec<String> = if argv.is_empty() {
            vec![path.to_string()]
        } else {
            argv.to_vec()
        };
        if let Some(d) = &mut loaded.dyn_aux {
            if d.execfn.is_empty() {
                d.execfn = path.to_string();
            }
        }
        let sp = build_stack(&mut mem, &argv_owned, envp, loaded.dyn_aux.as_ref());
        let old_trace = self.procs[idx].cpu.trace;
        let old_trace_after = self.procs[idx].cpu.trace_after;
        let p = &mut self.procs[idx];
        let mut cpu = Cpu::new(loaded.start_entry & !1, sp);
        cpu.thumb = loaded.start_entry & 1 == 1;
        cpu.trace = old_trace;
        cpu.trace_after = old_trace_after;
        p.cpu = cpu;
        p.mem = std::rc::Rc::new(std::cell::RefCell::new(mem));
        p.blocks.clear();
        p.sys.reset_exec(loaded.image_end);
        p.sys.exe_path = path.to_string();
    }

    /// clone(120): fork's general form. Sharing follows the
    /// flags -- CLONE_VM shares the address space (threads),
    /// CLONE_THREAD joins the parent's thread group. fd-table
    /// sharing (CLONE_FILES) and cwd sharing (CLONE_FS) are NOT
    /// done yet: the new thread gets a fork-style copy of the fd
    /// table, an accepted approximation (pthread_create itself
    /// does not depend on fd sharing; guests that share fds
    /// across threads would notice).
    fn do_clone(
        &mut self,
        parent_idx: usize,
        flags: u32,
        stack: u32,
        ptid: u32,
        tls: u32,
        ctid: u32,
    ) {
        const CLONE_VM: u32 = 0x100;
        const CLONE_PARENT: u32 = 0x8000;
        const CLONE_THREAD: u32 = 0x1_0000;
        const CLONE_SETTLS: u32 = 0x8_0000;
        const CLONE_PARENT_SETTID: u32 = 0x20_0000;
        const CLONE_CHILD_SETTID: u32 = 0x100_0000;
        const CLONE_CHILD_CLEARTID: u32 = 0x200_0000;
        let tid = self.next_pid;
        self.next_pid += 1;
        let child = {
            let parent = &self.procs[parent_idx];
            let mut cpu = parent.cpu.clone();
            cpu.r[0] = 0;
            if stack != 0 {
                cpu.r[13] = stack;
            }
            if flags & CLONE_SETTLS != 0 {
                cpu.tls = tls;
            }
            let tgid = if flags & CLONE_THREAD != 0 {
                parent.tgid
            } else {
                tid
            };
            let ppid = if flags & CLONE_PARENT != 0 {
                parent.ppid
            } else {
                parent.pid
            };
            let mem = if flags & CLONE_VM != 0 {
                parent.mem.clone()
            } else {
                std::rc::Rc::new(std::cell::RefCell::new(
                    parent.mem.borrow().clone_sparse(),
                ))
            };
            let sighand = parent.sys.sighand.clone();
            let asp = parent.sys.asp.clone();
            let mut sys = parent.sys.fork_clone(tid);
            if flags & 0x400 != 0 {
                // CLONE_SIGHAND: threads share dispositions (and
                // the group pending word) with the group.
                // fork_clone always builds a fresh table, which
                // also silently un-shared handler updates.
                sys.sighand = sighand;
            }
            if flags & CLONE_VM != 0 {
                // CLONE_VM: the address space (brk + mmap
                // bookkeeping) is one object for the whole
                // group; fork_clone's snapshot copy diverges
                // and corrupts the shared heap (see AddrSpace).
                sys.asp = asp;
            }
            sys.tgid = tgid;
            sys.ppid = ppid;
            Process {
                pid: tid,
                ppid,
                tgid,
                cpu,
                mem,
                sys,
                blocks: std::collections::HashMap::new(),
                zombie: None,
                wait_req: None,
                retry_syscall: false,
                block_streak: 0,
                cleartid: if flags & CLONE_CHILD_CLEARTID != 0 {
                    ctid
                } else {
                    0
                },
                blocks_dirty: false,
                binder_wait: false,
            }
        };
        if flags & CLONE_PARENT_SETTID != 0 && ptid != 0 {
            let p = &mut self.procs[parent_idx];
            let mut guard = p.mem.borrow_mut();
            put32(&mut guard, ptid, tid);
        }
        if flags & CLONE_CHILD_SETTID != 0 && ctid != 0 {
            let mut guard = child.mem.borrow_mut();
            put32(&mut guard, ctid, tid);
        }
        self.procs[parent_idx].cpu.r[0] = tid;
        self.procs.push(child);
    }

    /// kill/tkill/tgkill bookkeeping: validate the target, set
    /// the pending bit, write the return value into the sender.
    /// Group signals are anchored on the group leader's pending
    /// word (any unblocked member may take them at delivery).
    fn do_send_signal(&mut self, sender: usize, tgid: u32, tid: Option<u32>, sig: u32) {
        const ESRCH_NEG: u32 = (-3i32) as u32;
        const EINVAL_NEG: u32 = (-22i32) as u32;
        if sig > 64 {
            self.procs[sender].cpu.r[0] = EINVAL_NEG;
            return;
        }
        let target_idx = match tid {
            Some(t) => self.procs.iter().position(|p| p.pid == t),
            None => self.procs.iter().position(|p| p.tgid == tgid),
        };
        let ti = match target_idx {
            Some(i) => i,
            None => {
                self.procs[sender].cpu.r[0] = ESRCH_NEG;
                return;
            }
        };
        self.procs[sender].cpu.r[0] = 0;
        if sig == 0 {
            return; // existence probe only
        }
        let bit = 1u64 << (sig - 1);
        if tid.is_some() {
            self.procs[ti].sys.pending |= bit;
        } else {
            // Group signal: park it on the group's shared
            // pending word; any member thread may consume it
            // (deliver_pending) or wait for it (rt_sigtimedwait).
            self.procs[ti].sys.sighand.borrow_mut().group_pending |= bit;
        }
    }

    /// Deliver one pending, unblocked signal to process `idx`,
    /// if any. Returns Some(sig) when the default action kills
    /// the group; the caller turns that into the group's death.
    /// Frame layout (guest stack, rt_sigframe-shaped):
    ///   +0    siginfo (128 B; signo at +0, code at +8)
    ///   +128  ucontext: flags, link, stack (12 B),
    ///         then mcontext at +148: trap_no, error_code,
    ///         oldmask, r0..r10, fp, ip, sp, lr, pc, cpsr,
    ///         fault_addr (21 words), sigmask at +232.
    ///   total 240 B, 8-aligned.
    fn deliver_pending(&mut self, idx: usize) -> Option<u32> {
        const FRAME: u32 = 240;
        // Group pending lives on the leader (or first member).
        let tgid = self.procs[idx].tgid;
        let anchor = self
            .procs
            .iter()
            .position(|p| p.pid == tgid)
            .unwrap_or(idx);
        let _ = anchor;
        let mut pending = self.procs[idx].sys.pending;
        pending |= self.procs[idx].sys.sighand.borrow().group_pending;
        let mask = self.procs[idx].sys.sig_mask;
        // SIGKILL(9) / SIGSTOP(19) ignore the mask entirely.
        let mut avail = pending & !mask;
        if pending & (1u64 << 8) != 0 {
            avail |= 1u64 << 8;
        }
        if pending & (1u64 << 18) != 0 {
            avail |= 1u64 << 18;
        }
        if avail == 0 {
            return None;
        }
        let sig = avail.trailing_zeros() + 1;
        let bit = 1u64 << (sig - 1);
        // Consume from whichever word held it (own first).
        if self.procs[idx].sys.pending & bit != 0 {
            self.procs[idx].sys.pending &= !bit;
        } else {
            self.procs[idx].sys.sighand.borrow_mut().group_pending &= !bit;
        }
        let action = self.procs[idx].sys.sighand.borrow().actions[sig as usize];
        match action.handler {
            1 => None, // SIG_IGN: silently dropped
            0 => {
                match sig {
                    // Default-ignore set. Stop signals are also
                    // approximated as ignored: there is no stop
                    // state machine yet.
                    17 | 23 | 28 | 19 | 20 | 21 | 22 => None,
                    _ => Some(sig), // default action: terminate
                }
            }
            handler => {
                let p = &mut self.procs[idx];
                let old_mask = p.sys.sig_mask;
                let sp = (p.cpu.r[13] - FRAME) & !7;
                {
                    let mut mem = p.mem.borrow_mut();
                    // siginfo: signo, errno=0, code=0 (SI_USER)
                    put32(&mut mem, sp, sig);
                    put32(&mut mem, sp + 4, 0);
                    put32(&mut mem, sp + 8, 0);
                    // ucontext header: flags/link/stack all zero
                    for off in (128..148).step_by(4) {
                        put32(&mut mem, sp + off, 0);
                    }
                    // mcontext: trap_no, error_code, oldmask
                    put32(&mut mem, sp + 148, 0);
                    put32(&mut mem, sp + 152, 0);
                    put32(&mut mem, sp + 156, 0);
                    for i in 0..11 {
                        put32(&mut mem, sp + 160 + (i as u32) * 4, p.cpu.r[i]);
                    }
                    put32(&mut mem, sp + 204, p.cpu.r[11]); // fp
                    put32(&mut mem, sp + 208, p.cpu.r[12]); // ip
                    put32(&mut mem, sp + 212, p.cpu.r[13]); // sp
                    put32(&mut mem, sp + 216, p.cpu.r[14]); // lr
                    put32(&mut mem, sp + 220, p.cpu.r[15]); // pc
                    let mut cpsr = 0x10u32; // user mode
                    if p.cpu.n {
                        cpsr |= 1 << 31;
                    }
                    if p.cpu.z {
                        cpsr |= 1 << 30;
                    }
                    if p.cpu.c {
                        cpsr |= 1 << 29;
                    }
                    if p.cpu.v {
                        cpsr |= 1 << 28;
                    }
                    if p.cpu.thumb {
                        cpsr |= 1 << 5;
                    }
                    put32(&mut mem, sp + 224, cpsr);
                    put32(&mut mem, sp + 228, 0); // fault_address
                    // uc_sigmask = mask in force before delivery
                    mem.write_u64(sp + 232, old_mask);
                }
                p.cpu.r[13] = sp;
                p.cpu.r[0] = sig;
                p.cpu.r[1] = sp; // &siginfo
                p.cpu.r[2] = sp + 128; // &ucontext
                p.cpu.r[14] = action.restorer;
                p.cpu.r[15] = handler & !1;
                p.cpu.thumb = handler & 1 == 1;
                p.blocks.clear();
                // While the handler runs, its own signal (and
                // the action's mask) stay blocked, unless
                // SA_NODEFER (0x4000_0000).
                let mut m = old_mask | action.mask;
                if action.flags & 0x4000_0000 == 0 {
                    m |= bit;
                }
                p.sys.sig_mask = m & !(1u64 << 8) & !(1u64 << 18);
                None
            }
        }
    }

    /// rt_sigreturn: restore the context saved in the frame at
    /// the current stack pointer (see deliver_pending layout).
    fn do_sigreturn(&mut self, idx: usize) {
        let p = &mut self.procs[idx];
        let sp = p.cpu.r[13];
        let w = |mem: &Mem, off: u32| -> u32 { mem.read_u32(sp + off) };
        let (mut regs, cpsr, saved_mask) = {
            let mem = p.mem.borrow();
            let mut regs = [0u32; 16];
            for i in 0..11 {
                regs[i] = w(&mem, 160 + (i as u32) * 4);
            }
            regs[11] = w(&mem, 204);
            regs[12] = w(&mem, 208);
            regs[13] = w(&mem, 212);
            regs[14] = w(&mem, 216);
            regs[15] = w(&mem, 220);
            let cpsr = w(&mem, 224);
            let saved_mask = mem.read_u64(sp + 232);
            (regs, cpsr, saved_mask)
        };
        p.cpu.r = regs;
        p.cpu.n = cpsr & (1 << 31) != 0;
        p.cpu.z = cpsr & (1 << 30) != 0;
        p.cpu.c = cpsr & (1 << 29) != 0;
        p.cpu.v = cpsr & (1 << 28) != 0;
        p.cpu.thumb = cpsr & (1 << 5) != 0;
        p.sys.sig_mask = saved_mask & !(1u64 << 8) & !(1u64 << 18);
        p.blocks.clear();
    }

    /// exit(1) for one thread. If it was the group's last thread
    /// the whole group ends (finish_group). Returns Some(code)
    /// when the initial group ended and the run is over.
    /// Approximation: a non-last leader that exits is removed
    /// outright; a real kernel keeps it as a zombie until the
    /// group dies, which only matters for exotic wait patterns.
    fn terminate_thread(&mut self, idx: usize, code: u32) -> Option<u32> {
        let tgid = self.procs[idx].tgid;
        let members = self.procs.iter().filter(|p| p.tgid == tgid).count();
        // Clear the tid words (CLONE_CHILD_CLEARTID and
        // set_tid_address): futex waiters re-check them through
        // the WouldBlock re-issue path.
        let (cleartid, tid_addr) = (self.procs[idx].cleartid, self.procs[idx].sys.tid_addr);
        if cleartid != 0 || tid_addr != 0 {
            let mut guard = self.procs[idx].mem.borrow_mut();
            if cleartid != 0 {
                put32(&mut guard, cleartid, 0);
            }
            if tid_addr != 0 {
                put32(&mut guard, tid_addr, 0);
            }
        }
        if members > 1 {
            self.procs.remove(idx);
            None
        } else {
            self.finish_group(idx, code)
        }
    }

    /// End a whole thread group (clean exit): see
    /// finish_group_status.
    fn finish_group(&mut self, idx: usize, code: u32) -> Option<u32> {
        self.finish_group_status(idx, code << 8, code)
    }

    /// End a whole thread group: remove every member, leave a
    /// zombie under the group's parent (keyed by tgid, carrying
    /// `status_word`: exit code << 8, or the signal number for a
    /// signal death), and wake a parent blocked in wait4.
    /// Returns Some(exit_code) when the initial group ended.
    fn finish_group_status(
        &mut self,
        idx: usize,
        status_word: u32,
        exit_code: u32,
    ) -> Option<u32> {
        let tgid = self.procs[idx].tgid;
        let ppid = self.procs[idx].ppid;
        if tgid == 100 {
            return Some(exit_code);
        }
        // Binder: the group's nodes die with it (death
        // notifications and handle cleanup ride along).
        self.procs[idx]
            .sys
            .binder
            .borrow_mut()
            .proc_died(tgid);
        // Turn the caller into the group's zombie shell, drop
        // every other member (remove from the back so indices
        // stay valid).
        self.procs[idx].pid = tgid;
        self.procs[idx].zombie = Some(status_word);
        let others: Vec<usize> = self
            .procs
            .iter()
            .enumerate()
            .filter(|(i, p)| *i != idx && p.tgid == tgid)
            .map(|(i, _)| i)
            .collect();
        for i in others.into_iter().rev() {
            self.procs.remove(i);
        }
        self.wake_parent(tgid);
        // Orphaned zombie (parent already gone): reap.
        if let Some(ci) = self.procs.iter().position(|p| p.pid == tgid && p.zombie.is_some()) {
            if !self.procs.iter().any(|p| p.pid == ppid) {
                self.procs.remove(ci);
            }
        }
        None
    }

    fn do_fork(&mut self, parent_idx: usize) {
        let child_pid = self.next_pid;
        self.next_pid += 1;
        let child = {
            let parent = &self.procs[parent_idx];
            let mut cpu = parent.cpu.clone();
            cpu.r[0] = 0; // fork returns 0 in the child
            Process {
                pid: child_pid,
                ppid: parent.pid,
                tgid: child_pid,
                cpu,
                mem: std::rc::Rc::new(std::cell::RefCell::new(
                    parent.mem.borrow().clone_sparse(),
                )),
                sys: parent.sys.fork_clone(child_pid),
                blocks: std::collections::HashMap::new(),
                zombie: None,
                wait_req: None,
                retry_syscall: false,
                block_streak: 0,
                cleartid: 0,
                blocks_dirty: false,
                binder_wait: false,
            }
        };
        self.procs[parent_idx].cpu.r[0] = child_pid;
        self.procs.push(child);
    }

    /// Try to satisfy a wait4 for procs[idx]. Completes it (r0 =
    /// child pid, or 0 for WNOHANG with living children, or
    /// -ECHILD) or blocks the process until a child exits.
    fn do_wait(&mut self, idx: usize, pid_arg: i32, status_ptr: u32, options: u32) {
        match self.find_zombie_child(idx, pid_arg) {
            Some(child_idx) => {
                let (child_pid, code) = {
                    let c = &self.procs[child_idx];
                    (c.pid, c.zombie.unwrap_or(0))
                };
                self.procs.remove(child_idx);
                self.complete_wait(idx, child_pid, code, status_ptr);
            }
            None => {
                let has_living = self.procs.iter().any(|p| {
                    p.ppid == self.procs[idx].pid
                        && p.zombie.is_none()
                        && (pid_arg == -1 || pid_arg == 0 || p.pid == pid_arg as u32)
                });
                if !has_living {
                    self.procs[idx].cpu.r[0] = ECHILD_NEG;
                } else if options & 1 != 0 {
                    self.procs[idx].cpu.r[0] = 0; // WNOHANG
                } else {
                    self.procs[idx].wait_req = Some((pid_arg, status_ptr, options));
                }
            }
        }
    }

    fn find_zombie_child(&self, idx: usize, pid_arg: i32) -> Option<usize> {
        let parent_pid = self.procs[idx].pid;
        self.procs.iter().position(|p| {
            p.ppid == parent_pid
                && p.zombie.is_some()
                && (pid_arg == -1 || pid_arg == 0 || p.pid == pid_arg as u32)
        })
    }

    fn complete_wait(&mut self, idx: usize, child_pid: u32, code: u32, status_ptr: u32) {
        if status_ptr != 0 {
            let p = &mut self.procs[idx];
            let mut guard = p.mem.borrow_mut();
            put32(&mut guard, status_ptr, code);
        }
        self.procs[idx].cpu.r[0] = child_pid;
        self.procs[idx].wait_req = None;
    }

    /// A process just turned zombie: if its parent is blocked in
    /// a matching wait4, complete that wait now.
    fn wake_parent(&mut self, child_pid: u32) {
        let child_idx = match self.procs.iter().position(|p| p.pid == child_pid) {
            Some(i) => i,
            None => return,
        };
        let (ppid, code) = {
            let c = &self.procs[child_idx];
            (c.ppid, c.zombie.unwrap_or(0))
        };
        let parent_idx = match self.procs.iter().position(|p| p.pid == ppid) {
            Some(i) => i,
            None => return,
        };
        if let Some((pid_arg, status_ptr, _)) = self.procs[parent_idx].wait_req {
            if pid_arg == -1 || pid_arg == 0 || pid_arg as u32 == child_pid {
                self.procs.remove(child_idx);
                self.complete_wait(parent_idx, child_pid, code, status_ptr);
            }
        }
    }
}

/// Sparse memory copy for fork: zero pages are not touched, so a
/// 256MB address space costs only its dirty footprint.

fn dump_mem(mem: &Mem) {
    if let Ok(spec) = std::env::var("PAXCORE_DUMP") {
        // spec: "start-end:path" hex addresses
        let mut it = spec.split(':');
        if let (Some(range), Some(path)) = (it.next(), it.next()) {
            let mut ab = range.split('-');
            let s = u32::from_str_radix(ab.next().unwrap_or("0"), 16).unwrap_or(0) as usize;
            let e = u32::from_str_radix(ab.next().unwrap_or("0"), 16).unwrap_or(0) as usize;
            let mut buf = vec![0u8; e - s];
            mem.read_slice(s as u32, &mut buf);
            let _ = std::fs::write(path, &buf);
        }
    }
}
