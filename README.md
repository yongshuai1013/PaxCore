# PaxCore

A from-scratch ARM user-mode CPU interpreter core, written in Rust
with no dependencies. It emulates the ARM CPU itself (ARM + Thumb,
VFP), and implements the Linux/Android kernel surface in-core:
processes, threads, signals, pipes, futexes, and (in progress) an
in-core binder driver. Unmodified guest binaries run on it.

## Status

- M1: ARM/Thumb instruction set + VFP + syscall surface for a
  static musl busybox — full acceptance ladder green.
- M2: multiprocess core — fork/wait4, execve, pipes, clone
  threads (CLONE_VM), futex, signals with rt-frame delivery and
  sigreturn. All probe-verified.
- JIT: decoded-block cache for ARM code (~24 MIPS on the dev host
  for a busybox seq workload).
- M3 (in progress): dynamic loading (PT_INTERP) and an in-core
  binder, targeting the Android 2.3.7 (Gingerbread) guest booting
  to servicemanager.

## Layout

- `src/` — the core: `cpu.rs` / `thumb.rs` (instruction decode
  and execute), `block.rs` (block cache), `elf.rs` (loader),
  `syscall.rs` + `fs.rs` (kernel surface), `main.rs` (scheduler).
- `guest/` — assembly probes (each with a `.s` source) and the
  test busybox. Probes are built with the NDK clang:
  `clang --target=armv7-none-eabi -march=armv7-a -nostdlib -static`.
- `rootfs/` (not in git) — the busybox test root: `bin/` holds
  copies of the busybox binary under applet names (argv[0]
  dispatch, like a real system's hardlinks), `tmp/in.txt` is the
  standard test file, `proc/self/exe` is a busybox copy.

## Run

```
cargo build --release
./target/release/paxcore guest/busybox sh -c 'seq 3 | wc -l'
```

Environment knobs: `PAXCORE_TRACE`, `PAXCORE_TRACE_AFTER`,
`PAXCORE_MAX_STEPS`, `PAXCORE_WATCH=<hex>`, `PAXCORE_DUMP=a-b:path`,
`PAXCORE_SEED=<hex>`, `PAXCORE_ROOTFS`, `PAXCORE_NOCACHE=1`.

Debug rule used throughout: encodings, struct layouts and
syscall numbers are established by assembler probes and header
evidence before being coded — never from memory.
