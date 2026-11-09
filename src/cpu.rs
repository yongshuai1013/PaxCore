//! ARMv7-A interpreter core (ARM mode subset, M0).
//! Loud failure on unimplemented instructions: the panic message
//! carries pc + raw word, which is exactly the data that drives
//! decoder growth on the next milestone.

use crate::mem::Mem;

pub const REG_SP: usize = 13;
pub const REG_LR: usize = 14;
pub const REG_PC: usize = 15;

pub enum Step {
    Continue,
    Syscall,
}

#[derive(Clone)]
pub struct Cpu {
    pub r: [u32; 16],
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
    pub steps: u64,
    /// CPSR T bit: executing Thumb code.
    pub thumb: bool,
    /// Thread pointer set via the set_tls syscall / MCR p15.
    pub tls: u32,
    /// ITSTATE byte while inside a Thumb IT block (0 = outside).
    pub it: u8,
    /// VFP double registers d0..d31 (s-regs alias halves).
    pub d: [u64; 32],
    /// VFP status register (NZCV live in the cpu flags after VCMP
    /// + VMRS; the stored copy is what VMRS/VMSR move).
    pub fpscr: u32,
    /// PAXCORE_TRACE switch, read once at construction. Reading
    /// the environment on every step cost a measurable slice of
    /// the interpreter's per-instruction budget.
    pub trace: bool,
    /// PAXCORE_TRACE_AFTER threshold, read once at construction.
    pub trace_after: u64,
    /// PAXCORE_WATCHPC=<hex>[,<hex>]: dump registers whenever the PC
    /// reaches one of these addresses.
    pub watch_pc: Option<u32>,
    pub watch_pc2: Option<u32>,
}

impl Cpu {
    pub fn new(entry: u32, sp: u32) -> Cpu {
        let mut cpu = Cpu {
            r: [0; 16],
            n: false,
            z: false,
            c: false,
            v: false,
            steps: 0,
            thumb: false,
            tls: 0,
            it: 0,
            d: [0; 32],
            fpscr: 0,
            trace: std::env::var_os("PAXCORE_TRACE").is_some(),
            trace_after: std::env::var("PAXCORE_TRACE_AFTER")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            watch_pc: std::env::var("PAXCORE_WATCHPC")
                .ok()
                .and_then(|v| {
                    v.split(',')
                        .filter_map(|p| u32::from_str_radix(p.trim().trim_start_matches("0x"), 16).ok())
                        .next()
                })
                .or_else(|| None),
            watch_pc2: std::env::var("PAXCORE_WATCHPC")
                .ok()
                .and_then(|v| {
                    v.split(',')
                        .filter_map(|p| u32::from_str_radix(p.trim().trim_start_matches("0x"), 16).ok())
                        .nth(1)
                }),
        };
        cpu.r[REG_PC] = entry;
        cpu.r[REG_SP] = sp;
        cpu
    }

    pub fn pc(&self) -> u32 {
        self.r[REG_PC]
    }

    pub(crate) fn cond_ok(&self, cond: u32) -> bool {
        match cond {
            0x0 => self.z,
            0x1 => !self.z,
            0x2 => self.c,
            0x3 => !self.c,
            0x4 => self.n,
            0x5 => !self.n,
            0x6 => self.v,
            0x7 => !self.v,
            0x8 => self.c && !self.z,
            0x9 => !self.c || self.z,
            0xA => self.n == self.v,
            0xB => self.n != self.v,
            0xC => !self.z && (self.n == self.v),
            0xD => self.z || (self.n != self.v),
            0xE => true,
            _ => false, // 0xF: NV, treated as never in ARMv7
        }
    }

    pub(crate) fn set_nz(&mut self, val: u32) {
        self.n = val & 0x8000_0000 != 0;
        self.z = val == 0;
    }

    pub(crate) fn add_with_flags(&mut self, a: u32, b: u32, carry_in: u32, set: bool) -> u32 {
        let sum = a as u64 + b as u64 + carry_in as u64;
        let res = sum as u32;
        if set {
            self.set_nz(res);
            self.c = sum >> 32 != 0;
            self.v = (!(a ^ b) & (a ^ res)) & 0x8000_0000 != 0;
        }
        res
    }

    pub(crate) fn sub_with_flags(&mut self, a: u32, b: u32, carry_in: u32, set: bool) -> u32 {
        // ARM subtraction: a + ~b + carry_in (carry_in=1 means no borrow)
        let sum = a as u64 + (!b) as u64 + carry_in as u64;
        let res = sum as u32;
        if set {
            self.set_nz(res);
            self.c = sum >> 32 != 0;
            self.v = ((a ^ b) & (a ^ res)) & 0x8000_0000 != 0;
        }
        res
    }

    /// Barrel shifter for register operand2 with immediate shift.
    /// Returns (value, carry_out).
    pub(crate) fn shift_reg(&self, val: u32, typ: u32, amount: u32) -> (u32, bool) {
        match typ {
            0 => {
                // LSL
                if amount == 0 {
                    (val, self.c)
                } else if amount < 32 {
                    (val << amount, (val >> (32 - amount)) & 1 != 0)
                } else if amount == 32 {
                    (0, val & 1 != 0)
                } else {
                    (0, false)
                }
            }
            1 => {
                // LSR (amount 0 encodes 32)
                let amt = if amount == 0 { 32 } else { amount };
                if amt < 32 {
                    (val >> amt, (val >> (amt - 1)) & 1 != 0)
                } else if amt == 32 {
                    (0, val & 0x8000_0000 != 0)
                } else {
                    (0, false)
                }
            }
            2 => {
                // ASR (amount 0 encodes 32)
                let amt = if amount == 0 { 32 } else { amount };
                if amt >= 32 {
                    let sign = val & 0x8000_0000 != 0;
                    (if sign { 0xffff_ffff } else { 0 }, sign)
                } else {
                    (((val as i32) >> amt) as u32, (val >> (amt - 1)) & 1 != 0)
                }
            }
            _ => {
                // ROR (amount 0 encodes RRX)
                if amount == 0 {
                    let out = ((self.c as u32) << 31) | (val >> 1);
                    (out, val & 1 != 0)
                } else {
                    let amt = amount & 31;
                    if amt == 0 {
                        (val, val & 0x8000_0000 != 0)
                    } else {
                        (val.rotate_right(amt), (val >> (amt - 1)) & 1 != 0)
                    }
                }
            }
        }
    }
}

impl Cpu {
    pub(crate) fn rd(&self, mem: &Mem, addr: u32) -> u32 {
        mem.read_u32(addr)
    }
    pub(crate) fn wr(&self, mem: &mut Mem, addr: u32, val: u32) {
        mem.write_u32(addr, val);
    }
    pub(crate) fn rd8(&self, mem: &Mem, addr: u32) -> u32 {
        mem.byte(addr) as u32
    }
    pub(crate) fn wr8(&self, mem: &mut Mem, addr: u32, val: u32) {
        mem.set_byte(addr, val as u8);
    }

    /// Interworking jump: a data value written to PC selects
    /// the instruction set by bit 0 (ARMv7 semantics for LDR/MOV/
    /// LDM to PC). Storing the raw odd value instead once made
    /// the GB linker's PLT veneers execute Thumb code as ARM.
    pub(crate) fn jump_to(&mut self, val: u32) {
        self.thumb = val & 1 == 1;
        self.r[REG_PC] = val & !1;
    }

    pub(crate) fn unimp(&self, word: u32) -> ! {
        panic!(
            "unimplemented instruction 0x{word:08x} at pc=0x{:08x} (after {} steps)",
            self.r[REG_PC],
            self.steps
        );
    }

    /// Execute one instruction. Guest memory is bounds-checked by
    /// slice indexing; a bad access panics with the address context
    /// added by the caller.
    pub fn step(&mut self, mem: &mut Mem) -> Step {
        if self.thumb {
            return self.step_thumb(mem);
        }
        let pc = self.r[REG_PC];
        if let Some(out) = self.kuser_call(mem, pc) {
            return out;
        }
        let word = self.rd(mem, pc);
        self.steps += 1;
        if self.watch_pc == Some(pc) || self.watch_pc2 == Some(pc) {
            eprintln!(
                "[watchpc] steps={} pc=0x{pc:08x} r0={:#010x} r1={:#010x} r2={:#010x} r3={:#010x} r4={:#010x} r5={:#010x} r6={:#010x} r7={:#010x} r8={:#010x} r9={:#010x} r10={:#010x} r11={:#010x} r12={:#010x} sp={:#010x} lr={:#010x} nzcv={}{}{}{}",
                self.steps,
                self.r[0], self.r[1], self.r[2], self.r[3], self.r[4], self.r[5],
                self.r[6], self.r[7], self.r[8], self.r[9], self.r[10], self.r[11], self.r[12],
                self.r[13], self.r[14],
                self.n as u8, self.z as u8, self.c as u8, self.v as u8
            );
        }
        if self.trace && self.steps >= self.trace_after {
            eprintln!("[trace] A pc=0x{pc:08x} w=0x{word:08x} r0=0x{:08x} r1=0x{:08x} r3=0x{:08x} r4=0x{:08x} sp=0x{:08x} lr=0x{:08x}", self.r[0], self.r[1], self.r[3], self.r[4], self.r[13], self.r[14]);
        }
        let next_pc = pc.wrapping_add(4);
        // BLX immediate: 1111 101 H imm24 -- unconditional,
        // always switches to Thumb. The cond==0xF space must be
        // claimed before the generic cond check drops it.
        if word & 0xFE00_0000 == 0xFA00_0000 {
            let h = ((word >> 24) & 1) as u32;
            let imm24 = (word & 0x00FF_FFFF) as i32;
            let signed = (imm24 << 8) >> 8;
            self.r[REG_LR] = next_pc;
            let target = (pc as i32)
                .wrapping_add(8)
                .wrapping_add(signed.wrapping_mul(4))
                .wrapping_add((h << 1) as i32) as u32;
            self.r[REG_PC] = target & !1;
            self.thumb = true;
            return Step::Continue;
        }
        let cond = word >> 28;
        if cond != 0xE && !self.cond_ok(cond) {
            self.r[REG_PC] = next_pc;
            return Step::Continue;
        }
        // SVC (any cond): bits 27-24 == 1111
        if (word >> 24) & 0xF == 0xF {
            self.r[REG_PC] = next_pc;
            return Step::Syscall;
        }
        // Branch / branch-link: bits 27-25 == 101
        if (word >> 25) & 0x7 == 0x5 {
            let link = (word >> 24) & 1 == 1;
            let imm24 = (word & 0x00ff_ffff) as i32;
            let signed = (imm24 << 8) >> 8;
            if link {
                self.r[REG_LR] = next_pc;
            }
            self.r[REG_PC] = (pc as i64 + 8 + (signed as i64) * 4) as u32;
            return Step::Continue;
        }
        // Block data transfer: bits 27-25 == 100
        if (word >> 25) & 0x7 == 0x4 {
            let pre = (word >> 24) & 1 == 1;
            let up = (word >> 23) & 1 == 1;
            let wback = (word >> 21) & 1 == 1;
            let load = (word >> 20) & 1 == 1;
            let rn = ((word >> 16) & 0xF) as usize;
            let list = word & 0xFFFF;
            let count = list.count_ones() as u32;
            let base = self.r[rn];
            let start = if up {
                if pre { base.wrapping_add(4) } else { base }
            } else if pre {
                base.wrapping_sub(count * 4)
            } else {
                base.wrapping_sub(count * 4).wrapping_add(4)
            };
            let mut addr = start;
            let mut loaded_pc: Option<u32> = None;
            for i in 0..16 {
                if list & (1 << i) == 0 {
                    continue;
                }
                if load {
                    let val = self.rd(mem, addr);
                    if i == REG_PC {
                        loaded_pc = Some(val);
                    } else {
                        self.r[i] = val;
                    }
                } else {
                    let val = if i == REG_PC { pc + 12 } else { self.r[i] };
                    self.wr(mem, addr, val);
                }
                addr = addr.wrapping_add(4);
            }
            if wback {
                self.r[rn] = if up {
                    base.wrapping_add(count * 4)
                } else {
                    base.wrapping_sub(count * 4)
                };
            }
            match loaded_pc {
                Some(v) => self.jump_to(v),
                None => self.r[REG_PC] = next_pc,
            }
            return Step::Continue;
        }
        // Sign/zero extend family (UXTB/SXTH/...): bits 27-20 in
        // {68,6A,6B,6C,6E,6F}, bits 7-4 == 0111, bits 9-8 == 00.
        {
            let top8 = (word >> 20) & 0xFF;
            if matches!(top8, 0x68 | 0x6A | 0x6B | 0x6C | 0x6E | 0x6F)
                && (word >> 4) & 0xF == 0x7
                && (word >> 8) & 0x3 == 0
            {
                let zero = (word >> 22) & 1 == 1;
                let typ = (word >> 20) & 0x3;
                let rn = ((word >> 16) & 0xF) as usize;
                let rd = ((word >> 12) & 0xF) as usize;
                let rot = ((word >> 10) & 0x3) * 8;
                let rm = (word & 0xF) as usize;
                let v = self.r[rm].rotate_right(rot);
                let ext = |b: u32| -> u32 {
                    if zero { b } else { b as u8 as i8 as u32 }
                };
                let extracted = match typ {
                    0 => {
                        // B16: two bytes into two halfwords
                        let lo = if zero {
                            v & 0xFF
                        } else {
                            (v as u8 as i8 as u32) & 0xFFFF
                        };
                        let hi = if zero {
                            (v >> 16) & 0xFF
                        } else {
                            ((v >> 16) as u8 as i8 as u32) & 0xFFFF
                        };
                        lo | (hi << 16)
                    }
                    2 => ext(v & 0xFF),
                    3 => {
                        if zero {
                            v & 0xFFFF
                        } else {
                            v as u16 as i16 as u32
                        }
                    }
                    _ => self.unimp(word),
                };
                self.r[rd] = if rn == 15 || typ == 0 {
                    extracted
                } else {
                    self.r[rn].wrapping_add(extracted)
                };
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // Bitfield family (SBFX/BFC+BFI/UBFX): bits 27-21 ==
        // 0111101 / 0111110 / 0111111. Must precede the SDT
        // decode: these live in the same bits 27-25 == 011 space
        // but have bit 4 set, which SDT never does. The gate
        // must NOT include bit 20: it is the top bit of the
        // width/msb field, so gating on bits 27-20 (0x7A/0x7C/
        // 0x7E only) let every encoding with width/msb >= 16
        // fall through to the SDT decode -- zlib's
        // `bfi r12, r0, #16, #16` (msb=31) became a stray LDRB
        // and silently corrupted the values it packed, which
        // surfaced as "invalid literal/lengths set" from
        // inflate and GB dalvikvm being unable to load any
        // deflated jar.
        {
            let top7 = (word >> 21) & 0x7F;
            if matches!(top7, 0x3D | 0x3E | 0x3F) && (word >> 4) & 0x3 == 0x1 {
                let top8 = top7 << 1;
                // Field layout (probe-verified, 0xE7EA0A57 ==
                // ubfx r0, r7, #20, #11): bits 19-16 hold
                // width-1 for SBFX/UBFX and msb for BFC/BFI,
                // Rd = bits 15-12, lsb = bits 11-7, and Rn lives
                // in bits 3-0. The previous decode read Rn from
                // bits 19-16, so UBFX extracted from the wrong
                // register (usually r10 == 0) and returned 0;
                // that single field swap is what wedged musl's
                // dtoa recursion (biased-exponent extraction).
                let rn = (word & 0xF) as usize;
                let rd = ((word >> 12) & 0xF) as usize;
                let lsb = (word >> 7) & 0x1F;
                match top8 {
                    0x7E => {
                        // UBFX
                        let width = ((word >> 16) & 0x1F) + 1;
                        let mask = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };
                        let src = if rn == REG_PC { pc + 8 } else { self.r[rn] };
                        self.r[rd] = (src >> lsb) & mask;
                    }
                    0x7A => {
                        // SBFX
                        let width = ((word >> 16) & 0x1F) + 1;
                        let src = if rn == REG_PC { pc + 8 } else { self.r[rn] };
                        let shifted = (src >> lsb) << (32 - width);
                        self.r[rd] = ((shifted as i32) >> (32 - width)) as u32;
                    }
                    _ => {
                        // BFC (Rn == 1111) / BFI
                        let msb = ((word >> 16) & 0x1F) as u32;
                        let width = msb - lsb + 1;
                        let mask = ((1u32 << width) - 1) << lsb;
                        let ins = if rn == 15 {
                            0
                        } else {
                            (self.r[rn] << lsb) & mask
                        };
                        self.r[rd] = (self.r[rd] & !mask) | ins;
                    }
                }
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // SDIV / UDIV (ARMv7 divide extension): bits 27-20
        // == 0x71 (SDIV) or 0x73 (UDIV), bits 15-12 == 0xF,
        // bits 7-4 == 0x1. The register fields use the
        // media-space layout, NOT the data-processing one
        // (assembler-verified: sdiv r3, r5, r9 ==
        // 0xE713F915): Rd = bits 19-16, Rm = bits 11-8,
        // Rn = bits 3-0. Rd = Rn / Rm truncating toward
        // zero; division by zero yields 0 and INT_MIN / -1
        // wraps (no trap). GB's ARM-compiled libraries use
        // these in fixed-point paths (FreeType inside
        // libskia among them); before this arm existed the
        // encoding fell into an earlier load/store handler
        // and silently derailed execution into zero memory:
        // core bug #13.
        {
            let top8 = (word >> 20) & 0xFF;
            if (top8 == 0x71 || top8 == 0x73)
                && (word >> 12) & 0xF == 0xF
                && (word >> 4) & 0xF == 0x1
            {
                let rd = ((word >> 16) & 0xF) as usize;
                let rm = ((word >> 8) & 0xF) as usize;
                let rn = (word & 0xF) as usize;
                let a = if rn == REG_PC { pc + 8 } else { self.r[rn] };
                let b = if rm == REG_PC { pc + 8 } else { self.r[rm] };
                let r = if top8 == 0x71 {
                    let (a, b) = (a as i32, b as i32);
                    if b == 0 {
                        0
                    } else {
                        a.wrapping_div(b) as u32
                    }
                } else if b == 0 {
                    0
                } else {
                    a / b
                };
                self.r[rd] = r;
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // Signed DSP multiplies (ARMv5TE): bits 27-24 == 0001,
        // bits 7-4 == 1 <rs-half> <rm-half> 0. Field layout is
        // media-style: Rd = bits 19-16, Rn/RdLo = bits 15-12,
        // Rs = bits 11-8, Rm = bits 3-0; bit 6 picks Rs's half
        // (1 = top), bit 5 picks Rm's half. bits 23-20 select:
        // 0000 SMLAxy, 0110 SMULxy, 0100 SMLALxy, and 0010 the
        // word forms -- SMULWy when bit 5 is set, SMLAWy when
        // clear (all encodings assembler-verified). These fail
        // the classic multiply gate below (bit 4 clear) and used
        // to fall through every handler into the step tail, which
        // silently skipped them -- core bug #14: FreeType's
        // af_glyph_hints_reload computes the contour end pointer
        // with `smulbb` (contours[0] * sizeof(AF_Point)); the
        // skipped multiply left a stale register in the sum, the
        // `point == end` test never fired, the last outline
        // point's ->next was never written, and the hinting walk
        // over the point list ran off its end and spun forever.
        {
            let top8 = (word >> 20) & 0xFF;
            let is_dsp = (word >> 7) & 1 == 1
                && (word >> 4) & 1 == 0
                && matches!(top8, 0x10 | 0x12 | 0x14 | 0x16);
            if is_dsp {
                let rd = ((word >> 16) & 0xF) as usize;
                let rn = ((word >> 12) & 0xF) as usize;
                let rs = ((word >> 8) & 0xF) as usize;
                let rm = (word & 0xF) as usize;
                let rm_top = (word >> 5) & 1 == 1;
                let rs_top = (word >> 6) & 1 == 1;
                let get = |i: usize| -> u32 {
                    if i == REG_PC { pc.wrapping_add(8) } else { self.r[i] }
                };
                let half = |v: u32, top: bool| -> i64 {
                    (if top { (v >> 16) as u16 } else { v as u16 } as i16) as i64
                };
                match top8 {
                    0x10 => {
                        // SMLAxy
                        let p = half(get(rm), rm_top) * half(get(rs), rs_top);
                        self.r[rd] = get(rn).wrapping_add(p as u32);
                    }
                    0x16 => {
                        // SMULxy
                        let p = half(get(rm), rm_top) * half(get(rs), rs_top);
                        self.r[rd] = p as u32;
                    }
                    0x14 => {
                        // SMLALxy: RdHi:RdLo += hx(Rm) * hy(Rs)
                        let p = half(get(rm), rm_top) * half(get(rs), rs_top);
                        let acc = (((get(rd) as u64) << 32) | get(rn) as u64) as i64;
                        let res = acc.wrapping_add(p) as u64;
                        self.r[rn] = res as u32;
                        self.r[rd] = (res >> 32) as u32;
                    }
                    _ => {
                        // 0x12: word forms; Rs half from bit 6
                        let p = (get(rm) as i32 as i64) * half(get(rs), rs_top);
                        if rm_top {
                            // SMULWy (bit 5 set marks the
                            // no-accumulate form)
                            self.r[rd] = (p >> 16) as u32;
                        } else {
                            // SMLAWy
                            self.r[rd] = get(rn).wrapping_add((p >> 16) as u32);
                        }
                    }
                }
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // Single data transfer: bits 27-26 == 01
        if (word >> 26) & 0x3 == 0x1 {
            let pre = (word >> 24) & 1 == 1;
            let up = (word >> 23) & 1 == 1;
            let byte = (word >> 22) & 1 == 1;
            let wback = (word >> 21) & 1 == 1 || !pre;
            let load = (word >> 20) & 1 == 1;
            let rn = ((word >> 16) & 0xF) as usize;
            let rd = ((word >> 12) & 0xF) as usize;
            let off = if (word >> 25) & 1 == 1 {
                // Register offset: Rm shifted by imm5/type (bits 11-4)
                let rm = (word & 0xF) as usize;
                let imm5 = (word >> 7) & 0x1F;
                let typ = (word >> 5) & 0x3;
                let raw = if rm == REG_PC { pc + 8 } else { self.r[rm] };
                self.shift_reg(raw, typ, imm5).0
            } else {
                word & 0xFFF
            };
            let base = if rn == REG_PC { pc + 8 } else { self.r[rn] };
            let eff = if pre {
                if up { base.wrapping_add(off) } else { base.wrapping_sub(off) }
            } else {
                base
            };
            let mut jumped = false;
            if load {
                let val = if byte { self.rd8(mem, eff) } else { self.rd(mem, eff) };
                if rd == REG_PC {
                    self.jump_to(val);
                    jumped = true;
                } else {
                    self.r[rd] = val;
                }
            } else {
                let val = if rd == REG_PC { pc + 12 } else { self.r[rd] };
                if byte {
                    self.wr8(mem, eff, val);
                } else {
                    self.wr(mem, eff, val);
                }
            }
            if wback && !(load && rd == rn) {
                self.r[rn] = if pre {
                    eff
                } else if up {
                    base.wrapping_add(off)
                } else {
                    base.wrapping_sub(off)
                };
            }
            if !jumped {
                self.r[REG_PC] = next_pc;
            }
            return Step::Continue;
        }
        // Load/store exclusive (LDREX/STREX family): bits 27-20
        // in 0x18..=0x1F, bits 7-4 == 1001. Single-threaded guest:
        // the monitor is always ours, stores always succeed.
        {
            let top8 = (word >> 20) & 0xFF;
            if (0x18..=0x1F).contains(&top8) && (word & 0xF0) == 0x90 {
                let rn = ((word >> 16) & 0xF) as usize;
                let rd = ((word >> 12) & 0xF) as usize;
                let rm = (word & 0xF) as usize;
                let addr = if rn == REG_PC { pc + 8 } else { self.r[rn] };
                match top8 {
                    0x19 => self.r[rd] = self.rd(mem, addr), // LDREX
                    0x1D => self.r[rd] = self.rd8(mem, addr), // LDREXB
                    0x1F => {
                        // LDREXH
                        let a = addr as usize;
                        self.r[rd] = mem.read_u16(a as u32) as u32;
                    }
                    0x1B => {
                        // LDREXD
                        self.r[rd] = self.rd(mem, addr);
                        if rd + 1 < 16 {
                            self.r[rd + 1] = self.rd(mem, addr.wrapping_add(4));
                        }
                    }
                    0x18 => {
                        // STREX: Rd is the status register
                        self.wr(mem, addr, self.r[rm]);
                        self.r[rd] = 0;
                    }
                    0x1C => {
                        self.wr8(mem, addr, self.r[rm]);
                        self.r[rd] = 0;
                    }
                    0x1E => {
                        let a = addr as usize;
                        let v = self.r[rm] as u16;
                        mem.write_u16(a as u32, v);
                        self.r[rd] = 0;
                    }
                    _ => {
                        // STREXD: Rm, Rm+1
                        self.wr(mem, addr, self.r[rm]);
                        if rm + 1 < 16 {
                            self.wr(mem, addr.wrapping_add(4), self.r[rm + 1]);
                        }
                        self.r[rd] = 0;
                    }
                }
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // Multiply + extra load/store space: bits 27-26 == 00,
        // bit25 == 0, bit7 & bit4 both set.
        if (word >> 26) & 0x3 == 0x0
            && (word >> 25) & 1 == 0
            && word & 0x0000_0090 == 0x0000_0090
        {
            self.exec_multiply_extra(mem, word);
            return Step::Continue;
        }
        // Misc space inside bits 27-26 == 00: CLZ / MRS / MSR /
        // coprocessor thread-pointer access.
        if (word >> 26) & 0x3 == 0x0 || (word >> 26) & 0x3 == 0x3 {
            if self.try_misc(mem, word) {
                return Step::Continue;
            }
        }
        // VFP (coprocessor 10/11 space).
        if self.exec_vfp(mem, word) {
            return Step::Continue;
        }
        // MOVW / MOVT: bits 27-20 == 00110000 / 00110100,
        // imm16 = imm4(bits 19-16) : imm12(bits 11-0).
        {
            let top8 = (word >> 20) & 0xFF;
            if top8 == 0x30 || top8 == 0x34 {
                let imm16 = (((word >> 16) & 0xF) << 12) | (word & 0xFFF);
                let rd = ((word >> 12) & 0xF) as usize;
                if top8 == 0x30 {
                    self.r[rd] = imm16;
                } else {
                    self.r[rd] = (self.r[rd] & 0xFFFF) | (imm16 << 16);
                }
                self.r[REG_PC] = next_pc;
                return Step::Continue;
            }
        }
        // Data processing: bits 27-26 == 00
        if (word >> 26) & 0x3 == 0x0 {
            let imm = (word >> 25) & 1 == 1;
            let opcode = (word >> 21) & 0xF;
            let setflags = (word >> 20) & 1 == 1;
            let rn = ((word >> 16) & 0xF) as usize;
            let rd = ((word >> 12) & 0xF) as usize;
            let a = if rn == REG_PC { pc + 8 } else { self.r[rn] };
            let (b, sh_carry) = if imm {
                let imm8 = (word & 0xFF) as u32;
                let rot = ((word >> 8) & 0xF) * 2;
                if rot == 0 {
                    (imm8, self.c)
                } else {
                    (imm8.rotate_right(rot), imm8.rotate_right(rot) & 0x8000_0000 != 0)
                }
            } else {
                let rm = (word & 0xF) as usize;
                let raw = if rm == REG_PC { pc + 8 } else { self.r[rm] };
                let typ = (word >> 5) & 0x3;
                if (word >> 4) & 1 == 1 {
                    // Register-specified shift: amount is Rs[7:0];
                    // zero means no shift at all (unlike imm form).
                    let rs = ((word >> 8) & 0xF) as usize;
                    let amount = self.r[rs] & 0xFF;
                    self.shift_reg_regform(raw, typ, amount)
                } else {
                    let amount = (word >> 7) & 0x1F;
                    self.shift_reg(raw, typ, amount)
                }
            };
            let test_op = matches!(opcode, 0x8 | 0x9 | 0xA | 0xB);
            let set = setflags || test_op;
            let mut jumped = false;
            let result = match opcode {
                0x0 => { let r = a & b; if set { self.set_nz(r); self.c = sh_carry; } r } // AND
                0x1 => { let r = a ^ b; if set { self.set_nz(r); self.c = sh_carry; } r } // EOR
                0x2 => self.sub_with_flags(a, b, 1, set),                                // SUB
                0x3 => self.sub_with_flags(b, a, 1, set),                                // RSB
                0x4 => self.add_with_flags(a, b, 0, set),                                // ADD
                0x5 => self.add_with_flags(a, b, self.c as u32, set),                    // ADC
                0x6 => self.sub_with_flags(a, b, self.c as u32, set),                    // SBC
                0x7 => self.sub_with_flags(b, a, self.c as u32, set),                    // RSC
                0x8 => { let r = a & b; if set { self.set_nz(r); self.c = sh_carry; } r } // TST
                0x9 => { let r = a ^ b; if set { self.set_nz(r); self.c = sh_carry; } r } // TEQ
                0xA => { self.sub_with_flags(a, b, 1, true); 0 }                         // CMP
                0xB => { self.add_with_flags(a, b, 0, true); 0 }                         // CMN
                0xC => { let r = a | b; if set { self.set_nz(r); self.c = sh_carry; } r } // ORR
                0xD => { let r = b; if set { self.set_nz(r); self.c = sh_carry; } r }     // MOV
                0xE => { let r = a & !b; if set { self.set_nz(r); self.c = sh_carry; } r } // BIC
                _ => { let r = !b; if set { self.set_nz(r); self.c = sh_carry; } r }      // MVN
            };
            if !test_op {
                if rd == REG_PC {
                    self.jump_to(result);
                    jumped = true;
                } else {
                    self.r[rd] = result;
                }
            }
            if !jumped {
                self.r[REG_PC] = next_pc;
            }
            return Step::Continue;
        }
        self.unimp(word);
    }
}

impl Cpu {
    /// Register-form barrel shift: amount 0 = no shift; LSL/LSR/ASR
    /// saturate per the architecture for amounts >= 32.
    pub fn shift_reg_regform(&self, val: u32, typ: u32, amount: u32) -> (u32, bool) {
        if amount == 0 {
            return (val, self.c);
        }
        match typ {
            0 => {
                if amount < 32 {
                    (val << amount, (val >> (32 - amount)) & 1 != 0)
                } else if amount == 32 {
                    (0, val & 1 != 0)
                } else {
                    (0, false)
                }
            }
            1 => {
                if amount < 32 {
                    (val >> amount, (val >> (amount - 1)) & 1 != 0)
                } else if amount == 32 {
                    (0, val & 0x8000_0000 != 0)
                } else {
                    (0, false)
                }
            }
            2 => {
                if amount < 32 {
                    (((val as i32) >> amount) as u32, (val >> (amount - 1)) & 1 != 0)
                } else {
                    let sign = val & 0x8000_0000 != 0;
                    (if sign { 0xffff_ffff } else { 0 }, sign)
                }
            }
            _ => {
                let amt = amount & 31;
                if amt == 0 {
                    (val, val & 0x8000_0000 != 0)
                } else {
                    (val.rotate_right(amt), (val >> (amt - 1)) & 1 != 0)
                }
            }
        }
    }

    /// Multiply family + extra (halfword / signed) load-store.
    /// Entered with pc still pointing at the instruction.
    fn exec_multiply_extra(&mut self, mem: &mut Mem, word: u32) {
        let pc = self.r[REG_PC];
        let next_pc = pc.wrapping_add(4);
        // Discriminator inside this space: bits 6-5 == 00 means
        // multiply (or SWP when bits 27-24 == 0001); bits 6-5 != 00
        // means an extra (halfword / signed) load-store.
        let op_hi = (word >> 24) & 0xF;
        let mid = (word >> 20) & 0xF;
        if op_hi == 0x1 && (word >> 5) & 0x3 == 0 {
            self.unimp(word); // SWP/SWPB: not yet
        }
        if op_hi == 0x0 && (word >> 5) & 0x3 == 0 {
            // Multiply / long multiply: bits 23-20 select the op.
            let rd = ((word >> 16) & 0xF) as usize;
            let rn = ((word >> 12) & 0xF) as usize;
            let rs = ((word >> 8) & 0xF) as usize;
            let rm = (word & 0xF) as usize;
            let set = (word >> 20) & 1 == 1;
            match mid {
                0x0 | 0x1 => {
                    // MUL
                    let res = self.r[rm].wrapping_mul(self.r[rs]);
                    self.r[rd] = res;
                    if set { self.set_nz(res); }
                }
                0x2 | 0x3 => {
                    // MLA
                    let res = self.r[rm]
                        .wrapping_mul(self.r[rs])
                        .wrapping_add(self.r[rn]);
                    self.r[rd] = res;
                    if set { self.set_nz(res); }
                }
                0x4 => {
                    // UMAAL: RdHi:RdLo = Rm*Rs + RdHi + RdLo
                    let res = (self.r[rm] as u64) * (self.r[rs] as u64)
                        + self.r[rd] as u64
                        + self.r[rn] as u64;
                    self.r[rn] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                }
                0x6 | 0x7 => {
                    // MLS
                    let res = self.r[rn]
                        .wrapping_sub(self.r[rm].wrapping_mul(self.r[rs]));
                    self.r[rd] = res;
                    if set { self.set_nz(res); }
                }
                0x8 | 0x9 => {
                    // UMULL: Rd=rn field is RdLo, rd field is RdHi
                    let res = (self.r[rm] as u64) * (self.r[rs] as u64);
                    self.r[rn] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                    if set { self.set_nz(res as u32 | ((res >> 32) as u32)); self.z = res == 0; self.n = (res >> 63) != 0; }
                }
                0xA | 0xB => {
                    // UMLAL
                    let acc = ((self.r[rd] as u64) << 32) | self.r[rn] as u64;
                    let res = acc + (self.r[rm] as u64) * (self.r[rs] as u64);
                    self.r[rn] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                    if set { self.z = res == 0; self.n = (res >> 63) != 0; }
                }
                0xC | 0xD => {
                    // SMULL
                    let res = (self.r[rm] as i32 as i64) * (self.r[rs] as i32 as i64);
                    let res = res as u64;
                    self.r[rn] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                    if set { self.z = res == 0; self.n = (res >> 63) != 0; }
                }
                0xE | 0xF => {
                    // SMLAL
                    let acc = (((self.r[rd] as u64) << 32) | self.r[rn] as u64) as i64;
                    let res = (acc + (self.r[rm] as i32 as i64) * (self.r[rs] as i32 as i64)) as u64;
                    self.r[rn] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                    if set { self.z = res == 0; self.n = (res >> 63) != 0; }
                }
                _ => self.unimp(word),
            }
            self.r[REG_PC] = next_pc;
            return;
        }
        // Extra load/store: LDRH/STRH/LDRSB/LDRSH.
        let pre = (word >> 24) & 1 == 1;
        let up = (word >> 23) & 1 == 1;
        let imm_off = (word >> 22) & 1 == 1;
        let wback = (word >> 21) & 1 == 1 || !pre;
        let load = (word >> 20) & 1 == 1;
        let rn = ((word >> 16) & 0xF) as usize;
        let rd = ((word >> 12) & 0xF) as usize;
        let kind = (word >> 5) & 0x3; // 1=half, 2=signed byte, 3=signed half
        let off = if imm_off {
            (((word >> 8) & 0xF) << 4) | (word & 0xF)
        } else {
            self.r[(word & 0xF) as usize]
        };
        let base = if rn == REG_PC { pc + 8 } else { self.r[rn] };
        let eff = if pre {
            if up { base.wrapping_add(off) } else { base.wrapping_sub(off) }
        } else {
            base
        };
        if kind == 0 {
            self.unimp(word);
        }
        // Double-word transfers hide in the signed slots:
        // kind 2 + L=0 is LDRD, kind 3 + L=0 is STRD.
        if kind == 2 && !load {
            let lo = self.rd(mem, eff);
            let hi = self.rd(mem, eff.wrapping_add(4));
            self.r[rd] = lo;
            if rd + 1 < 16 {
                self.r[rd + 1] = hi;
            }
        } else if kind == 3 && !load {
            let lo = self.r[rd];
            let hi = if rd + 1 < 16 { self.r[rd + 1] } else { 0 };
            self.wr(mem, eff, lo);
            self.wr(mem, eff.wrapping_add(4), hi);
        } else if load {
            let val = match kind {
                1 => {
                    let a = eff as usize;
                    mem.read_u16(a as u32) as u32
                }
                2 => mem.byte(eff) as i8 as u32,
                _ => {
                    let a = eff as usize;
                    (mem.read_u16(a as u32) as i16) as u32
                }
            };
            self.r[rd] = val;
        } else {
            if kind != 1 {
                self.unimp(word); // only STRH stores exist here
            }
            let a = eff as usize;
            let v = self.r[rd] as u16;
            mem.write_u16(a as u32, v);
        }
        if wback {
            self.r[rn] = if pre {
                eff
            } else if up {
                base.wrapping_add(off)
            } else {
                base.wrapping_sub(off)
            };
        }
        self.r[REG_PC] = next_pc;
    }

    /// Misc space: BX/BLX register, CLZ, MRS/MSR, coprocessor
    /// The kernel's kuser helper page (0xFFFF0000): fixed ARM
    /// routines the C library calls directly. They are kernel
    /// surface, so the core implements their semantics itself:
    ///   0xFFFF0FA0 __kernel_memory_barrier -- a no-op here
    ///     (single-interpreter ordering), r0 clobbered to 0.
    ///   0xFFFF0FC0 __kernel_cmpxchg -- *r2 == r0 ? (*r2 = r1,
    ///     return 0) : return -1 (r1/r2 preserved on failure,
    ///     matching the real helper closely enough for libc).
    ///   0xFFFF0FE0 __kernel_get_tls -- returns the thread's
    ///     TLS pointer (the value set by set_tls).
    /// GB's linker reaches __kernel_get_tls through a literal
    /// in its text, which is how this gap was found.
    pub(crate) fn kuser_call(&mut self, mem: &mut Mem, pc: u32) -> Option<Step> {
        match pc {
            0xFFFF_0FA0 => {
                self.r[0] = 0;
                let lr = self.r[REG_LR];
                self.jump_to(lr);
                Some(Step::Continue)
            }
            0xFFFF_0FC0 => {
                let (old, new, ptr) = (self.r[0], self.r[1], self.r[2]);
                if mem.read_u32(ptr) == old {
                    mem.write_u32(ptr, new);
                    self.r[0] = 0;
                } else {
                    self.r[0] = u32::MAX; // -1
                }
                let lr = self.r[REG_LR];
                self.jump_to(lr);
                Some(Step::Continue)
            }
            0xFFFF_0FE0 => {
                self.r[0] = self.tls;
                let lr = self.r[REG_LR];
                self.jump_to(lr);
                Some(Step::Continue)
            }
            _ => None,
        }
    }

    /// thread-pointer access, barriers. Returns true when handled
    /// (and PC advanced); false lets normal decode proceed.
    fn try_misc(&mut self, _mem: &mut Mem, word: u32) -> bool {
        let pc = self.r[REG_PC];
        let next_pc = pc.wrapping_add(4);
        // BX Rm / BLX Rm
        if word & 0x0FFF_FFF0 == 0x012F_FF10 || word & 0x0FFF_FFF0 == 0x012F_FF30 {
            let rm = (word & 0xF) as usize;
            let target = self.r[rm];
            if word & 0x0FFF_FFF0 == 0x012F_FF30 {
                self.r[REG_LR] = next_pc;
            }
            self.thumb = target & 1 == 1;
            self.r[REG_PC] = target & !1;
            return true;
        }
        // BKPT
        if word & 0x0FF0_00F0 == 0x0120_0070 {
            self.unimp(word);
        }
        // CLZ: bits 11-4 are 1111_0001 (0xF1), verified against the
        // guest binary's own CLZ encodings (e.g. 0xE16F2F13).
        if (word >> 20) & 0xFF == 0x16
            && (word >> 16) & 0xF == 0xF
            && (word >> 4) & 0xFF == 0xF1
        {
            let rm = (word & 0xF) as usize;
            let rd = ((word >> 12) & 0xF) as usize;
            self.r[rd] = self.r[rm].leading_zeros();
            self.r[REG_PC] = next_pc;
            return true;
        }
        // MRS (read composed CPSR approximation)
        if (word >> 20) & 0xDF == 0x10
            && (word >> 16) & 0xF == 0xF
            && word & 0xFFF == 0
        {
            let rd = ((word >> 12) & 0xF) as usize;
            let mut cpsr = 0x10u32; // user mode
            if self.n { cpsr |= 1 << 31; }
            if self.z { cpsr |= 1 << 30; }
            if self.c { cpsr |= 1 << 29; }
            if self.v { cpsr |= 1 << 28; }
            if self.thumb { cpsr |= 1 << 5; }
            self.r[rd] = cpsr;
            self.r[REG_PC] = next_pc;
            return true;
        }
        // MSR: no-op for M0 (guests do not rely on it in userspace)
        if (word >> 20) & 0xDF == 0x12 {
            self.r[REG_PC] = next_pc;
            return true;
        }
        // MRC/MCR: p15 c13 = thread pointer registers
        if (word >> 26) & 0x3 == 0x3 && (word >> 24) & 0xF == 0xE {
            let cp = (word >> 8) & 0xF;
            let crn = (word >> 16) & 0xF;
            let crm = word & 0xF;
            let opc2 = (word >> 5) & 0x7;
            let load = (word >> 20) & 1 == 1;
            let rd = ((word >> 12) & 0xF) as usize;
            if cp == 15 && crn == 13 && crm == 0 && (opc2 == 3 || opc2 == 4) {
                if load {
                    self.r[rd] = self.tls;
                } else {
                    self.tls = self.r[rd];
                }
                self.r[REG_PC] = next_pc;
                return true;
            }
            if cp == 15 {
                // Cache / barrier maintenance etc.: no-op.
                self.r[REG_PC] = next_pc;
                return true;
            }
            return false; // VFP etc.: loud failure downstream
        }
        false
    }
}

// ----------------------------------------------------------------
// VFP: scalar single/double with a plain register file. Encodings
// verified against the /tmp/vfp.s + /tmp/vimm.s probe dumps.
impl Cpu {
    pub(crate) fn get_d(&self, i: usize) -> f64 {
        f64::from_bits(self.d[i])
    }
    pub(crate) fn set_d(&mut self, i: usize, v: f64) {
        self.d[i] = v.to_bits();
    }
    pub(crate) fn get_s(&self, i: usize) -> f32 {
        let bits = if i % 2 == 0 {
            self.d[i / 2] as u32
        } else {
            (self.d[i / 2] >> 32) as u32
        };
        f32::from_bits(bits)
    }
    pub(crate) fn set_s(&mut self, i: usize, v: f32) {
        let b = v.to_bits() as u64;
        if i % 2 == 0 {
            self.d[i / 2] = (self.d[i / 2] & 0xFFFF_FFFF_0000_0000) | b;
        } else {
            self.d[i / 2] = (self.d[i / 2] & 0x0000_0000_FFFF_FFFF) | (b << 32);
        }
    }
    fn get_s_bits(&self, i: usize) -> u32 {
        self.get_s(i).to_bits()
    }
    fn set_s_bits(&mut self, i: usize, bits: u32) {
        self.set_s(i, f32::from_bits(bits));
    }

    /// VFP immediate constant: imm8 -> sign * (1 + frac/16) * 2^E,
    /// E = ((imm8 >> 4) & 0x7) XOR 4, minus 3. Derived from the
    /// probed table (0x60->0.5, 0x70->1.0, 0x00->2.0, 0x78->1.5...).
    fn vfp_imm(imm8: u32) -> f64 {
        let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
        let e = (((imm8 >> 4) & 0x7) ^ 4) as i32 - 3;
        let frac = (imm8 & 0xF) as f64 / 16.0;
        sign * (1.0 + frac) * 2f64.powi(e)
    }

    pub(crate) fn exec_vfp(&mut self, mem: &mut Mem, word: u32) -> bool {
        let pc = self.r[REG_PC];
        let next_pc = pc.wrapping_add(4);
        let top4 = (word >> 24) & 0xF;
        let cp = (word >> 8) & 0xF;
        if cp != 0xA && cp != 0xB {
            return false;
        }
        let dbl = cp == 0xB;
        let d_idx = |w: u32| -> usize {
            // D-register number from the [15:12] field + bit 22.
            (((w >> 12) & 0xF) | (((w >> 22) & 1) << 4)) as usize
        };
        let s_idx = |w: u32| -> usize {
            // S-register number from the [15:12] field + bit 22.
            ((((w >> 12) & 0xF) << 1) | ((w >> 22) & 1)) as usize
        };
        let n_idx_d = |w: u32| -> usize {
            (((w >> 16) & 0xF) | (((w >> 7) & 1) << 4)) as usize
        };
        let n_idx_s = |w: u32| -> usize {
            ((((w >> 16) & 0xF) << 1) | ((w >> 7) & 1)) as usize
        };
        let m_idx_d = |w: u32| -> usize {
            ((w & 0xF) | (((w >> 5) & 1) << 4)) as usize
        };
        let m_idx_s = |w: u32| -> usize {
            (((w & 0xF) << 1) | ((w >> 5) & 1)) as usize
        };
        // FPSCR transfer: bits 23-20 == 1110 (VMSR) / 1111 (VMRS),
        // register id in bits 19-16 == 0001.
        if top4 == 0xE && ((word >> 20) & 0xF) >= 0xE && ((word >> 16) & 0xF) == 1 {
            let rd = ((word >> 12) & 0xF) as usize;
            if ((word >> 20) & 0xF) == 0xF {
                if rd == REG_PC {
                    self.n = self.fpscr & (1 << 31) != 0;
                    self.z = self.fpscr & (1 << 30) != 0;
                    self.c = self.fpscr & (1 << 29) != 0;
                    self.v = self.fpscr & (1 << 28) != 0;
                } else {
                    self.r[rd] = self.fpscr;
                }
            } else {
                self.fpscr = self.r[rd];
            }
            self.r[REG_PC] = next_pc;
            return true;
        }
        // VMOV core <-> single: bits 23-20 == 0000/0001, bit 4 set,
        // low nibble zero.
        if top4 == 0xE && ((word >> 20) & 0xF) <= 1 && (word >> 4) & 1 == 1 && word & 0xF == 0 {
            let to_s = (word >> 20) & 1 == 0;
            // Sn packing for VMOV core<->single is the n_idx_s
            // form: bits 19-16 shifted, low bit from bit 7 (probe:
            // vmov r2, s5 == 0xEE122A90 has bit 7 set, bit 22
            // clear; the bit-22 form silently read s4 instead).
            let sn = n_idx_s(word);
            let rt = ((word >> 12) & 0xF) as usize;
            if to_s {
                self.set_s_bits(sn, self.r[rt]);
            } else {
                self.r[rt] = self.get_s_bits(sn);
            }
            self.r[REG_PC] = next_pc;
            return true;
        }
        // VMOV double <-> two core registers: top 1100, bits 23-20
        // == 0100 (to double) / 0101 (from double), 7-4 == 0001.
        if top4 == 0xC && matches!((word >> 20) & 0xF, 0x4 | 0x5) && (word & 0xF0) == 0x10 {
            let to_d = ((word >> 20) & 0xF) == 0x4;
            let rt = ((word >> 12) & 0xF) as usize;
            let rt2 = ((word >> 16) & 0xF) as usize;
            let dm = m_idx_d(word);
            if to_d {
                self.d[dm] = (self.r[rt] as u64) | ((self.r[rt2] as u64) << 32);
            } else {
                self.r[rt] = self.d[dm] as u32;
                self.r[rt2] = (self.d[dm] >> 32) as u32;
            }
            self.r[REG_PC] = next_pc;
            return true;
        }
        // Load/store single + multiple (VLDR/VSTR/VLDM/VSTM,
        // which includes VPUSH/VPOP).
        if top4 == 0xD || top4 == 0xC {
            let load = (word >> 20) & 1 == 1;
            let rn = ((word >> 16) & 0xF) as usize;
            let base = if rn == REG_PC { pc + 8 } else { self.r[rn] };
            if top4 == 0xD && (word >> 21) & 1 == 0 {
                // Single transfer: offset = imm8 * 4, U = bit 23.
                let off = (word & 0xFF) * 4;
                let addr = if (word >> 23) & 1 == 1 {
                    base.wrapping_add(off)
                } else {
                    base.wrapping_sub(off)
                };
                if dbl {
                    let d = d_idx(word);
                    if load {
                        let lo = self.rd(mem, addr) as u64;
                        let hi = self.rd(mem, addr.wrapping_add(4)) as u64;
                        self.d[d] = lo | (hi << 32);
                    } else {
                        self.wr(mem, addr, self.d[d] as u32);
                        self.wr(mem, addr.wrapping_add(4), (self.d[d] >> 32) as u32);
                    }
                } else {
                    let s = s_idx(word);
                    if load {
                        let v = self.rd(mem, addr);
                        self.set_s_bits(s, v);
                    } else {
                        self.wr(mem, addr, self.get_s_bits(s));
                    }
                }
                self.r[REG_PC] = next_pc;
                return true;
            }
            if (word >> 21) & 1 == 1 || top4 == 0xC {
                // Multiple: P=bit24, U=bit23, W=bit21, L=bit20.
                let pre = (word >> 24) & 1 == 1;
                let up = (word >> 23) & 1 == 1;
                let wback = (word >> 21) & 1 == 1;
                let imm8 = (word & 0xFF) as u32;
                let (count, start_reg) = if dbl {
                    (imm8 / 2, d_idx(word))
                } else {
                    (imm8, s_idx(word))
                };
                let each: u32 = if dbl { 8 } else { 4 };
                let total = count * each;
                let start = if up {
                    if pre { base.wrapping_add(each) } else { base }
                } else if pre {
                    base.wrapping_sub(total)
                } else {
                    base.wrapping_sub(total).wrapping_add(each)
                };
                let mut addr = start;
                for i in 0..count as usize {
                    if dbl {
                        if load {
                            let lo = self.rd(mem, addr) as u64;
                            let hi = self.rd(mem, addr.wrapping_add(4)) as u64;
                            self.d[start_reg + i] = lo | (hi << 32);
                        } else {
                            self.wr(mem, addr, self.d[start_reg + i] as u32);
                            self.wr(mem, addr.wrapping_add(4), (self.d[start_reg + i] >> 32) as u32);
                        }
                    } else {
                        if load {
                            let v = self.rd(mem, addr);
                            self.set_s_bits(start_reg + i, v);
                        } else {
                            self.wr(mem, addr, self.get_s_bits(start_reg + i));
                        }
                    }
                    addr = addr.wrapping_add(each);
                }
                if wback {
                    self.r[rn] = if up {
                        base.wrapping_add(total)
                    } else {
                        base.wrapping_sub(total)
                    };
                }
                self.r[REG_PC] = next_pc;
                return true;
            }
            return false;
        }
        // Data processing: top 1110.
        if top4 == 0xE {
            let op = (word >> 20) & 0xF;
            // VCMP/VCMPE f64 (field table machine-verified over
            // all guest instances: bits 23-20 == 0xB, bits 19-16
            // in {4, 5} with 5 = compare against +0.0 and 4 =
            // against Dm, Dd = bits 15-12, bits 11-8 == 0xB,
            // bit 6 set; bit 7 is the E flag, numerically inert;
            // Dm = bits 3-0 directly).
            if op == 0xB
                && matches!((word >> 16) & 0xF, 4 | 5)
                && ((word >> 8) & 0xF) == 0xB
                && (word >> 6) & 1 == 1
            {
                let a = self.get_d(((word >> 12) & 0xF) as usize);
                let b = if ((word >> 16) & 0xF) == 4 {
                    self.get_d((word & 0xF) as usize)
                } else {
                    0.0
                };
                let unordered = a.is_nan() || b.is_nan();
                let lt = !unordered && a < b;
                let eq = !unordered && a == b;
                // VFP compares write FPSCR only; core APSR flags
                // belong to the guest until it moves them itself
                // with VMRS. Writing self.n/z/c/v here clobbered
                // a just-VMRS'd verdict that a pending branch was
                // about to consume (busybox seq pre-loads its
                // inc>0 verdict into APSR, then compares cur/last).
                let nibble = ((lt || unordered) as u32) << 31
                    | (eq as u32) << 30
                    | ((!lt || unordered) as u32) << 29
                    | (unordered as u32) << 28;
                self.fpscr = (self.fpscr & 0x0FFF_FFFF) | nibble;
                self.r[REG_PC] = next_pc;
                return true;
            }
            // VCVT to s32/u32 from f64 (field table machine-
            // verified against assembler probes and guest
            // samples: bits 19-16 == 0xC for u32, 0xD for s32;
            // source Dm = bits 3-0 directly; dest Sd via s_idx,
            // whose bit 22 lands in the bits 23-20 nibble -- so
            // op reads 0xB or 0xF depending on whether the dest
            // register number is odd, and both must be accepted.
            // Rounding is selected by bit 7: SET = plain VCVT,
            // which per the ARM manual rounds TOWARDS ZERO;
            // CLEAR = VCVTR, which uses the FPSCR mode (round
            // to nearest-even at the default fpscr). An earlier
            // version had this backwards, which inverted the
            // residual sign in musl fmt_fp's digit-extraction
            // loop and made it diverge. Bit 6 is set in both.)
            if dbl
                && matches!(op, 0xB | 0xF)
                && matches!((word >> 16) & 0xF, 0xC | 0xD)
                && (word >> 6) & 1 == 1
            {
                let v = self.get_d((word & 0xF) as usize);
                let r = if v.is_nan() {
                    0.0
                } else if (word >> 7) & 1 == 1 {
                    v.trunc()
                } else {
                    v.round_ties_even()
                };
                let bits = if ((word >> 16) & 0xF) == 0xC {
                    if r <= 0.0 { 0 } else if r >= 4294967296.0 { u32::MAX } else { r as u32 }
                } else if r <= -2147483649.0 {
                    i32::MIN as u32
                } else if r >= 2147483648.0 {
                    i32::MAX as u32
                } else {
                    (r as i32) as u32
                };
                self.set_s_bits(s_idx(word), bits);
                self.r[REG_PC] = next_pc;
                return true;
            }
            // Multiply-accumulate f64 family (sample-verified:
            // bits 11-8 == 0xB; op == 0x0 gives VMLA with bit 6
            // clear / VMLS with bit 6 set; op == 0x1 with bit 6
            // clear is VNMLS, defined by the ARM manual as
            // Dd = -(Dd) + Dn*Dm. Vd = bits 15-12, Vn = bits
            // 19-16, Vm = bits 3-0 directly.)
            if dbl && matches!(op, 0x0 | 0x1) && ((word >> 8) & 0xF) == 0xB {
                let d = ((word >> 12) & 0xF) as usize;
                let n = ((word >> 16) & 0xF) as usize;
                let m = (word & 0xF) as usize;
                let prod = self.get_d(n) * self.get_d(m);
                let acc = self.get_d(d);
                let r = match (op, (word >> 6) & 1) {
                    (0x0, 0) => acc + prod,
                    (0x0, _) => acc - prod,
                    (0x1, 0) => -acc + prod,
                    // VNMLA (assembler-verified encoding
                    // 0xEE1E1B45): -(acc + prod).
                    _ => -(acc + prod),
                };
                self.set_d(d, r);
                self.r[REG_PC] = next_pc;
                return true;
            }
            // Multiply-accumulate f32 family (the f64 block
            // above's mirror; encodings assembler-verified:
            // vmla.f32 s1 = 0xEE470A08, vmls.f32 s1 =
            // 0xEE470A48, vnmls.f32 s1 = 0xEE570A08,
            // vnmla.f32 s1 = 0xEE570A48. Canonical ops are
            // 0x0 (VMLA/VMLS) and 0x1 (VNMLA/VNMLS), with
            // bit 6 the add/sub selector -- but an ODD
            // destination register bleeds its low bit into
            // op bit 22 (the bug #9 bleed), so odd-d forms
            // read op 0x4/0x5. Mask bit 2 out (op3) before
            // matching, exactly like the three-register
            // block below; keying on raw op 0x4/0x5 missed
            // every even-destination FMA (guest Skia:
            // vmla.f32 s6, s7, s16 = 0xEE033A88).)
            let opf = op & !0x4;
            if !dbl && matches!(opf, 0x0 | 0x1) && ((word >> 8) & 0xF) == 0xA && (word >> 4) & 1 == 0 {
                let (d, n, m) = (s_idx(word), n_idx_s(word), m_idx_s(word));
                let prod = self.get_s(n) * self.get_s(m);
                let acc = self.get_s(d);
                let r = match (opf, (word >> 6) & 1) {
                    (0x0, 0) => acc + prod,
                    (0x0, _) => acc - prod,
                    (0x1, 0) => -acc + prod,
                    _ => -(acc + prod),
                };
                self.set_s(d, r);
                self.r[REG_PC] = next_pc;
                return true;
            }
            // Three-register arithmetic. The destination
            // register's packed number bleeds into op bit 22
            // (s_idx puts an odd S register's low bit there):
            // vmul.f32 s15, ... reads op == 0x6, not 0x2 -- the
            // same bleed the VCVT-to-int gate above documents
            // for 0xB/0xF. Canonical opcodes for this family
            // (VMUL 0010, VADD/VSUB 0011, VDIV 1000) never set
            // bit 22, so mask it out before matching.
            let op3 = op & !0x4;
            if matches!(op3, 0x2 | 0x3 | 0x8) && (word >> 4) & 1 == 0 {
                let sub = op3 == 0x3 && (word >> 6) & 1 == 1;
                if dbl {
                    let (d, n, m) = (d_idx(word), n_idx_d(word), m_idx_d(word));
                    let (a, b) = (self.get_d(n), self.get_d(m));
                    let r = match op3 {
                        0x3 => {
                            if sub { a - b } else { a + b }
                        }
                        0x2 => a * b,
                        _ => a / b,
                    };
                    self.set_d(d, r);
                } else {
                    let (d, n, m) = (s_idx(word), n_idx_s(word), m_idx_s(word));
                    let (a, b) = (self.get_s(n), self.get_s(m));
                    let r = match op3 {
                        0x3 => {
                            if sub { a - b } else { a + b }
                        }
                        0x2 => a * b,
                        _ => a / b,
                    };
                    self.set_s(d, r);
                }
                self.r[REG_PC] = next_pc;
                return true;
            }
            // Unary / immediate / convert family: op == 1011,
            // plus the f32 mirror at op == 1111 (bit 23 is the
            // precision selector for this family: vmov.f32
            // s15, #0.5 == 0xEEF67A00 vs vmov.f64 == 0xEEB6..;
            // every sub-check below keys on fields that keep
            // the two apart -- VCVT-to-int has bits 7-6 != 00,
            // VCVT-between needs bits 19-16 == 7, and precision
            // itself comes from cp/dbl, so widening the gate
            // cannot misroute an f64 encoding).
            if matches!(op, 0xB | 0xF) {
                // VCVT between f32 and f64 (field table machine-
                // verified: bits 19-16 == 7, bits 7-6 == 11;
                // bits 11-8 == 0xA means f64 destination from an
                // f32 source, 0xB means f32 destination from an
                // f64 source -- the cp nibble names the SOURCE
                // precision here, so the old unary (7,3) arm,
                // which keyed direction on cp == 0xB as "double
                // result", had the f32.f64 direction backwards).
                if ((word >> 16) & 0xF) == 7
                    && ((word >> 6) & 0x3) == 0x3
                    && matches!((word >> 8) & 0xF, 0xA | 0xB)
                {
                    if ((word >> 8) & 0xF) == 0xA {
                        let v = self.get_s(m_idx_s(word));
                        self.set_d(d_idx(word), v as f64);
                    } else {
                        let v = self.get_d((word & 0xF) as usize);
                        self.set_s(s_idx(word), v as f32);
                    }
                    self.r[REG_PC] = next_pc;
                    return true;
                }
                // VCVT from s32/u32 (integer held in an s-register,
                // converted to float). Field layout verified against
                // guest-binary samples (0xEEB84B46 vcvt.f64.u32 d4,
                // s12; 0xEEB87B67 d7, s15; 0xEEF87A67 vcvt.f32.u32
                // s15, s15): bits 23-16 == 0xB8 (f64 dst) or 0xF8
                // (f32 dst), dst via the usual d_idx/s_idx packing,
                // Sm via m_idx_s, bit 7 set = signed source (clean
                // s32/u32 sample pairs differ only in bit 7).
                let mid8 = (word >> 16) & 0xFF;
                if mid8 == 0xB8 || mid8 == 0xF8 {
                    let bits = self.get_s_bits(m_idx_s(word));
                    let signed = (word >> 7) & 1 == 1;
                    if mid8 == 0xB8 {
                        let v = if signed { bits as i32 as f64 } else { bits as f64 };
                        self.set_d(d_idx(word), v);
                    } else {
                        let v = if signed { bits as i32 as f32 } else { bits as f32 };
                        self.set_s(s_idx(word), v);
                    }
                    self.r[REG_PC] = next_pc;
                    return true;
                }
                let hi = (word >> 16) & 0xF;
                let mode = (word >> 6) & 0x3;
                if mode == 0 {
                    // VMOV immediate: bits 19-16 are the high half
                    // of imm8, not a precision selector (probe:
                    // vmov.f64 d9, #0.5 == 0xEEB69B00 has imm8
                    // 0x60 there); precision comes from cp (dbl).
                    let imm8 = (((word >> 16) & 0xF) << 4) | (word & 0xF);
                    let v = Self::vfp_imm(imm8);
                    if dbl {
                        self.set_d(d_idx(word), v);
                    } else {
                        self.set_s(s_idx(word), v as f32);
                    }
                    self.r[REG_PC] = next_pc;
                    return true;
                }
                let handled = self.exec_vfp_unary(word, hi, mode, dbl,
                    d_idx(word), s_idx(word), m_idx_d(word), m_idx_s(word));
                if handled {
                    self.r[REG_PC] = next_pc;
                    return true;
                }
                return false;
            }
            return false;
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_vfp_unary(
        &mut self,
        word: u32,
        hi: u32,
        mode: u32,
        dbl: bool,
        d: usize,
        s: usize,
        m_d: usize,
        m_s: usize,
    ) -> bool {
        match (hi, mode) {
            (0, 1) => {
                // VMOV register
                if dbl { self.set_d(d, self.get_d(m_d)); } else { self.set_s(s, self.get_s(m_s)); }
            }
            (0, 3) => {
                if dbl { self.set_d(d, self.get_d(m_d).abs()); } else { self.set_s(s, self.get_s(m_s).abs()); }
            }
            (1, 1) => {
                if dbl { self.set_d(d, -self.get_d(m_d)); } else { self.set_s(s, -self.get_s(m_s)); }
            }
            (1, 3) => {
                if dbl { self.set_d(d, self.get_d(m_d).sqrt()); } else { self.set_s(s, self.get_s(m_s).sqrt()); }
            }
            (4, 1) | (4, 3) | (5, 1) | (5, 3) => {
                // VCMP / VCMPE: sets NZCV in FPSCR. Bits 19-16
                // (hi) select the second operand: 0100 = the Sm
                // register, 0101 = +0.0. Bit 7 is only the E
                // flag (NaN exception signaling); reading it as
                // the zero selector made every VCMPE against a
                // register compare against 0.0 instead --
                // vcmpe.f32 (0.8, 1.0) reported GT, which in
                // turn inverted Dalvik's cmpg/cmpl-float
                // verdicts (a Java range check on 0.8f threw
                // IllegalArgumentException while printing the
                // perfectly intact value 8.0E-1).
                let (a, b) = if dbl {
                    (self.get_d(d), if hi == 5 { 0.0 } else { self.get_d(m_d) })
                } else {
                    (
                        self.get_s(s) as f64,
                        if hi == 5 { 0.0 } else { self.get_s(m_s) as f64 },
                    )
                };
                let unordered = a.is_nan() || b.is_nan();
                let lt = !unordered && a < b;
                let eq = !unordered && a == b;
                // FPSCR only, as in the intercept above: VFP
                // compares never write the core APSR directly.
                let nibble = ((lt || unordered) as u32) << 31
                    | (eq as u32) << 30
                    | ((!lt || unordered) as u32) << 29
                    | (unordered as u32) << 28;
                self.fpscr = (self.fpscr & 0x0FFF_FFFF) | nibble;
            }
            (7, 3) => {
                // VCVT between f32 and f64 (dst precision = cp).
                if dbl {
                    self.set_d(d, self.get_s(m_s) as f64);
                } else {
                    self.set_s(s, self.get_d(m_d) as f32);
                }
            }
            (8, 3) => {
                // VCVT from s32 (source is an s-register's bits).
                let v = self.get_s_bits(m_s) as i32;
                if dbl { self.set_d(d, v as f64); } else { self.set_s(s, v as f32); }
            }
            (9, 3) => {
                // VCVT from u32.
                let v = self.get_s_bits(m_s);
                if dbl { self.set_d(d, v as f64); } else { self.set_s(s, v as f32); }
            }
            (0xC, 3) => {
                // VCVT to u32 (FPSCR rounding: round-to-nearest-even
                // at the default fpscr value 0).
                let v = if dbl { self.get_d(m_d) } else { self.get_s(m_s) as f64 };
                let r = if v.is_nan() { 0.0 } else { v.round_ties_even() };
                let bits = if r <= 0.0 {
                    0
                } else if r >= 4294967296.0 {
                    u32::MAX
                } else {
                    r as u32
                };
                self.set_s_bits(s, bits);
            }
            (0xD, 3) => {
                // VCVT to s32.
                let v = if dbl { self.get_d(m_d) } else { self.get_s(m_s) as f64 };
                let r = if v.is_nan() { 0.0 } else { v.round_ties_even() };
                let bits = if r <= -2147483649.0 {
                    i32::MIN as u32
                } else if r >= 2147483648.0 {
                    i32::MAX as u32
                } else {
                    (r as i32) as u32
                };
                self.set_s_bits(s, bits);
            }
            _ => return false,
        }
        true
    }
}
