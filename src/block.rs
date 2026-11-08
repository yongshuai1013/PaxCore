//! Basic-block decode cache (JIT stage 2a, ARM mode).
//!
//! `step()` re-walks its whole dispatch chain for every
//! instruction. This module decodes a run of instructions once
//! into pre-extracted `Op`s and executes the block directly;
//! shapes outside the covered set end the block with `Op::Legacy`,
//! which hands that one instruction back to `step()`. Semantics
//! of every covered shape are copied from the matching `step()`
//! arm, including its dispatch exclusions (multiply / extra
//! load-store space, the try_misc patterns, MOVW/MOVT precedence)
//! so a word can never be fast-decoded into a different meaning
//! than the legacy path would give it.
//!
//! Staleness: blocks are decoded from guest memory and cached by
//! pc. The guest could in principle store over its own code; the
//! M1 guest (static busybox) never does, and `main` flushes the
//! whole cache after every syscall, which bounds any staleness
//! window to a single syscall-free stretch. When execve lands
//! (M2) a flush there is mandatory regardless.
//!
//! The cache is bypassed entirely when tracing (PAXCORE_TRACE)
//! so traces stay instruction-exact, and when PAXCORE_NOCACHE=1
//! is set (differential testing against the legacy path).

use crate::cpu::{Cpu, Step, REG_LR, REG_PC};
use crate::mem::Mem;
use std::collections::HashMap;
use std::rc::Rc;

pub const MAX_BLOCK_OPS: usize = 32;

#[derive(Clone, Copy, Debug)]
pub enum Shift {
    Imm(u32, u32), // (type, amount): legacy shift_reg semantics
    Reg(u32, u8),  // (type, rs): legacy shift_reg_regform semantics
}

#[derive(Clone, Copy, Debug)]
pub enum SdtOff {
    Imm(u32),
    Reg { rm: u8, shift: Shift },
}

#[derive(Clone, Copy, Debug)]
pub enum Op {
    DpImm {
        cond: u8,
        opcode: u8,
        setflags: bool,
        rn: u8,
        rd: u8,
        imm8: u32,
        rot: u32,
    },
    DpReg {
        cond: u8,
        opcode: u8,
        setflags: bool,
        rn: u8,
        rd: u8,
        rm: u8,
        shift: Shift,
    },
    MovImm16 {
        cond: u8,
        top: bool, // false = MOVW, true = MOVT
        rd: u8,
        imm16: u32,
    },
    Sdt {
        cond: u8,
        pre: bool,
        up: bool,
        byte: bool,
        wback: bool, // legacy: bit21 || !pre, precomputed
        load: bool,
        rn: u8,
        rd: u8,
        off: SdtOff,
    },
    Bdt {
        cond: u8,
        pre: bool,
        up: bool,
        wback: bool,
        load: bool,
        rn: u8,
        list: u16,
    },
    Extend {
        cond: u8,
        zero: bool,
        typ: u32,
        rn: u8,
        rd: u8,
        rot: u32,
        rm: u8,
    },
    Bitfield {
        cond: u8,
        top8: u8,
        rn: u8,
        rd: u8,
        lsb: u32,
        field: u32, // width-1 (SBFX/UBFX) or msb (BFC/BFI)
    },
    Branch {
        cond: u8,
        link: bool,
        target: u32,
    },
    Svc,
    Legacy,
}

pub struct Block {
    pub ops: Vec<Op>,
}

/// Decode one instruction word into a fast `Op`, or `Op::Legacy`
/// when the word belongs to a family the fast path does not cover
/// (or to an exclusion the legacy dispatch checks first).
fn decode(pc: u32, word: u32) -> Op {
    let cond = (word >> 28) as u8;
    // The cond==0xF space is unconditional encodings (BLX
    // immediate among them): never decode those here, the
    // legacy path owns them. (A plain B/BL decode once silently
    // swallowed a BLX and ran Thumb code as ARM.)
    if cond == 0xF {
        return Op::Legacy;
    }
    // SVC: bits 27-24 == 1111 (legacy checks after cond).
    if (word >> 24) & 0xF == 0xF {
        return Op::Svc;
    }
    // Branch / branch-link: bits 27-25 == 101.
    if (word >> 25) & 0x7 == 0x5 {
        let link = (word >> 24) & 1 == 1;
        let imm24 = (word & 0x00ff_ffff) as i32;
        let signed = (imm24 << 8) >> 8;
        let target = (pc as i64 + 8 + (signed as i64) * 4) as u32;
        return Op::Branch { cond, link, target };
    }
    // Block data transfer: bits 27-25 == 100.
    if (word >> 25) & 0x7 == 0x4 {
        return Op::Bdt {
            cond,
            pre: (word >> 24) & 1 == 1,
            up: (word >> 23) & 1 == 1,
            wback: (word >> 21) & 1 == 1,
            load: (word >> 20) & 1 == 1,
            rn: ((word >> 16) & 0xF) as u8,
            list: (word & 0xFFFF) as u16,
        };
    }
    let top8 = ((word >> 20) & 0xFF) as u8;
    // Sign/zero extend family (checked before SDT in legacy).
    if matches!(top8, 0x68 | 0x6A | 0x6B | 0x6C | 0x6E | 0x6F)
        && (word >> 4) & 0xF == 0x7
        && (word >> 8) & 0x3 == 0
    {
        return Op::Extend {
            cond,
            zero: (word >> 22) & 1 == 1,
            typ: ((word >> 20) & 0x3) as u32,
            rn: ((word >> 16) & 0xF) as u8,
            rd: ((word >> 12) & 0xF) as u8,
            rot: ((word >> 10) & 0x3) * 8,
            rm: (word & 0xF) as u8,
        };
    }
    // Bitfield family (also before SDT in legacy).
    if matches!(top8, 0x7A | 0x7C | 0x7E) && (word >> 4) & 0x3 == 0x1 {
        return Op::Bitfield {
            cond,
            top8,
            rn: (word & 0xF) as u8,
            rd: ((word >> 12) & 0xF) as u8,
            lsb: (word >> 7) & 0x1F,
            field: (word >> 16) & 0x1F,
        };
    }
    // Single data transfer: bits 27-26 == 01.
    if (word >> 26) & 0x3 == 0x1 {
        let pre = (word >> 24) & 1 == 1;
        let off = if (word >> 25) & 1 == 1 {
            SdtOff::Reg {
                rm: (word & 0xF) as u8,
                shift: Shift::Imm((word >> 5) & 0x3, (word >> 7) & 0x1F),
            }
        } else {
            SdtOff::Imm(word & 0xFFF)
        };
        return Op::Sdt {
            cond,
            pre,
            up: (word >> 23) & 1 == 1,
            byte: (word >> 22) & 1 == 1,
            wback: (word >> 21) & 1 == 1 || !pre,
            load: (word >> 20) & 1 == 1,
            rn: ((word >> 16) & 0xF) as u8,
            rd: ((word >> 12) & 0xF) as u8,
            off,
        };
    }
    // Everything below lives in bits 27-26 == 00 space, where the
    // legacy dispatch first claims: multiply + extra load/store
    // (bit25 == 0 and bits 7,4 both set -- this also covers the
    // LDREX/STREX space), then the try_misc patterns (BX/BLX reg,
    // BKPT, CLZ, MRS, MSR). All of those stay legacy.
    if (word >> 26) & 0x3 == 0 {
        if (word >> 25) & 1 == 0 && word & 0x0000_0090 == 0x0000_0090 {
            return Op::Legacy;
        }
        if word & 0x0FFF_FFF0 == 0x012F_FF10 || word & 0x0FFF_FFF0 == 0x012F_FF30 {
            return Op::Legacy; // BX / BLX reg
        }
        if word & 0x0FF0_00F0 == 0x0120_0070 {
            return Op::Legacy; // BKPT
        }
        if top8 == 0x16 && ((word >> 16) & 0xF) == 0xF && ((word >> 4) & 0xFF) == 0xF1 {
            return Op::Legacy; // CLZ
        }
        if ((word >> 20) & 0xDF) == 0x10 && ((word >> 16) & 0xF) == 0xF && word & 0xFFF == 0 {
            return Op::Legacy; // MRS
        }
        if ((word >> 20) & 0xDF) == 0x12 {
            return Op::Legacy; // MSR
        }
        // MOVW / MOVT precede DP in legacy.
        if top8 == 0x30 || top8 == 0x34 {
            return Op::MovImm16 {
                cond,
                top: top8 == 0x34,
                rd: ((word >> 12) & 0xF) as u8,
                imm16: (((word >> 16) & 0xF) << 12) | (word & 0xFFF),
            };
        }
        // Data processing.
        let opcode = ((word >> 21) & 0xF) as u8;
        let setflags = (word >> 20) & 1 == 1;
        let rn = ((word >> 16) & 0xF) as u8;
        let rd = ((word >> 12) & 0xF) as u8;
        if (word >> 25) & 1 == 1 {
            return Op::DpImm {
                cond,
                opcode,
                setflags,
                rn,
                rd,
                imm8: word & 0xFF,
                rot: ((word >> 8) & 0xF) * 2,
            };
        }
        let rm = (word & 0xF) as u8;
        let typ = (word >> 5) & 0x3;
        let shift = if (word >> 4) & 1 == 1 {
            Shift::Reg(typ, ((word >> 8) & 0xF) as u8)
        } else {
            Shift::Imm(typ, (word >> 7) & 0x1F)
        };
        return Op::DpReg { cond, opcode, setflags, rn, rd, rm, shift };
    }
    Op::Legacy
}

/// True when executing this op can write the pc (so the block
/// must end right after it).
fn writes_pc(op: &Op) -> bool {
    match op {
        Op::DpImm { rd, opcode, .. } | Op::DpReg { rd, opcode, .. } => {
            *rd as usize == REG_PC && !matches!(opcode, 0x8 | 0x9 | 0xA | 0xB)
        }
        Op::MovImm16 { rd, .. } => *rd as usize == REG_PC,
        Op::Sdt { load, rd, .. } => *load && *rd as usize == REG_PC,
        Op::Bdt { load, list, .. } => *load && list & (1 << 15) != 0,
        Op::Extend { rd, .. } | Op::Bitfield { rd, .. } => *rd as usize == REG_PC,
        Op::Branch { .. } | Op::Svc | Op::Legacy => true,
    }
}

fn decode_block(cpu: &Cpu, mem: &Mem, start: u32) -> Block {
    let mut ops = Vec::new();
    let mut pc = start;
    for _ in 0..MAX_BLOCK_OPS {
        let word = cpu.rd(mem, pc);
        let op = decode(pc, word);
        let last = writes_pc(&op);
        ops.push(op);
        if last {
            break;
        }
        pc = pc.wrapping_add(4);
    }
    Block { ops }
}

pub type BlockCache = HashMap<u32, Rc<Block>>;

#[derive(PartialEq)]
enum Flow {
    /// pc advanced to the next instruction in the block.
    Next,
    /// pc was written by the op (branch, load to pc, ...); the
    /// block ends here with the new pc already in place.
    Jumped,
    /// SVC executed; pc already points past it.
    Syscall,
}

impl Cpu {
    /// Execute the cached (or newly decoded) block at the current
    /// pc. Returns Some(Step::Syscall) when an SVC was hit and the
    /// caller must service it; None when the block simply finished
    /// and execution can continue at the new pc. The caller
    /// guarantees ARM mode with the cache enabled.
    pub fn run_block(&mut self, mem: &mut Mem, cache: &mut BlockCache) -> Option<Step> {
        let start = self.r[REG_PC];
        let block = match cache.get(&start) {
            Some(b) => b.clone(),
            None => {
                let b = Rc::new(decode_block(self, mem, start));
                cache.insert(start, b.clone());
                b
            }
        };
        let mut pc = start;
        for op in &block.ops {
            self.steps += 1;
            // Legacy step() reads the instruction's own pc from
            // r[REG_PC] (block transfers with rn == pc, legacy
            // fallbacks), so keep it exact for every op.
            self.r[REG_PC] = pc;
            match self.exec_op(mem, pc, op) {
                Flow::Next => {
                    pc = pc.wrapping_add(4);
                    self.r[REG_PC] = pc;
                }
                Flow::Jumped => break,
                Flow::Syscall => return Some(Step::Syscall),
            }
        }
        None
    }

    fn reg(&self, i: u8, pc: u32) -> u32 {
        if i as usize == REG_PC {
            pc.wrapping_add(8)
        } else {
            self.r[i as usize]
        }
    }

    fn shifted(&mut self, val: u32, shift: Shift) -> (u32, bool) {
        match shift {
            Shift::Imm(typ, amount) => self.shift_reg(val, typ, amount),
            Shift::Reg(typ, rs) => {
                let amount = self.r[rs as usize] & 0xFF;
                self.shift_reg_regform(val, typ, amount)
            }
        }
    }

    fn exec_op(&mut self, mem: &mut Mem, pc: u32, op: &Op) -> Flow {
        let next_pc = pc.wrapping_add(4);
        let cond = match op {
            Op::DpImm { cond, .. }
            | Op::DpReg { cond, .. }
            | Op::MovImm16 { cond, .. }
            | Op::Sdt { cond, .. }
            | Op::Bdt { cond, .. }
            | Op::Extend { cond, .. }
            | Op::Bitfield { cond, .. }
            | Op::Branch { cond, .. } => *cond as u32,
            Op::Svc | Op::Legacy => 0xE,
        };
        if cond != 0xE && !self.cond_ok(cond) {
            self.r[REG_PC] = next_pc;
            return Flow::Next;
        }
        match op {
            Op::Svc => {
                self.r[REG_PC] = next_pc;
                Flow::Syscall
            }
            Op::Legacy => {
                // Hand this one instruction to the legacy path;
                // step() counts it too, so hand the count over.
                self.steps -= 1;
                match self.step(mem) {
                    Step::Syscall => Flow::Syscall,
                    Step::Continue => {
                        if self.r[REG_PC] == next_pc {
                            Flow::Next
                        } else {
                            Flow::Jumped
                        }
                    }
                }
            }
            Op::Branch { link, target, .. } => {
                if *link {
                    self.r[REG_LR] = next_pc;
                }
                self.r[REG_PC] = *target;
                Flow::Jumped
            }
            Op::DpImm { opcode, setflags, rn, rd, imm8, rot, .. } => {
                let a = self.reg(*rn, pc);
                let (b, sh_carry) = if *rot == 0 {
                    (*imm8, self.c)
                } else {
                    let v = imm8.rotate_right(*rot);
                    (v, v & 0x8000_0000 != 0)
                };
                self.exec_dp(pc, *opcode, *setflags, a, b, sh_carry, *rd)
            }
            Op::DpReg { opcode, setflags, rn, rd, rm, shift, .. } => {
                let a = self.reg(*rn, pc);
                let raw = self.reg(*rm, pc);
                let (b, sh_carry) = self.shifted(raw, *shift);
                self.exec_dp(pc, *opcode, *setflags, a, b, sh_carry, *rd)
            }
            Op::MovImm16 { top, rd, imm16, .. } => {
                if *top {
                    self.r[*rd as usize] = (self.r[*rd as usize] & 0xFFFF) | (imm16 << 16);
                } else {
                    self.r[*rd as usize] = *imm16;
                }
                self.r[REG_PC] = next_pc;
                if *rd as usize == REG_PC {
                    Flow::Jumped
                } else {
                    Flow::Next
                }
            }
            Op::Sdt { pre, up, byte, wback, load, rn, rd, off, .. } => {
                let off_val = match off {
                    SdtOff::Imm(v) => *v,
                    SdtOff::Reg { rm, shift } => {
                        let raw = self.reg(*rm, pc);
                        self.shifted(raw, *shift).0
                    }
                };
                let base = self.reg(*rn, pc);
                let eff = if *pre {
                    if *up {
                        base.wrapping_add(off_val)
                    } else {
                        base.wrapping_sub(off_val)
                    }
                } else {
                    base
                };
                let mut jumped = false;
                if *load {
                    let val = if *byte {
                        self.rd8(mem, eff)
                    } else {
                        self.rd(mem, eff)
                    };
                    if *rd as usize == REG_PC {
                        self.jump_to(val);
                        jumped = true;
                    } else {
                        self.r[*rd as usize] = val;
                    }
                } else {
                    let val = if *rd as usize == REG_PC {
                        pc.wrapping_add(12)
                    } else {
                        self.r[*rd as usize]
                    };
                    if *byte {
                        self.wr8(mem, eff, val);
                    } else {
                        self.wr(mem, eff, val);
                    }
                }
                if *wback && !(*load && *rd == *rn) {
                    self.r[*rn as usize] = if *pre {
                        eff
                    } else if *up {
                        base.wrapping_add(off_val)
                    } else {
                        base.wrapping_sub(off_val)
                    };
                }
                if jumped {
                    Flow::Jumped
                } else {
                    self.r[REG_PC] = next_pc;
                    Flow::Next
                }
            }
            Op::Bdt { pre, up, wback, load, rn, list, .. } => {
                let count = list.count_ones() as u32;
                let base = self.r[*rn as usize];
                let start = if *up {
                    if *pre {
                        base.wrapping_add(4)
                    } else {
                        base
                    }
                } else if *pre {
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
                    if *load {
                        let val = self.rd(mem, addr);
                        if i == REG_PC {
                            loaded_pc = Some(val);
                        } else {
                            self.r[i] = val;
                        }
                    } else {
                        let val = if i == REG_PC {
                            pc.wrapping_add(12)
                        } else {
                            self.r[i]
                        };
                        self.wr(mem, addr, val);
                    }
                    addr = addr.wrapping_add(4);
                }
                if *wback {
                    self.r[*rn as usize] = if *up {
                        base.wrapping_add(count * 4)
                    } else {
                        base.wrapping_sub(count * 4)
                    };
                }
                match loaded_pc {
                    Some(v) => {
                        self.jump_to(v);
                        Flow::Jumped
                    }
                    None => {
                        self.r[REG_PC] = next_pc;
                        Flow::Next
                    }
                }
            }
            Op::Extend { zero, typ, rn, rd, rot, rm, .. } => {
                let v = self.r[*rm as usize].rotate_right(*rot);
                let ext = |b: u32| -> u32 {
                    if *zero {
                        b
                    } else {
                        b as u8 as i8 as u32
                    }
                };
                let extracted = match typ {
                    0 => {
                        let lo = if *zero {
                            v & 0xFF
                        } else {
                            (v as u8 as i8 as u32) & 0xFFFF
                        };
                        let hi = if *zero {
                            (v >> 16) & 0xFF
                        } else {
                            ((v >> 16) as u8 as i8 as u32) & 0xFFFF
                        };
                        lo | (hi << 16)
                    }
                    2 => ext(v & 0xFF),
                    _ => {
                        if *zero {
                            v & 0xFFFF
                        } else {
                            v as u16 as i16 as u32
                        }
                    }
                };
                self.r[*rd as usize] = if *rn as usize == REG_PC || *typ == 0 {
                    extracted
                } else {
                    self.r[*rn as usize].wrapping_add(extracted)
                };
                self.r[REG_PC] = next_pc;
                if *rd as usize == REG_PC {
                    Flow::Jumped
                } else {
                    Flow::Next
                }
            }
            Op::Bitfield { top8, rn, rd, lsb, field, .. } => {
                match top8 {
                    0x7E => {
                        let width = field + 1;
                        let mask = if width >= 32 {
                            u32::MAX
                        } else {
                            (1u32 << width) - 1
                        };
                        let src = self.reg(*rn, pc);
                        self.r[*rd as usize] = (src >> lsb) & mask;
                    }
                    0x7A => {
                        let width = field + 1;
                        let src = self.reg(*rn, pc);
                        let shifted = (src >> lsb) << (32 - width);
                        self.r[*rd as usize] = ((shifted as i32) >> (32 - width)) as u32;
                    }
                    _ => {
                        let msb = *field;
                        let width = msb - lsb + 1;
                        let mask = ((1u32 << width) - 1) << lsb;
                        let ins = if *rn == 15 {
                            0
                        } else {
                            (self.r[*rn as usize] << lsb) & mask
                        };
                        self.r[*rd as usize] = (self.r[*rd as usize] & !mask) | ins;
                    }
                }
                self.r[REG_PC] = next_pc;
                if *rd as usize == REG_PC {
                    Flow::Jumped
                } else {
                    Flow::Next
                }
            }
        }
    }

    /// The legacy DP result computation, shared shape for the
    /// immediate and register operand forms. Returns the flow;
    /// test ops never write rd, and a write to pc ends the block.
    fn exec_dp(
        &mut self,
        _pc: u32,
        opcode: u8,
        setflags: bool,
        a: u32,
        b: u32,
        sh_carry: bool,
        rd: u8,
    ) -> Flow {
        let test_op = matches!(opcode, 0x8 | 0x9 | 0xA | 0xB);
        let set = setflags || test_op;
        let result = match opcode {
            0x0 => {
                let r = a & b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0x1 => {
                let r = a ^ b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0x2 => self.sub_with_flags(a, b, 1, set),
            0x3 => self.sub_with_flags(b, a, 1, set),
            0x4 => self.add_with_flags(a, b, 0, set),
            0x5 => self.add_with_flags(a, b, self.c as u32, set),
            0x6 => self.sub_with_flags(a, b, self.c as u32, set),
            0x7 => self.sub_with_flags(b, a, self.c as u32, set),
            0x8 => {
                let r = a & b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0x9 => {
                let r = a ^ b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0xA => {
                self.sub_with_flags(a, b, 1, true);
                0
            }
            0xB => {
                self.add_with_flags(a, b, 0, true);
                0
            }
            0xC => {
                let r = a | b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0xD => {
                let r = b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            0xE => {
                let r = a & !b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
            _ => {
                let r = !b;
                if set {
                    self.set_nz(r);
                    self.c = sh_carry;
                }
                r
            }
        };
        if test_op {
            return Flow::Next;
        }
        if rd as usize == REG_PC {
            self.r[REG_PC] = result;
            Flow::Jumped
        } else {
            self.r[rd as usize] = result;
            Flow::Next
        }
    }
}
