//! Thumb / Thumb-2 decoder. Encodings verified against
//! llvm-objdump output for guest/encprobe.s (see the probe file);
//! families not yet covered fail loudly via unimp().

use crate::cpu::{Cpu, Step, REG_LR, REG_PC, REG_SP};

fn rd16(mem: &[u8], addr: u32) -> u32 {
    let a = addr as usize;
    u16::from_le_bytes([mem[a], mem[a + 1]]) as u32
}

/// ThumbExpandImm: i:imm3:imm8 (12 bits) -> 32-bit constant.
fn expand_imm(imm12: u32) -> u32 {
    let imm8 = imm12 & 0xFF;
    match imm12 >> 10 {
        0 => match (imm12 >> 8) & 0x3 {
            0 => imm8,
            1 => (imm8 << 16) | imm8,
            2 => (imm8 << 24) | (imm8 << 8),
            _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
        },
        _ => {
            let base = 0x80 | (imm12 & 0x7F);
            base.rotate_right((imm12 >> 7) & 0x1F)
        }
    }
}

impl Cpu {
    fn it_advance(&mut self) {
        if self.it & 0x0F != 0 {
            self.it = (self.it & 0xE0) | (((self.it & 0x1F) << 1) & 0x1F);
        }
    }

    pub fn step_thumb(&mut self, mem: &mut [u8]) -> Step {
        let pc = self.r[REG_PC];
        let hw = rd16(mem, pc);
        self.steps += 1;
        if self.trace && self.steps >= self.trace_after {
            eprintln!("[trace] T pc=0x{pc:08x} hw=0x{hw:04x} r0=0x{:08x} r1=0x{:08x}", self.r[0], self.r[1]);
        }
        let is32 = matches!(hw >> 11, 0x1D | 0x1E | 0x1F);
        let len: u32 = if is32 { 4 } else { 2 };
        let hw2 = if is32 { rd16(mem, pc + 2) } else { 0 };
        // IT block condition for this instruction.
        let in_it = self.it & 0x0F != 0;
        let is_it_insn = !is32 && (hw & 0xFF00) == 0xBF00 && (hw & 0xF) != 0;
        if in_it && !is_it_insn {
            let cond = (self.it >> 4) & 0xF;
            if !self.cond_ok(cond as u32) {
                self.r[REG_PC] = pc + len;
                self.it_advance();
                return Step::Continue;
            }
        }
        let last_in_it = in_it && ((self.it & 0x1F) << 1) & 0x0F == 0;
        let out = self.exec_thumb(mem, pc, hw, hw2, in_it, last_in_it);
        if in_it && !is_it_insn {
            self.it_advance();
        }
        out
    }
}

impl Cpu {
    #[allow(clippy::too_many_arguments)]
    fn exec_thumb(
        &mut self,
        mem: &mut [u8],
        pc: u32,
        hw: u32,
        hw2: u32,
        in_it: bool,
        last_in_it: bool,
    ) -> Step {
        if matches!(hw >> 11, 0x1D | 0x1E | 0x1F) {
            return self.exec_thumb32(mem, pc, hw, hw2);
        }
        let pc4 = pc + 4;
        let next = pc + 2;
        // Flag-setting for implied-S 16-bit ops: suppressed inside
        // an IT block except for the last instruction in it.
        let sf = !in_it || last_in_it;
        // Shift by immediate / add-sub register / add-sub imm3:
        // bits 15-13 == 000, sub-op = bits 12-11 (3 = add/sub forms).
        if hw >> 13 == 0 {
            let op = (hw >> 11) & 0x3;
            if op == 3 {
                // 00011: add/sub
                let sub = (hw >> 9) & 1 == 1;
                let imm_form = (hw >> 10) & 1 == 1;
                let rn = ((hw >> 6) & 0x7) as usize;
                let rm = ((hw >> 3) & 0x7) as usize;
                let rd = (hw & 0x7) as usize;
                let b = if imm_form { rn as u32 } else { self.r[rm] };
                let a = self.r[rn];
                self.r[rd] = if sub {
                    self.sub_with_flags(a, b, 1, sf)
                } else {
                    self.add_with_flags(a, b, 0, sf)
                };
            } else {
                let imm5 = (hw >> 6) & 0x1F;
                let rm = ((hw >> 3) & 0x7) as usize;
                let rd = (hw & 0x7) as usize;
                let (val, carry) = self.shift_reg(self.r[rm], op, imm5);
                self.r[rd] = val;
                if sf {
                    self.set_nz(val);
                    self.c = carry;
                }
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Move/compare/add/sub immediate 8: bits 15-13 == 001,
        // op = bits 12-11 (0 MOV, 1 CMP, 2 ADD, 3 SUB).
        if hw >> 13 == 0b001 {
            let op = (hw >> 11) & 0x3;
            let rd = ((hw >> 8) & 0x7) as usize;
            let imm = hw & 0xFF;
            match op {
                0 => {
                    self.r[rd] = imm;
                    if sf { self.set_nz(imm); }
                }
                1 => {
                    self.sub_with_flags(self.r[rd], imm, 1, true);
                }
                2 => {
                    let r = self.add_with_flags(self.r[rd], imm, 0, sf);
                    self.r[rd] = r;
                }
                _ => {
                    let r = self.sub_with_flags(self.r[rd], imm, 1, sf);
                    self.r[rd] = r;
                }
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Data processing (register operands), 010000
        if hw >> 10 == 0x10 {
            let op = (hw >> 6) & 0xF;
            let rm = ((hw >> 3) & 0x7) as usize;
            let rdn = (hw & 0x7) as usize;
            let b = self.r[rm];
            let a = self.r[rdn];
            match op {
                0x0 => { let r = a & b; self.r[rdn] = r; if sf { self.set_nz(r); } }
                0x1 => { let r = a ^ b; self.r[rdn] = r; if sf { self.set_nz(r); } }
                0x2 | 0x3 | 0x4 | 0x7 => {
                    let typ = match op { 2 => 0, 3 => 1, 4 => 2, _ => 3 };
                    let (r, carry) = self.shift_reg_regform(a, typ, b & 0xFF);
                    self.r[rdn] = r;
                    if sf { self.set_nz(r); self.c = carry; }
                }
                0x5 => { let r = self.add_with_flags(a, b, self.c as u32, sf); self.r[rdn] = r; }
                0x6 => { let r = self.sub_with_flags(a, b, self.c as u32, sf); self.r[rdn] = r; }
                0x8 => { let r = a & b; if true { self.set_nz(r); } }
                0x9 => { let r = self.sub_with_flags(0, b, 1, sf); self.r[rdn] = r; }
                0xA => { self.sub_with_flags(a, b, 1, true); }
                0xB => { self.add_with_flags(a, b, 0, true); }
                0xC => { let r = a | b; self.r[rdn] = r; if sf { self.set_nz(r); } }
                0xD => { let r = a.wrapping_mul(b); self.r[rdn] = r; if sf { self.set_nz(r); } }
                0xE => { let r = a & !b; self.r[rdn] = r; if sf { self.set_nz(r); } }
                _ => { let r = !b; self.r[rdn] = r; if sf { self.set_nz(r); } }
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Special data processing / branch-exchange, 010001
        if hw >> 10 == 0x11 {
            let op = (hw >> 8) & 0x3;
            let rm = ((hw >> 3) & 0xF) as usize;
            if op == 3 {
                // BX / BLX register
                let target = if rm == REG_PC { pc4 } else { self.r[rm] };
                if (hw >> 7) & 1 == 1 {
                    self.r[REG_LR] = next | 1;
                }
                self.thumb = target & 1 == 1;
                self.r[REG_PC] = target & !1;
                return Step::Continue;
            }
            let dn = ((hw >> 7) & 1) as usize;
            let rdn = (dn << 3) | (hw & 0x7) as usize;
            let b = if rm == REG_PC { pc4 } else { self.r[rm] };
            match op {
                0 => {
                    let a = if rdn == REG_PC { pc4 } else { self.r[rdn] };
                    let r = a.wrapping_add(b);
                    if rdn == REG_PC {
                        self.thumb = r & 1 == 1;
                        self.r[REG_PC] = r & !1;
                    } else {
                        self.r[rdn] = r;
                        self.r[REG_PC] = next;
                    }
                }
                1 => {
                    let a = if rdn == REG_PC { pc4 } else { self.r[rdn] };
                    self.sub_with_flags(a, b, 1, true);
                    self.r[REG_PC] = next;
                }
                _ => {
                    if rdn == REG_PC {
                        self.thumb = b & 1 == 1;
                        self.r[REG_PC] = b & !1;
                    } else {
                        self.r[rdn] = b;
                        self.r[REG_PC] = next;
                    }
                }
            }
            return Step::Continue;
        }
        // LDR literal, 01001
        if hw >> 11 == 0x09 {
            let rd = ((hw >> 8) & 0x7) as usize;
            let addr = (pc4 & !3) + (hw & 0xFF) * 4;
            self.r[rd] = self.rd(mem, addr);
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Load/store register offset, 0101
        if hw >> 12 == 0x5 {
            let op = (hw >> 9) & 0x7;
            let rm = ((hw >> 6) & 0x7) as usize;
            let rn = ((hw >> 3) & 0x7) as usize;
            let rd = (hw & 0x7) as usize;
            let addr = self.r[rn].wrapping_add(self.r[rm]);
            match op {
                0 => self.wr(mem, addr, self.r[rd]),
                1 => {
                    let v = self.r[rd] as u16;
                    let a = addr as usize;
                    mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
                }
                2 => self.wr8(mem, addr, self.r[rd]),
                3 => self.r[rd] = mem[addr as usize] as i8 as u32,
                4 => self.r[rd] = self.rd(mem, addr),
                5 => {
                    let a = addr as usize;
                    self.r[rd] = u16::from_le_bytes([mem[a], mem[a + 1]]) as u32;
                }
                6 => self.r[rd] = self.rd8(mem, addr),
                _ => {
                    let a = addr as usize;
                    self.r[rd] = u16::from_le_bytes([mem[a], mem[a + 1]]) as i16 as u32;
                }
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Load/store immediate (word/byte), 011x; halfword, 1000;
        // SP-relative, 1001
        if (0x6..=0x9).contains(&(hw >> 12)) {
            let kind = hw >> 12;
            let load = (hw >> 11) & 1 == 1;
            let rd = if kind == 0x9 {
                ((hw >> 8) & 0x7) as usize
            } else {
                (hw & 0x7) as usize
            };
            let addr = match kind {
                0x6 | 0x7 => {
                    let rn = ((hw >> 3) & 0x7) as usize;
                    let imm5 = (hw >> 6) & 0x1F;
                    let scale = if kind == 0x6 { 4 } else { 1 };
                    self.r[rn].wrapping_add(imm5 * scale)
                }
                0x8 => {
                    let rn = ((hw >> 3) & 0x7) as usize;
                    self.r[rn].wrapping_add(((hw >> 6) & 0x1F) * 2)
                }
                _ => self.r[REG_SP].wrapping_add((hw & 0xFF) * 4),
            };
            let byte = kind == 0x7;
            let half = kind == 0x8;
            if load {
                self.r[rd] = if byte {
                    self.rd8(mem, addr)
                } else if half {
                    let a = addr as usize;
                    u16::from_le_bytes([mem[a], mem[a + 1]]) as u32
                } else {
                    self.rd(mem, addr)
                };
            } else if byte {
                self.wr8(mem, addr, self.r[rd]);
            } else if half {
                let a = addr as usize;
                let v = self.r[rd] as u16;
                mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
            } else {
                self.wr(mem, addr, self.r[rd]);
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // ADR / ADD SP, 1010
        if hw >> 12 == 0xA {
            let rd = ((hw >> 8) & 0x7) as usize;
            let imm = (hw & 0xFF) * 4;
            self.r[rd] = if (hw >> 11) & 1 == 1 {
                self.r[REG_SP].wrapping_add(imm)
            } else {
                (pc4 & !3).wrapping_add(imm)
            };
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Misc 16-bit, 1011
        if hw >> 12 == 0xB {
            if (hw & 0xFF80) == 0xB000 {
                // ADD/SUB SP, imm7
                let imm = (hw & 0x7F) * 4;
                if (hw >> 7) & 1 == 1 {
                    self.r[REG_SP] = self.r[REG_SP].wrapping_sub(imm);
                } else {
                    self.r[REG_SP] = self.r[REG_SP].wrapping_add(imm);
                }
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            if (hw & 0xFFC0) & 0xFF00 == 0xB200 {
                // SXTH/SXTB/UXTH/UXTB
                let op = (hw >> 6) & 0x3;
                let rm = ((hw >> 3) & 0x7) as usize;
                let rd = (hw & 0x7) as usize;
                let v = self.r[rm];
                self.r[rd] = match op {
                    0 => v as u16 as i16 as u32,
                    1 => v as u8 as i8 as u32,
                    2 => v & 0xFFFF,
                    _ => v & 0xFF,
                };
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            if (hw & 0xFE00) == 0xB400 {
                // PUSH {list, LR?}
                let mut list = hw & 0xFF;
                if (hw >> 8) & 1 == 1 {
                    list |= 1 << 14;
                }
                let count = list.count_ones();
                let mut addr = self.r[REG_SP].wrapping_sub(count * 4);
                self.r[REG_SP] = addr;
                for i in 0..16 {
                    if list & (1 << i) != 0 {
                        self.wr(mem, addr, self.r[i]);
                        addr += 4;
                    }
                }
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            if (hw & 0xFE00) == 0xBC00 {
                // POP {list, PC?}
                let mut list = hw & 0xFF;
                let with_pc = (hw >> 8) & 1 == 1;
                if with_pc {
                    list |= 1 << 15;
                }
                let mut addr = self.r[REG_SP];
                let mut jumped = false;
                for i in 0..16 {
                    if list & (1 << i) != 0 {
                        let val = self.rd(mem, addr);
                        addr += 4;
                        if i == REG_PC {
                            self.thumb = val & 1 == 1;
                            self.r[REG_PC] = val & !1;
                            jumped = true;
                        } else {
                            self.r[i] = val;
                        }
                    }
                }
                self.r[REG_SP] = addr;
                if !jumped {
                    self.r[REG_PC] = next;
                }
                return Step::Continue;
            }
            if (hw & 0xFF00) == 0xBE00 {
                self.unimp(hw); // BKPT
            }
            if (hw & 0xFF00) == 0xBF00 {
                if hw & 0xFF == 0 {
                    // NOP / hints (WFE/WFI/SEV/YIELD): no-op
                    self.r[REG_PC] = next;
                    return Step::Continue;
                }
                // IT: cond = bits 7-4, mask = bits 3-0
                self.it = (hw & 0xFF) as u8;
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            if (hw & 0xFFC0) == 0xBA00 || (hw & 0xFFC0) == 0xBA40 || (hw & 0xFFC0) == 0xBAC0 {
                // REV / REV16 / REVSH
                let rm = ((hw >> 3) & 0x7) as usize;
                let rd = (hw & 0x7) as usize;
                let v = self.r[rm];
                self.r[rd] = match (hw >> 6) & 0x3 {
                    0 => v.swap_bytes(),
                    1 => ((v >> 8) & 0xFF)
                        | ((v & 0xFF) << 8)
                        | ((v >> 24) << 16)
                        | (((v >> 16) & 0xFF) << 24),
                    _ => v as u16 as i16 as u32,
                };
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            if (hw & 0xF500) == 0xB100 {
                // CBZ / CBNZ
                let nz = (hw >> 11) & 1 == 1;
                let imm = (((hw >> 3) & 0x1F) << 1) | (((hw >> 9) & 1) << 6);
                let rn = (hw & 0x7) as usize;
                let zero = self.r[rn] == 0;
                self.r[REG_PC] = if zero != nz { pc4 + imm } else { next };
                return Step::Continue;
            }
            if (hw & 0xFF00) >= 0xB600 && (hw & 0xFF00) <= 0xB6FF {
                // CPS / SETEND: no-op in userspace emulation
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            self.unimp(hw);
        }
        // STMIA / LDMIA, 1100
        if hw >> 12 == 0xC {
            let load = (hw >> 11) & 1 == 1;
            let rn = ((hw >> 8) & 0x7) as usize;
            let list = hw & 0xFF;
            let count = list.count_ones();
            let mut addr = self.r[rn];
            for i in 0..8 {
                if list & (1 << i) != 0 {
                    if load {
                        let v = self.rd(mem, addr);
                        self.r[i] = v;
                    } else {
                        self.wr(mem, addr, self.r[i]);
                    }
                    addr += 4;
                }
            }
            self.r[rn] = self.r[rn].wrapping_add(count * 4);
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Conditional branch / SVC / UDF, 1101
        if hw >> 12 == 0xD {
            let cond = (hw >> 8) & 0xF;
            if cond == 0xF {
                self.r[REG_PC] = next;
                return Step::Syscall;
            }
            if cond == 0xE {
                self.unimp(hw); // UDF
            }
            let imm = ((hw & 0xFF) as i32) << 24 >> 23; // sign-extended imm8 << 1
            self.r[REG_PC] = if self.cond_ok(cond) {
                (pc4 as i32 + imm) as u32
            } else {
                next
            };
            return Step::Continue;
        }
        // Unconditional branch, 11100
        if hw >> 11 == 0x1C {
            let imm = ((hw & 0x7FF) as i32) << 21 >> 20; // sign-extended imm11 << 1
            self.r[REG_PC] = (pc4 as i32 + imm) as u32;
            return Step::Continue;
        }
        self.unimp(hw);
    }
}

/// ThumbExpandImm with carry: plain imm8 keeps the old carry,
/// pattern/rotation forms take bit31 of the result.
fn expand_imm_carry(imm12: u32, old_c: bool) -> (u32, bool) {
    let v = expand_imm(imm12);
    if imm12 >> 10 == 0 && (imm12 >> 8) & 0x3 == 0 {
        (v, old_c)
    } else {
        (v, v & 0x8000_0000 != 0)
    }
}

impl Cpu {
    fn exec_thumb32(&mut self, mem: &mut [u8], pc: u32, hw: u32, hw2: u32) -> Step {
        let pc4 = pc + 4;
        let next = pc + 4;
        // Hints first: NOP.W/barriers share the branch group's
        // top bits (their cond field would read 1110/1111).
        if (hw & 0xFFE0) == 0xF3A0 || hw == 0xF3BF {
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Branches: their hw2 marker bits (bit15 set) cannot
        // collide with data-processing-immediate (hw2 bit15 = 0).
        if (hw >> 11) == 0x1E {
            let s = (hw >> 10) & 1;
            if (hw2 & 0xD000) == 0xD000 {
                // BL
                let j1 = (hw2 >> 13) & 1;
                let j2 = (hw2 >> 11) & 1;
                let i1 = 1 - (j1 ^ s);
                let i2 = 1 - (j2 ^ s);
                let imm = (s << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | ((hw & 0x3FF) << 12)
                    | ((hw2 & 0x7FF) << 1);
                let off = ((imm << 7) as i32) >> 7;
                self.r[REG_LR] = next | 1;
                self.r[REG_PC] = (pc4 as i32 + off) as u32;
                return Step::Continue;
            }
            if (hw2 & 0xD000) == 0x9000 {
                // B.W unconditional
                let j1 = (hw2 >> 13) & 1;
                let j2 = (hw2 >> 11) & 1;
                let i1 = 1 - (j1 ^ s);
                let i2 = 1 - (j2 ^ s);
                let imm = (s << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | ((hw & 0x3FF) << 12)
                    | ((hw2 & 0x7FF) << 1);
                let off = ((imm << 7) as i32) >> 7;
                self.r[REG_PC] = (pc4 as i32 + off) as u32;
                return Step::Continue;
            }
            if (hw2 & 0xD000) == 0x8000 {
                // B.W conditional
                let cond = (hw >> 6) & 0xF;
                if cond < 0xE && self.cond_ok(cond) {
                    let j1 = (hw2 >> 13) & 1;
                    let j2 = (hw2 >> 11) & 1;
                    let i1 = 1 - (j1 ^ s);
                    let i2 = 1 - (j2 ^ s);
                    let imm = (s << 20)
                        | (i1 << 19)
                        | (i2 << 18)
                        | ((hw & 0x3F) << 12)
                        | ((hw2 & 0x7FF) << 1);
                    let off = ((imm << 11) as i32) >> 11;
                    self.r[REG_PC] = (pc4 as i32 + off) as u32;
                } else if cond >= 0xE {
                    self.unimp(hw);
                } else {
                    self.r[REG_PC] = next;
                }
                return Step::Continue;
            }
        }
        // LDM/STM wide: bits 15-9 == 1110100; bit 6 set marks the
        // dual (LDRD/STRD) sub-space instead.
        if (hw >> 9) == 0x74 {
            if (hw >> 6) & 1 == 1 {
                // LDRD / STRD wide (encoding verified vs enc2.s)
                let pre = (hw >> 8) & 1 == 1;
                let up = (hw >> 7) & 1 == 1;
                let wback = (hw >> 5) & 1 == 1 || !pre;
                let load = (hw >> 4) & 1 == 1;
                let rn = (hw & 0xF) as usize;
                let rt = ((hw2 >> 12) & 0xF) as usize;
                let rt2 = ((hw2 >> 8) & 0xF) as usize;
                let off = (hw2 & 0xFF) * 4;
                let base = self.r[rn];
                let eff = if pre {
                    if up { base.wrapping_add(off) } else { base.wrapping_sub(off) }
                } else {
                    base
                };
                if load {
                    self.r[rt] = self.rd(mem, eff);
                    self.r[rt2] = self.rd(mem, eff + 4);
                } else {
                    self.wr(mem, eff, self.r[rt]);
                    self.wr(mem, eff + 4, self.r[rt2]);
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
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            let pre = (hw >> 8) & 1 == 1;
            let up = (hw >> 7) & 1 == 1;
            let wback = (hw >> 5) & 1 == 1;
            let load = (hw >> 4) & 1 == 1;
            let rn = (hw & 0xF) as usize;
            let list = hw2 & 0xFFFF;
            let count = list.count_ones();
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
            if wback && !(load && list & (1 << rn) != 0) {
                self.r[rn] = if up {
                    base.wrapping_add(count * 4)
                } else {
                    base.wrapping_sub(count * 4)
                };
            }
            match loaded_pc {
                Some(v) => {
                    self.thumb = v & 1 == 1;
                    self.r[REG_PC] = v & !1;
                }
                None => self.r[REG_PC] = next,
            }
            return Step::Continue;
        }
        // MOVW / MOVT
        if (hw & 0xFBF0) == 0xF240 || (hw & 0xFBF0) == 0xF2C0 {
            let imm16 = ((hw & 0xF) << 12)
                | (((hw >> 10) & 1) << 11)
                | (((hw2 >> 12) & 0x7) << 8)
                | (hw2 & 0xFF);
            let rd = ((hw2 >> 8) & 0xF) as usize;
            if (hw & 0xFBF0) == 0xF240 {
                self.r[rd] = imm16;
            } else {
                self.r[rd] = (self.r[rd] & 0xFFFF) | (imm16 << 16);
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Data processing (immediate): bits 15-11 == 11110
        if (hw >> 11) == 0x1E && (hw2 & 0x8000) == 0 {
            let opc = (hw >> 5) & 0xF;
            let set = (hw >> 4) & 1 == 1;
            let rn = (hw & 0xF) as usize;
            let rd = ((hw2 >> 8) & 0xF) as usize;
            let imm12 = (((hw >> 10) & 1) << 11)
                | (((hw2 >> 12) & 0x7) << 8)
                | (hw2 & 0xFF);
            let (b, bcarry) = expand_imm_carry(imm12, self.c);
            let a = if rn == REG_PC { pc4 } else { self.r[rn] };
            let test_op = matches!(opc, 0x0 | 0x4 | 0x8 | 0xD) && rd == REG_PC;
            let do_set = set || test_op;
            let mut jumped = false;
            let result = match opc {
                0x0 => { let r = a & b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x1 => { let r = a & !b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x2 => {
                    let r = if rn == 15 { b } else { a | b };
                    if do_set { self.set_nz(r); self.c = bcarry; }
                    r
                }
                0x3 => { let r = !b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x4 => { let r = a ^ b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x8 => self.add_with_flags(a, b, 0, do_set),
                0xA => self.add_with_flags(a, b, self.c as u32, do_set),
                0xB => self.sub_with_flags(a, b, self.c as u32, do_set),
                0xD => self.sub_with_flags(a, b, 1, do_set),
                0xE => self.sub_with_flags(b, a, 1, do_set),
                _ => self.unimp(hw),
            };
            if !test_op {
                if rd == REG_PC {
                    self.thumb = result & 1 == 1;
                    self.r[REG_PC] = result & !1;
                    jumped = true;
                } else {
                    self.r[rd] = result;
                }
            }
            if !jumped {
                self.r[REG_PC] = next;
            }
            return Step::Continue;
        }
        // Data processing (register): bits 15-9 == 1110101
        if (hw >> 9) == 0x75 {
            let opc = (hw >> 5) & 0xF;
            let set = (hw >> 4) & 1 == 1;
            let rn = (hw & 0xF) as usize;
            let rd = ((hw2 >> 8) & 0xF) as usize;
            let rm = (hw2 & 0xF) as usize;
            let amount = (((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3);
            let typ = (hw2 >> 4) & 0x3;
            let raw = if rm == REG_PC { pc4 } else { self.r[rm] };
            let (b, bcarry) = self.shift_reg(raw, typ, amount);
            let a = if rn == REG_PC { pc4 } else { self.r[rn] };
            let test_op = matches!(opc, 0x0 | 0x4 | 0x8 | 0xD) && rd == REG_PC;
            let do_set = set || test_op;
            let mut jumped = false;
            let result = match opc {
                0x0 => { let r = a & b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x1 => { let r = a & !b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x2 => {
                    let r = if rn == 15 { b } else { a | b };
                    if do_set { self.set_nz(r); self.c = bcarry; }
                    r
                }
                0x3 => { let r = !b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x4 => { let r = a ^ b; if do_set { self.set_nz(r); self.c = bcarry; } r }
                0x8 => self.add_with_flags(a, b, 0, do_set),
                0xA => self.add_with_flags(a, b, self.c as u32, do_set),
                0xB => self.sub_with_flags(a, b, self.c as u32, do_set),
                0xD => self.sub_with_flags(a, b, 1, do_set),
                0xE => self.sub_with_flags(b, a, 1, do_set),
                _ => self.unimp(hw),
            };
            if !test_op {
                if rd == REG_PC {
                    self.thumb = result & 1 == 1;
                    self.r[REG_PC] = result & !1;
                    jumped = true;
                } else {
                    self.r[rd] = result;
                }
            }
            if !jumped {
                self.r[REG_PC] = next;
            }
            return Step::Continue;
        }
        // Multiply / CLZ group: bits 15-11 == 11111, bits 11-9 == 101
        if (hw >> 11) == 0x1F && ((hw >> 9) & 0x7) == 0x5 {
            if (hw & 0xFFF0) == 0xFAB0 && (hw2 & 0x00F0) == 0x0080 {
                let rd = ((hw2 >> 8) & 0xF) as usize;
                let rm = (hw2 & 0xF) as usize;
                self.r[rd] = self.r[rm].leading_zeros();
                self.r[REG_PC] = next;
                return Step::Continue;
            }
            let op = (hw >> 5) & 0xF;
            let rn = (hw & 0xF) as usize;
            let ra = ((hw2 >> 12) & 0xF) as usize;
            let rd = ((hw2 >> 8) & 0xF) as usize;
            let rm = (hw2 & 0xF) as usize;
            match op {
                0x8 => {
                    if ra == 15 {
                        // MUL
                        self.r[rd] = self.r[rn].wrapping_mul(self.r[rm]);
                    } else {
                        // MLS: Rd = Ra - Rn * Rm
                        self.r[rd] = self.r[ra]
                            .wrapping_sub(self.r[rn].wrapping_mul(self.r[rm]));
                    }
                }
                0x9 => {
                    if (hw & 0xF0) == 0x90 {
                        // SDIV (marker verified vs enc2.s: hw1 0xFB91)
                        let d = self.r[rm] as i32;
                        self.r[rd] = if d == 0 {
                            0
                        } else {
                            ((self.r[rn] as i32).wrapping_div(d)) as u32
                        };
                    } else {
                        // MLA
                        self.r[rd] = self.r[rn]
                            .wrapping_mul(self.r[rm])
                            .wrapping_add(self.r[ra]);
                    }
                }
                0xB => {
                    if (hw & 0xF0) == 0x90 {
                        // UDIV (marker verified: hw1 0xFBB1)
                        let d = self.r[rm];
                        self.r[rd] = if d == 0 { 0 } else { self.r[rn] / d };
                    } else {
                        self.unimp(hw);
                    }
                }
                0xC => {
                    // SMULL: RdLo = hw2[15:12], RdHi = rd field
                    let res = (self.r[rn] as i32 as i64 * self.r[rm] as i32 as i64) as u64;
                    self.r[ra] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                }
                0xD => {
                    // UMULL
                    let res = self.r[rn] as u64 * self.r[rm] as u64;
                    self.r[ra] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                }
                0xE => {
                    // SMLAL
                    let acc = ((self.r[rd] as u64) << 32) | self.r[ra] as u64;
                    let res = (acc as i64
                        + self.r[rn] as i32 as i64 * self.r[rm] as i32 as i64)
                        as u64;
                    self.r[ra] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                }
                0xF => {
                    // UMLAL
                    let acc = ((self.r[rd] as u64) << 32) | self.r[ra] as u64;
                    let res = acc + self.r[rn] as u64 * self.r[rm] as u64;
                    self.r[ra] = res as u32;
                    self.r[rd] = (res >> 32) as u32;
                }
                _ => self.unimp(hw),
            }
            self.r[REG_PC] = next;
            return Step::Continue;
        }
        // Load/store wide: bits 15-11 == 11111, bits 11-8 in {8, 9}
        if (hw >> 11) == 0x1F && ((hw >> 8) & 0x7) <= 1 {
            let group9 = (hw >> 8) & 1 == 1;
            let op = (hw >> 4) & 0xF;
            let rn = (hw & 0xF) as usize;
            let rt = ((hw2 >> 12) & 0xF) as usize;
            let imm12 = hw2 & 0xFFF;
            // kind: (size 0=byte, 1=half, 2=word; load; signed)
            let (size, load, signed): (u32, bool, bool);
            let addr: u32;
            if rn == REG_PC {
                // Literal pool access (loads only; op bit 3 is U)
                match (op & 0x7, group9) {
                    (0x5, _) => (size, load, signed) = (2, true, false),
                    (0x1, false) => (size, load, signed) = (0, true, false),
                    (0x1, true) => (size, load, signed) = (0, true, true),
                    (0x3, false) => (size, load, signed) = (1, true, false),
                    (0x3, true) => (size, load, signed) = (1, true, true),
                    _ => self.unimp(hw),
                }
                let base = (pc + 4) & !3;
                addr = if (hw >> 7) & 1 == 1 {
                    base.wrapping_add(imm12)
                } else {
                    base.wrapping_sub(imm12)
                };
            } else if !group9 && op < 6 && (hw2 & 0x0FC0) == 0 {
                // Register offset (encoding verified vs enc2.s)
                match op {
                    0 => (size, load, signed) = (0, false, false),
                    1 => (size, load, signed) = (0, true, false),
                    2 => (size, load, signed) = (1, false, false),
                    3 => (size, load, signed) = (1, true, false),
                    4 => (size, load, signed) = (2, false, false),
                    _ => (size, load, signed) = (2, true, false),
                }
                let rm = (hw2 & 0xF) as usize;
                let sh = (hw2 >> 4) & 0x3;
                addr = self.r[rn].wrapping_add(self.r[rm] << sh);
            } else {
                match (op, group9) {
                    (0x8, false) => (size, load, signed) = (0, false, false),
                    (0x9, false) => (size, load, signed) = (0, true, false),
                    (0xA, false) => (size, load, signed) = (1, false, false),
                    (0xB, false) => (size, load, signed) = (1, true, false),
                    (0xC, false) => (size, load, signed) = (2, false, false),
                    (0xD, _) => (size, load, signed) = (2, true, false),
                    (0x9, true) => (size, load, signed) = (0, true, true),
                    (0xB, true) => (size, load, signed) = (1, true, true),
                    (0x8, true) | (0xA, true) | (0xC, true) => {
                        // PLD / PLI immediate: no-op
                        self.r[REG_PC] = next;
                        return Step::Continue;
                    }
                    _ => self.unimp(hw),
                }
                if (hw2 >> 8) & 0xF == 0xF {
                    // Private / negative imm8 forms: not covered yet
                    self.unimp(hw);
                }
                addr = self.r[rn].wrapping_add(imm12);
            }
            if load {
                if rt == REG_PC && size != 2 {
                    // PLD (byte/half prefetch forms encoding): no-op
                    self.r[REG_PC] = next;
                    return Step::Continue;
                }
                let val = match (size, signed) {
                    (0, false) => self.rd8(mem, addr),
                    (0, true) => mem[addr as usize] as i8 as u32,
                    (1, false) => {
                        let a = addr as usize;
                        u16::from_le_bytes([mem[a], mem[a + 1]]) as u32
                    }
                    (1, true) => {
                        let a = addr as usize;
                        u16::from_le_bytes([mem[a], mem[a + 1]]) as i16 as u32
                    }
                    _ => self.rd(mem, addr),
                };
                if rt == REG_PC {
                    self.thumb = val & 1 == 1;
                    self.r[REG_PC] = val & !1;
                } else {
                    self.r[rt] = val;
                    self.r[REG_PC] = next;
                }
            } else {
                let val = self.r[rt];
                match size {
                    0 => self.wr8(mem, addr, val),
                    1 => {
                        let a = addr as usize;
                        mem[a..a + 2].copy_from_slice(&(val as u16).to_le_bytes());
                    }
                    _ => self.wr(mem, addr, val),
                }
                self.r[REG_PC] = next;
            }
            return Step::Continue;
        }
        self.unimp(hw);
    }
}
