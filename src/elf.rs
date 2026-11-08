//! Minimal ELF32 (ARM) loader: PT_LOAD segments into the
//! sparse guest address space.

use crate::mem::Mem;

pub struct Loaded {
    pub entry: u32,
    /// First address past the loaded image (for the initial brk).
    pub image_end: u32,
    /// PT_INTERP contents, when the image is dynamically linked.
    pub interp: Option<String>,
    /// Guest address of the program headers (0 when unknown).
    pub phdr: u32,
    pub phent: u32,
    pub phnum: u32,
    /// The ELF's own entry (before any interpreter redirect).
    pub raw_entry: u32,
    /// Lowest loaded vaddr (the image base; AT_BASE for an
    /// interpreter).
    pub min_vaddr: u32,
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub fn load(bytes: &[u8], mem: &mut Mem) -> Result<Loaded, String> {
    load_at(bytes, mem, 0)
}

/// Load with a relocation bias (0 for ET_EXEC; ET_DYN images get
/// their vaddrs shifted by `bias`).
pub fn load_at(bytes: &[u8], mem: &mut Mem, bias: u32) -> Result<Loaded, String> {
    let mut image_end: u32 = 0;
    let mut interp: Option<String> = None;
    let mut phdr: u32 = 0;
    let mut min_vaddr: u32 = u32::MAX;
    if bytes.len() < 52 || &bytes[0..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if bytes[4] != 1 {
        return Err("not a 32-bit ELF".into());
    }
    let machine = u16_at(bytes, 18);
    if machine != 40 {
        return Err(format!("not an ARM ELF (e_machine={machine})"));
    }
    let entry = u32_at(bytes, 24);
    let phoff = u32_at(bytes, 28) as usize;
    let _ = entry;
    let phentsize = u16_at(bytes, 42) as usize;
    let phnum = u16_at(bytes, 44) as usize;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if p + 32 > bytes.len() {
            return Err("program header out of bounds".into());
        }
        let p_type = u32_at(bytes, p);
        let off = u32_at(bytes, p + 4) as usize;
        let vaddr = u32_at(bytes, p + 8) as usize;
        let filesz = u32_at(bytes, p + 16) as usize;
        let memsz = u32_at(bytes, p + 20) as usize;
        if p_type == 3 {
            // PT_INTERP
            if off + filesz <= bytes.len() {
                let raw = &bytes[off..off + filesz];
                let s = raw.split(|&b| b == 0).next().unwrap_or(raw);
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            continue;
        }
        if p_type != 1 {
            continue; // PT_LOAD only below
        }
        let gvaddr = (vaddr as u32).wrapping_add(bias);
        if (gvaddr as usize) + memsz > mem.len() {
            return Err(format!(
                "segment at 0x{gvaddr:x} size 0x{memsz:x} exceeds guest memory 0x{:x}",
                mem.len()
            ));
        }
        if off + filesz > bytes.len() {
            return Err("segment file range out of bounds".into());
        }
        mem.write_slice(gvaddr, &bytes[off..off + filesz]);
        mem.zero_range(gvaddr + filesz as u32, memsz - filesz);
        if phdr == 0 && off <= phoff && phoff < off + filesz {
            phdr = gvaddr + (phoff - off) as u32;
        }
        image_end = image_end.max(gvaddr + memsz as u32);
        min_vaddr = min_vaddr.min(gvaddr);
    }
    let phent = phentsize as u32;
    let raw_entry = entry;
    Ok(Loaded {
        entry: raw_entry.wrapping_add(bias),
        image_end,
        interp,
        phdr,
        phent,
        phnum: phnum as u32,
        raw_entry: raw_entry.wrapping_add(bias),
        min_vaddr: if min_vaddr == u32::MAX { bias } else { min_vaddr },
    })
}
