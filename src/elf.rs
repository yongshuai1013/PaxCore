//! Minimal ELF32 (ARM) loader: PT_LOAD segments into flat memory.

pub struct Loaded {
    pub entry: u32,
    /// First address past the loaded image (for the initial brk).
    pub image_end: u32,
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub fn load(bytes: &[u8], mem: &mut [u8]) -> Result<Loaded, String> {
    let mut image_end: u32 = 0;
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
    let phentsize = u16_at(bytes, 42) as usize;
    let phnum = u16_at(bytes, 44) as usize;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if p + 32 > bytes.len() {
            return Err("program header out of bounds".into());
        }
        let p_type = u32_at(bytes, p);
        if p_type != 1 {
            continue; // PT_LOAD only
        }
        let off = u32_at(bytes, p + 4) as usize;
        let vaddr = u32_at(bytes, p + 8) as usize;
        let filesz = u32_at(bytes, p + 16) as usize;
        let memsz = u32_at(bytes, p + 20) as usize;
        if vaddr + memsz > mem.len() {
            return Err(format!(
                "segment at 0x{vaddr:x} size 0x{memsz:x} exceeds guest memory 0x{:x}",
                mem.len()
            ));
        }
        if off + filesz > bytes.len() {
            return Err("segment file range out of bounds".into());
        }
        mem[vaddr..vaddr + filesz].copy_from_slice(&bytes[off..off + filesz]);
        for b in &mut mem[vaddr + filesz..vaddr + memsz] {
            *b = 0;
        }
        image_end = image_end.max((vaddr + memsz) as u32);
    }
    Ok(Loaded { entry, image_end })
}
