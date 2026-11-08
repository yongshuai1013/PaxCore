//! Sparse guest address space: 3 GiB of virtual space backed by
//! 64 KiB chunks that exist only once touched. The Android
//! linker lives at 0xB0000000, so a dense buffer is impossible;
//! chunk lookup is a direct vector index, keeping fetch cost low.

/// The full 32-bit space: the kernel's kuser helper page lives
/// at 0xFFFF0000, above the 3 GiB mark, so chunks must be able
/// to reach all the way up.
pub const ADDR_SPACE: usize = 0x1_0000_0000;
const CHUNK: usize = 65_536;
const NCHUNKS: usize = (ADDR_SPACE / CHUNK) as usize;

pub struct Mem {
    chunks: Vec<Option<Box<[u8; CHUNK]>>>,
}

impl Mem {
    pub fn new() -> Mem {
        let mut chunks = Vec::with_capacity(NCHUNKS);
        chunks.resize_with(NCHUNKS, || None);
        Mem { chunks }
    }

    pub fn len(&self) -> usize {
        ADDR_SPACE
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    fn chunk_idx(addr: u32) -> usize {
        (addr as usize) / CHUNK
    }

    pub fn byte(&self, addr: u32) -> u8 {
        match &self.chunks[Self::chunk_idx(addr)] {
            Some(c) => c[(addr as usize) % CHUNK],
            None => 0,
        }
    }

    pub fn set_byte(&mut self, addr: u32, v: u8) {
        let idx = Self::chunk_idx(addr);
        let c = self.chunks[idx].get_or_insert_with(|| Box::new([0u8; CHUNK]));
        c[(addr as usize) % CHUNK] = v;
    }

    pub fn read_u16(&self, addr: u32) -> u16 {
        u16::from_le_bytes([self.byte(addr), self.byte(addr.wrapping_add(1))])
    }

    pub fn read_u32(&self, addr: u32) -> u32 {
        // Fast path: the whole word inside one chunk.
        let off = (addr as usize) % CHUNK;
        if off <= CHUNK - 4 {
            if let Some(c) = &self.chunks[Self::chunk_idx(addr)] {
                return u32::from_le_bytes(c[off..off + 4].try_into().unwrap());
            }
            return 0;
        }
        u32::from_le_bytes([
            self.byte(addr),
            self.byte(addr.wrapping_add(1)),
            self.byte(addr.wrapping_add(2)),
            self.byte(addr.wrapping_add(3)),
        ])
    }

    pub fn read_u64(&self, addr: u32) -> u64 {
        (self.read_u32(addr) as u64) | ((self.read_u32(addr.wrapping_add(4)) as u64) << 32)
    }

    pub fn write_u16(&mut self, addr: u32, v: u16) {
        let b = v.to_le_bytes();
        self.set_byte(addr, b[0]);
        self.set_byte(addr.wrapping_add(1), b[1]);
    }

    pub fn write_u32(&mut self, addr: u32, v: u32) {
        let off = (addr as usize) % CHUNK;
        if off <= CHUNK - 4 {
            let idx = Self::chunk_idx(addr);
            let c = self.chunks[idx].get_or_insert_with(|| Box::new([0u8; CHUNK]));
            c[off..off + 4].copy_from_slice(&v.to_le_bytes());
            return;
        }
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            self.set_byte(addr.wrapping_add(i as u32), *b);
        }
    }

    pub fn write_u64(&mut self, addr: u32, v: u64) {
        self.write_u32(addr, v as u32);
        self.write_u32(addr.wrapping_add(4), (v >> 32) as u32);
    }

    pub fn read_slice(&self, addr: u32, out: &mut [u8]) {
        let mut done = 0usize;
        while done < out.len() {
            let a = addr.wrapping_add(done as u32);
            let off = (a as usize) % CHUNK;
            let n = (CHUNK - off).min(out.len() - done);
            match &self.chunks[Self::chunk_idx(a)] {
                Some(c) => out[done..done + n].copy_from_slice(&c[off..off + n]),
                None => out[done..done + n].fill(0),
            }
            done += n;
        }
    }

    pub fn write_slice(&mut self, addr: u32, data: &[u8]) {
        let mut done = 0usize;
        while done < data.len() {
            let a = addr.wrapping_add(done as u32);
            let off = (a as usize) % CHUNK;
            let n = (CHUNK - off).min(data.len() - done);
            let idx = Self::chunk_idx(a);
            let c = self.chunks[idx].get_or_insert_with(|| Box::new([0u8; CHUNK]));
            c[off..off + n].copy_from_slice(&data[done..done + n]);
            done += n;
        }
    }

    pub fn zero_range(&mut self, addr: u32, len: usize) {
        // Zeroing untouched space is a no-op (reads already
        // return 0); only existing chunks need clearing.
        let mut done = 0usize;
        while done < len {
            let a = addr.wrapping_add(done as u32);
            let off = (a as usize) % CHUNK;
            let n = (CHUNK - off).min(len - done);
            if let Some(c) = &mut self.chunks[Self::chunk_idx(a)] {
                c[off..off + n].fill(0);
            }
            done += n;
        }
    }

    /// Deep-copy only the chunks that exist (fork semantics).
    pub fn clone_sparse(&self) -> Mem {
        Mem {
            chunks: self
                .chunks
                .iter()
                .map(|c| c.as_ref().map(|b| Box::new(**b)))
                .collect(),
        }
    }
}
