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

/// One MAP_SHARED window: guest range [base, base+len) aliases
/// `backing[offset .. offset+len)`. The backing lives outside
/// any single address space (owned by the syscall layer's area
/// registry, or created fresh for anonymous shared maps), so
/// every process that maps the same area reads and writes the
/// same bytes -- GB's /dev/__properties__ workspace depends on
/// this. Fork copies the window list (Rc clones: same backing);
/// exec builds a fresh Mem, dropping the windows.
#[derive(Clone)]
pub struct SharedWindow {
    pub base: u32,
    pub len: u32,
    pub offset: usize,
    pub backing: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
}

pub struct Mem {
    chunks: Vec<Option<Box<[u8; CHUNK]>>>,
    shared: Vec<SharedWindow>,
}

impl Mem {
    pub fn new() -> Mem {
        let mut chunks = Vec::with_capacity(NCHUNKS);
        chunks.resize_with(NCHUNKS, || None);
        Mem {
            chunks,
            shared: Vec::new(),
        }
    }

    /// The window containing `addr`, if any.
    fn win_at(&self, addr: u32) -> Option<&SharedWindow> {
        self.shared
            .iter()
            .find(|w| addr >= w.base && addr.wrapping_sub(w.base) < w.len)
    }

    /// The window covering the WHOLE range [addr, addr+n).
    fn range_win(&self, addr: u32, n: usize) -> Option<&SharedWindow> {
        self.shared.iter().find(|w| {
            addr >= w.base && (addr as u64 - w.base as u64) + n as u64 <= w.len as u64
        })
    }

    fn hits_shared(&self, addr: u32, n: usize) -> bool {
        if self.shared.is_empty() || n == 0 {
            return false;
        }
        let end = addr as u64 + n as u64;
        self.shared.iter().any(|w| {
            let wb = w.base as u64;
            let we = wb + w.len as u64;
            (addr as u64) < we && wb < end
        })
    }

    pub fn add_shared(
        &mut self,
        base: u32,
        len: u32,
        offset: usize,
        backing: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    ) {
        self.shared.push(SharedWindow {
            base,
            len,
            offset,
            backing,
        });
    }

    /// Drop the parts of any windows overlapping [base, base+len),
    /// splitting a window when the range cuts through its middle.
    pub fn remove_shared(&mut self, base: u32, len: u32) {
        if self.shared.is_empty() || len == 0 {
            return;
        }
        let end = base.wrapping_add(len);
        let mut out: Vec<SharedWindow> = Vec::with_capacity(self.shared.len() + 1);
        for w in self.shared.drain(..) {
            let we = w.base.wrapping_add(w.len);
            if we <= base || w.base >= end {
                out.push(w);
                continue;
            }
            if w.base < base {
                // Left remainder.
                out.push(SharedWindow {
                    base: w.base,
                    len: base - w.base,
                    offset: w.offset,
                    backing: w.backing.clone(),
                });
            }
            if we > end {
                // Right remainder.
                out.push(SharedWindow {
                    base: end,
                    len: we - end,
                    offset: w.offset + (end - w.base) as usize,
                    backing: w.backing,
                });
            }
        }
        self.shared = out;
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
        if !self.shared.is_empty() {
            if let Some(w) = self.win_at(addr) {
                let off = (addr - w.base) as usize + w.offset;
                return w.backing.borrow().get(off).copied().unwrap_or(0);
            }
        }
        match &self.chunks[Self::chunk_idx(addr)] {
            Some(c) => c[(addr as usize) % CHUNK],
            None => 0,
        }
    }

    pub fn set_byte(&mut self, addr: u32, v: u8) {
        if !self.shared.is_empty() {
            if let Some(w) = self.win_at(addr) {
                let off = (addr - w.base) as usize + w.offset;
                let mut b = w.backing.borrow_mut();
                if off >= b.len() {
                    b.resize(off + 1, 0);
                }
                b[off] = v;
                return;
            }
        }
        let idx = Self::chunk_idx(addr);
        let c = self.chunks[idx].get_or_insert_with(|| Box::new([0u8; CHUNK]));
        c[(addr as usize) % CHUNK] = v;
    }

    pub fn read_u16(&self, addr: u32) -> u16 {
        u16::from_le_bytes([self.byte(addr), self.byte(addr.wrapping_add(1))])
    }

    pub fn read_u32(&self, addr: u32) -> u32 {
        if !self.shared.is_empty() {
            if let Some(w) = self.range_win(addr, 4) {
                let off = (addr - w.base) as usize + w.offset;
                let b = w.backing.borrow();
                let mut v = [0u8; 4];
                if off + 4 <= b.len() {
                    v.copy_from_slice(&b[off..off + 4]);
                } else {
                    for (i, x) in v.iter_mut().enumerate() {
                        *x = b.get(off + i).copied().unwrap_or(0);
                    }
                }
                return u32::from_le_bytes(v);
            }
            if self.hits_shared(addr, 4) {
                return u32::from_le_bytes([
                    self.byte(addr),
                    self.byte(addr.wrapping_add(1)),
                    self.byte(addr.wrapping_add(2)),
                    self.byte(addr.wrapping_add(3)),
                ]);
            }
        }
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
        if !self.shared.is_empty() {
            if let Some(w) = self.range_win(addr, 4) {
                let off = (addr - w.base) as usize + w.offset;
                let mut b = w.backing.borrow_mut();
                if off + 4 > b.len() {
                    b.resize(off + 4, 0);
                }
                b[off..off + 4].copy_from_slice(&v.to_le_bytes());
                return;
            }
            if self.hits_shared(addr, 4) {
                for (i, x) in v.to_le_bytes().iter().enumerate() {
                    self.set_byte(addr.wrapping_add(i as u32), *x);
                }
                return;
            }
        }
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
            if !self.shared.is_empty() {
                if let Some(w) = self.win_at(a) {
                    let woff = (a - w.base) as usize + w.offset;
                    let n = ((w.base + w.len - a) as usize).min(out.len() - done);
                    let b = w.backing.borrow();
                    for i in 0..n {
                        out[done + i] = b.get(woff + i).copied().unwrap_or(0);
                    }
                    done += n;
                    continue;
                }
            }
            let off = (a as usize) % CHUNK;
            let mut n = (CHUNK - off).min(out.len() - done);
            if !self.shared.is_empty() {
                // Stop a private segment at the next window.
                for w in &self.shared {
                    if w.base > a {
                        n = n.min((w.base - a) as usize);
                    }
                }
            }
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
            if !self.shared.is_empty() {
                if let Some(w) = self.win_at(a) {
                    let woff = (a - w.base) as usize + w.offset;
                    let n = ((w.base + w.len - a) as usize).min(data.len() - done);
                    let mut b = w.backing.borrow_mut();
                    if woff + n > b.len() {
                        b.resize(woff + n, 0);
                    }
                    b[woff..woff + n].copy_from_slice(&data[done..done + n]);
                    done += n;
                    continue;
                }
            }
            let off = (a as usize) % CHUNK;
            let mut n = (CHUNK - off).min(data.len() - done);
            if !self.shared.is_empty() {
                for w in &self.shared {
                    if w.base > a {
                        n = n.min((w.base - a) as usize);
                    }
                }
            }
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
            if !self.shared.is_empty() {
                if let Some(w) = self.win_at(a) {
                    let woff = (a - w.base) as usize + w.offset;
                    let n = ((w.base + w.len - a) as usize).min(len - done);
                    let mut b = w.backing.borrow_mut();
                    for i in 0..n {
                        if woff + i < b.len() {
                            b[woff + i] = 0;
                        }
                    }
                    done += n;
                    continue;
                }
            }
            let off = (a as usize) % CHUNK;
            let mut n = (CHUNK - off).min(len - done);
            if !self.shared.is_empty() {
                for w in &self.shared {
                    if w.base > a {
                        n = n.min((w.base - a) as usize);
                    }
                }
            }
            if let Some(c) = &mut self.chunks[Self::chunk_idx(a)] {
                c[off..off + n].fill(0);
            }
            done += n;
        }
    }

    /// Deep-copy only the chunks that exist (fork semantics).
    /// Shared windows are NOT copied: the child aliases the
    /// same backing stores, exactly like a real fork.
    pub fn clone_sparse(&self) -> Mem {
        Mem {
            chunks: self
                .chunks
                .iter()
                .map(|c| c.as_ref().map(|b| Box::new(**b)))
                .collect(),
            shared: self.shared.clone(),
        }
    }
}
