//! In-core GB binder driver (protocol version 7), modelled on
//! the semantics the PaxVM supervisor validated against real GB
//! libbinder: nodes owned by processes, per-process handle
//! tables, transaction routing with parcel object translation,
//! an mmap arena per process for delivered payloads, and death
//! notifications. State is shared by every task through
//! `Rc<RefCell<BinderCore>>`; deliveries are materialized into a
//! process's own address space when that process drains its
//! inbox inside its own BINDER_WRITE_READ.

use std::collections::{HashMap, VecDeque};

use crate::mem::Mem;

// ioctl requests (from the GB kernel binder.h; sizes verified
// against the supervisor's table).
pub const BINDER_WRITE_READ: u32 = 0xC018_6201;
pub const BINDER_SET_MAX_THREADS: u32 = 0x4004_6205;
pub const BINDER_SET_CONTEXT_MGR: u32 = 0x4004_6207;
pub const BINDER_THREAD_EXIT: u32 = 0x4004_6208;
pub const BINDER_VERSION: u32 = 0xC004_6209;
pub const BINDER_SET_IDLE_TIMEOUT: u32 = 0x4008_6203;
pub const BINDER_SET_IDLE_PRIORITY: u32 = 0x4004_6204;

// BC_* driver commands (userspace -> driver). The payload size
// is encoded in bits 16..=29 of the command word itself.
pub const BC_TRANSACTION: u32 = 0x4028_6300;
pub const BC_REPLY: u32 = 0x4028_6301;
pub const BC_FREE_BUFFER: u32 = 0x4004_6303;
pub const BC_INCREFS: u32 = 0x4004_6304;
pub const BC_ACQUIRE: u32 = 0x4004_6305;
pub const BC_RELEASE: u32 = 0x4004_6306;
pub const BC_DECREFS: u32 = 0x4004_6307;
pub const BC_INCREFS_DONE: u32 = 0x4008_6308;
pub const BC_ACQUIRE_DONE: u32 = 0x4008_6309;
pub const BC_ATTEMPT_ACQUIRE: u32 = 0x4008_630a;
pub const BC_REGISTER_LOOPER: u32 = 0x0000_630b;
pub const BC_ENTER_LOOPER: u32 = 0x0000_630c;
pub const BC_EXIT_LOOPER: u32 = 0x0000_630d;
pub const BC_REQUEST_DEATH_NOTIFICATION: u32 = 0x4008_630e;
pub const BC_CLEAR_DEATH_NOTIFICATION: u32 = 0x4008_630f;
pub const BC_DEAD_BINDER_DONE: u32 = 0x4004_6310;

// BR_* driver returns (driver -> userspace).
pub const BR_ERROR: u32 = 0x8004_7200;
pub const BR_OK: u32 = 0x0000_7201;
pub const BR_TRANSACTION: u32 = 0x8028_7202;
pub const BR_REPLY: u32 = 0x8028_7203;
pub const BR_DEAD_REPLY: u32 = 0x0000_7205;
pub const BR_TRANSACTION_COMPLETE: u32 = 0x0000_7206;
pub const BR_INCREFS: u32 = 0x8008_7207;
pub const BR_ACQUIRE: u32 = 0x8008_7208;
pub const BR_RELEASE: u32 = 0x8008_7209;
pub const BR_DECREFS: u32 = 0x8008_720a;
pub const BR_ATTEMPT_ACQUIRE: u32 = 0x8008_720b;
pub const BR_NOOP: u32 = 0x0000_720c;
pub const BR_SPAWN_LOOPER: u32 = 0x0000_720d;
pub const BR_FINISHED: u32 = 0x0000_720e;
pub const BR_DEAD_BINDER: u32 = 0x8004_720f;
pub const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8004_7210;
pub const BR_FAILED_REPLY: u32 = 0x0000_7211;

// flat_binder_object types.
pub const OBJ_BINDER: u32 = 0x7362_2A85;
pub const OBJ_WEAK_BINDER: u32 = 0x7762_2A85;
pub const OBJ_FD: u32 = 0x6664_2A85;
pub const OBJ_HANDLE: u32 = 0x7368_2A85;
pub const OBJ_WEAK_HANDLE: u32 = 0x7768_2A85;

// binder_transaction_data flags.
pub const TF_ONE_WAY: u32 = 0x01;

pub type NodeId = u64;

/// A queued driver->userspace item. Byte items are emitted
/// verbatim; transactions first reserve arena space in the
/// receiver and patch their data pointers, so they can only be
/// materialized by the receiver's own syscall path.
pub enum BrItem {
    Bytes(Vec<u8>),
    Txn {
        cmd: u32,
        sender_pid: u32,
        code: u32,
        flags: u32,
        target_ptr: u32,
        cookie: u32,
        data: Vec<u8>,
        offsets: Vec<u32>,
    },
}

struct Node {
    owner: u32,
    ptr: u32,
    cookie: u32,
    /// A BR_INCREFS/BR_ACQUIRE has been queued to the owner and
    /// not yet acknowledged by BC_*_DONE (or undone by release).
    weak_told: bool,
    strong_told: bool,
}

#[derive(Clone, Copy)]
struct HandleInfo {
    node: NodeId,
    strong: u32,
    weak: u32,
}

struct InFlight {
    from: u32,
}

pub struct ProcState {
    handles: HashMap<u32, HandleInfo>,
    by_node: HashMap<NodeId, u32>,
    next_handle: u32,
    inbox: VecDeque<BrItem>,
    inflight: Vec<InFlight>,
    arena: Option<(u32, u32)>, // (base, size)
    arena_bump: u32,           // next offset to try
    arena_free: Vec<(u32, u32)>, // (offset, len)
    arena_live: HashMap<u32, u32>, // guest ptr -> len
    pub looper: bool,
    death_reqs: Vec<(NodeId, u32)>, // (node, cookie)
}

impl ProcState {
    fn new() -> ProcState {
        ProcState {
            handles: HashMap::new(),
            by_node: HashMap::new(),
            next_handle: 1,
            inbox: VecDeque::new(),
            inflight: Vec::new(),
            arena: None,
            arena_bump: 0,
            arena_free: Vec::new(),
            arena_live: HashMap::new(),
            looper: false,
            death_reqs: Vec::new(),
        }
    }

    fn arena_alloc(&mut self, len: u32) -> Option<u32> {
        let (base, size) = self.arena?;
        let len = (len + 7) & !7;
        for i in 0..self.arena_free.len() {
            let (off, flen) = self.arena_free[i];
            if flen >= len {
                if flen == len {
                    self.arena_free.remove(i);
                } else {
                    self.arena_free[i] = (off + len, flen - len);
                }
                let ptr = base + off;
                self.arena_live.insert(ptr, len);
                return Some(ptr);
            }
        }
        if self.arena_bump + len <= size {
            let off = self.arena_bump;
            self.arena_bump += len;
            let ptr = base + off;
            self.arena_live.insert(ptr, len);
            return Some(ptr);
        }
        None
    }

    fn arena_free(&mut self, ptr: u32) {
        if let Some(len) = self.arena_live.remove(&ptr) {
            if let Some((base, _)) = self.arena {
                self.arena_free.push((ptr - base, len));
            }
        }
    }
}

pub struct BinderCore {
    nodes: HashMap<NodeId, Node>,
    by_owner_ptr: HashMap<(u32, u32), NodeId>,
    next_node: NodeId,
    procs: HashMap<u32, ProcState>,
    ctx_mgr: Option<NodeId>,
}

fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

impl BinderCore {
    pub fn new() -> BinderCore {
        BinderCore {
            nodes: HashMap::new(),
            by_owner_ptr: HashMap::new(),
            next_node: 1,
            procs: HashMap::new(),
            ctx_mgr: None,
        }
    }

    pub fn proc(&mut self, pid: u32) -> &mut ProcState {
        self.procs.entry(pid).or_insert_with(ProcState::new)
    }

    pub fn has_inbox(&self, pid: u32) -> bool {
        self.procs
            .get(&pid)
            .map(|p| !p.inbox.is_empty())
            .unwrap_or(false)
    }

    pub fn set_arena(&mut self, pid: u32, base: u32, size: u32) {
        let p = self.proc(pid);
        p.arena = Some((base, size));
        p.arena_bump = 0;
        p.arena_free.clear();
        p.arena_live.clear();
    }

    /// BINDER_SET_CONTEXT_MGR: the caller's implicit node
    /// (ptr 0, cookie 0) becomes the handle-0 target.
    pub fn set_context_mgr(&mut self, pid: u32) -> bool {
        if self.ctx_mgr.is_some() {
            return false;
        }
        let node = self.find_or_create_node(pid, 0, 0);
        self.ctx_mgr = Some(node);
        true
    }

    fn find_or_create_node(&mut self, owner: u32, ptr: u32, cookie: u32) -> NodeId {
        if let Some(&id) = self.by_owner_ptr.get(&(owner, ptr)) {
            return id;
        }
        let id = self.next_node;
        self.next_node += 1;
        self.nodes.insert(
            id,
            Node {
                owner,
                ptr,
                cookie,
                weak_told: false,
                strong_told: false,
            },
        );
        self.by_owner_ptr.insert((owner, ptr), id);
        id
    }

    /// Give `pid` a handle to `node`, creating the reference
    /// (and the owner notifications) on first use.
    fn handle_for(&mut self, pid: u32, node: NodeId, weak: bool) -> u32 {
        if let Some(&h) = self.proc(pid).by_node.get(&node) {
            return h;
        }
        let owner = self.nodes[&node].owner;
        let (nptr, ncookie) = (self.nodes[&node].ptr, self.nodes[&node].cookie);
        let h = {
            let p = self.proc(pid);
            let h = p.next_handle;
            p.next_handle += 1;
            p.handles.insert(
                h,
                HandleInfo {
                    node,
                    strong: 0,
                    weak: 0,
                },
            );
            p.by_node.insert(node, h);
            h
        };
        if owner != pid {
            // First reference from another process: notify the
            // owner so its local object stays alive / accounted.
            let n = self.nodes.get_mut(&node).unwrap();
            let mut notes = Vec::new();
            if !n.weak_told {
                n.weak_told = true;
                let mut b = Vec::with_capacity(12);
                b.extend_from_slice(&BR_INCREFS.to_le_bytes());
                b.extend_from_slice(&nptr.to_le_bytes());
                b.extend_from_slice(&ncookie.to_le_bytes());
                notes.push(b);
            }
            if !weak && !n.strong_told {
                n.strong_told = true;
                let mut b = Vec::with_capacity(12);
                b.extend_from_slice(&BR_ACQUIRE.to_le_bytes());
                b.extend_from_slice(&nptr.to_le_bytes());
                b.extend_from_slice(&ncookie.to_le_bytes());
                notes.push(b);
            }
            if !notes.is_empty() {
                let op = self.proc(owner);
                for b in notes {
                    op.inbox.push_back(BrItem::Bytes(b));
                }
            }
        }
        h
    }

    /// Rewrite a parcel's binder objects from the sender's world
    /// into the receiver's. Returns None on an untranslatable
    /// object (the transaction then fails with BR_FAILED_REPLY).
    fn translate(
        &mut self,
        sender: u32,
        receiver: u32,
        data: &mut [u8],
        offsets: &[u32],
    ) -> bool {
        for &off in offsets {
            let o = off as usize;
            if o + 16 > data.len() {
                return false;
            }
            let ty = get32(data, o);
            let obj_ptr = get32(data, o + 8);
            let cookie = get32(data, o + 12);
            match ty {
                OBJ_BINDER | OBJ_WEAK_BINDER => {
                    let weak = ty == OBJ_WEAK_BINDER;
                    let node = self.find_or_create_node(sender, obj_ptr, cookie);
                    if receiver == sender {
                        // Stays a local object.
                    } else {
                        let h = self.handle_for(receiver, node, weak);
                        put32(data, o, if weak { OBJ_WEAK_HANDLE } else { OBJ_HANDLE });
                        put32(data, o + 8, h);
                        put32(data, o + 12, 0);
                    }
                }
                OBJ_HANDLE | OBJ_WEAK_HANDLE => {
                    let weak = ty == OBJ_WEAK_HANDLE;
                    let node = match self.proc(sender).handles.get(&obj_ptr) {
                        Some(hi) => hi.node,
                        None => return false,
                    };
                    let n = &self.nodes[&node];
                    if receiver == n.owner {
                        // Back home: becomes the local object again.
                        let (p, c) = (n.ptr, n.cookie);
                        put32(data, o, if weak { OBJ_WEAK_BINDER } else { OBJ_BINDER });
                        put32(data, o + 8, p);
                        put32(data, o + 12, c);
                    } else if receiver == sender {
                        // Our own handle, looped back: unchanged.
                    } else {
                        let h = self.handle_for(receiver, node, weak);
                        put32(data, o, if weak { OBJ_WEAK_HANDLE } else { OBJ_HANDLE });
                        put32(data, o + 8, h);
                        put32(data, o + 12, 0);
                    }
                }
                OBJ_FD => {
                    // File descriptors need fd-table cooperation
                    // from the syscall layer; GB servicemanager
                    // traffic never carries them. Fail loudly
                    // rather than mistranslate.
                    return false;
                }
                _ => {
                    // Unknown object type (e.g. BINDER_TYPE_PTR
                    // from a newer stack): pass through.
                }
            }
        }
        true
    }

    fn queue_simple(&mut self, pid: u32, bytes: Vec<u8>) {
        self.proc(pid).inbox.push_back(BrItem::Bytes(bytes));
    }

    fn queue_u32(&mut self, pid: u32, cmd: u32) {
        self.queue_simple(pid, cmd.to_le_bytes().to_vec());
    }

    /// Full transaction entry with the parcel bytes already read
    /// from the sender's address space.
    pub fn do_transact(
        &mut self,
        sender: u32,
        is_reply: bool,
        target_handle: u32,
        code: u32,
        flags: u32,
        mut data: Vec<u8>,
        offsets: Vec<u32>,
    ) {
        let oneway = flags & TF_ONE_WAY != 0;
        if std::env::var_os("PAXCORE_BINDER_DEBUG").is_some() {
            let head: Vec<String> = data
                .iter()
                .take(32)
                .map(|b| format!("{b:02x}"))
                .collect();
            eprintln!(
                "[binder] transact sender={sender} reply={is_reply} handle={target_handle} code={code} dsize={} offs={:?} data={}",
                data.len(),
                offsets,
                head.join(" ")
            );
        }
        // Resolve the destination process.
        let (dest, node) = if is_reply {
            match self.proc(sender).inflight.pop() {
                Some(inf) => (inf.from, None),
                None => {
                    self.queue_u32(sender, BR_FAILED_REPLY);
                    return;
                }
            }
        } else if target_handle == 0 {
            match self.ctx_mgr {
                Some(n) => (self.nodes[&n].owner, Some(n)),
                None => {
                    self.queue_u32(sender, BR_DEAD_REPLY);
                    return;
                }
            }
        } else {
            match self.proc(sender).handles.get(&target_handle) {
                Some(hi) => {
                    let n = hi.node;
                    (self.nodes[&n].owner, Some(n))
                }
                None => {
                    self.queue_u32(sender, BR_FAILED_REPLY);
                    return;
                }
            }
        };
        if let Some(n) = node {
            if !self.nodes.contains_key(&n) {
                self.queue_u32(sender, BR_DEAD_REPLY);
                return;
            }
        }
        if !self.procs.contains_key(&dest) && dest != sender {
            // Owner process is gone (or never existed).
            self.queue_u32(sender, BR_DEAD_REPLY);
            return;
        }
        if !self.translate(sender, dest, &mut data, &offsets) {
            self.queue_u32(sender, BR_FAILED_REPLY);
            return;
        }
        if std::env::var_os("PAXCORE_BINDER_DEBUG").is_some() {
            eprintln!("[binder]   -> dest={dest} node={node:?}");
        }
        let (tptr, tcookie) = match node {
            Some(n) => {
                let nd = &self.nodes[&n];
                (nd.ptr, nd.cookie)
            }
            None => (0, 0),
        };
        self.proc(dest).inbox.push_back(BrItem::Txn {
            cmd: if is_reply { BR_REPLY } else { BR_TRANSACTION },
            sender_pid: if is_reply { 0 } else { sender },
            code,
            flags,
            target_ptr: tptr,
            cookie: tcookie,
            data,
            offsets,
        });
        // The receiver's inflight entry (for routing its future
        // BC_REPLY back here) is pushed when the transaction is
        // materialized in drain(), preserving stack order.
        if oneway && !is_reply {
            self.queue_u32(sender, BR_TRANSACTION_COMPLETE);
        }
    }

    /// Process a BC_* command stream from `pid`. Parcels for
    /// transactions are fetched through `fetch_parcel`, which
    /// reads (data, offsets) for a 40-byte transaction_data the
    /// core has just decoded. Returns bytes consumed.
    pub fn process_write(
        &mut self,
        pid: u32,
        cmds: &[u8],
        fetch_parcel: &mut dyn FnMut(&[u8]) -> (Vec<u8>, Vec<u32>),
    ) -> usize {
        let mut i = 0usize;
        while i + 4 <= cmds.len() {
            let cmd = get32(cmds, i);
            let payload = ((cmd >> 16) & 0x3FFF) as usize;
            if i + 4 + payload > cmds.len() {
                break;
            }
            let body = &cmds[i + 4..i + 4 + payload];
            match cmd {
                BC_ENTER_LOOPER | BC_REGISTER_LOOPER => {
                    self.proc(pid).looper = true;
                }
                BC_EXIT_LOOPER => {
                    self.proc(pid).looper = false;
                }
                BC_FREE_BUFFER => {
                    let ptr = get32(body, 0);
                    self.proc(pid).arena_free(ptr);
                }
                BC_INCREFS | BC_ACQUIRE | BC_RELEASE | BC_DECREFS => {
                    let h = get32(body, 0);
                    self.adjust_ref(pid, h, cmd);
                }
                BC_INCREFS_DONE | BC_ACQUIRE_DONE => {
                    // Owner acknowledging a notification: the
                    // matching node's told flag stays set (the
                    // reference exists); nothing further to do.
                }
                BC_ATTEMPT_ACQUIRE => {
                    // Only meaningful for local objects; the
                    // kernel would answer BR_ATTEMPT_ACQUIRE on
                    // the read side. GB libbinder uses it solely
                    // through weak refs to local objects, which
                    // never reach the driver with a handle.
                }
                BC_TRANSACTION | BC_REPLY => {
                    let (data, offsets) = fetch_parcel(body);
                    self.do_transact(
                        pid,
                        cmd == BC_REPLY,
                        get32(body, 0),
                        get32(body, 8),
                        get32(body, 12),
                        data,
                        offsets,
                    );
                }
                BC_REQUEST_DEATH_NOTIFICATION => {
                    let h = get32(body, 0);
                    let cookie = get32(body, 4);
                    if let Some(hi) = self.proc(pid).handles.get(&h) {
                        let node = hi.node;
                        self.proc(pid).death_reqs.push((node, cookie));
                    }
                }
                BC_CLEAR_DEATH_NOTIFICATION => {
                    let h = get32(body, 0);
                    let cookie = get32(body, 4);
                    let node = self.proc(pid).handles.get(&h).map(|hi| hi.node);
                    if let Some(n) = node {
                        let p = self.proc(pid);
                        p.death_reqs.retain(|&(dn, c)| !(dn == n && c == cookie));
                    }
                    let mut b = Vec::with_capacity(8);
                    b.extend_from_slice(&BR_CLEAR_DEATH_NOTIFICATION_DONE.to_le_bytes());
                    b.extend_from_slice(&cookie.to_le_bytes());
                    self.queue_simple(pid, b);
                }
                BC_DEAD_BINDER_DONE => {}
                _ => {
                    // Unknown command: the encoded payload size
                    // still lets us stay in sync.
                }
            }
            i += 4 + payload;
        }
        i
    }

    fn adjust_ref(&mut self, pid: u32, h: u32, cmd: u32) {
        let node = match self.proc(pid).handles.get(&h) {
            Some(hi) => hi.node,
            None => return,
        };
        let mut notify: Option<u32> = None;
        {
            let p = self.proc(pid);
            let hi = p.handles.get_mut(&h).unwrap();
            match cmd {
                BC_INCREFS => hi.weak += 1,
                BC_ACQUIRE => hi.strong += 1,
                BC_RELEASE => {
                    hi.strong = hi.strong.saturating_sub(1);
                    if hi.strong == 0 {
                        notify = Some(BR_RELEASE);
                    }
                }
                BC_DECREFS => {
                    hi.weak = hi.weak.saturating_sub(1);
                    if hi.weak == 0 {
                        notify = Some(BR_DECREFS);
                    }
                }
                _ => {}
            }
        }
        if let Some(br) = notify {
            let (owner, ptr, cookie) = {
                let n = &self.nodes[&node];
                (n.owner, n.ptr, n.cookie)
            };
            {
                let n = self.nodes.get_mut(&node).unwrap();
                if br == BR_RELEASE {
                    n.strong_told = false;
                } else {
                    n.weak_told = false;
                }
            }
            let mut b = Vec::with_capacity(12);
            b.extend_from_slice(&br.to_le_bytes());
            b.extend_from_slice(&ptr.to_le_bytes());
            b.extend_from_slice(&cookie.to_le_bytes());
            self.queue_simple(owner, b);
            // A fully released handle disappears.
            let p = self.proc(pid);
            let gone = p
                .handles
                .get(&h)
                .map(|hi| hi.strong == 0 && hi.weak == 0)
                .unwrap_or(false);
            if gone {
                let p = self.proc(pid);
                p.handles.remove(&h);
                p.by_node.remove(&node);
            }
        }
    }

    /// Move queued BR items into the caller's read buffer,
    /// materializing transaction payloads into its arena.
    /// Returns bytes written. Items that do not fit stay queued.
    pub fn drain(&mut self, pid: u32, mem: &mut Mem, read_ptr: u32, read_size: u32) -> u32 {
        let dbg = std::env::var_os("PAXCORE_BINDER_DEBUG").is_some();
        let inbox_len = self.proc(pid).inbox.len();
        if dbg && inbox_len > 0 {
            eprintln!("[binder] drain pid={pid} inbox={inbox_len}");
        }
        let mut written = 0u32;
        loop {
            let front_is_txn = match self.procs.get(&pid).and_then(|p| p.inbox.front()) {
                None => break,
                Some(BrItem::Bytes(b)) => {
                    if written + b.len() as u32 > read_size {
                        break;
                    }
                    false
                }
                Some(BrItem::Txn { .. }) => {
                    if written + 44 > read_size {
                        break;
                    }
                    true
                }
            };
            let item = self.proc(pid).inbox.pop_front().unwrap();
            match item {
                BrItem::Bytes(b) => {
                    mem.write_slice(read_ptr + written, &b);
                    written += b.len() as u32;
                }
                BrItem::Txn {
                    cmd,
                    sender_pid,
                    code,
                    flags,
                    target_ptr,
                    cookie,
                    data,
                    offsets,
                } => {
                    let total = data.len() as u32 + offsets.len() as u32 * 4;
                    let buf = match self.proc(pid).arena_alloc(total.max(8)) {
                        Some(b) => b,
                        None => {
                            // No arena room: fail the transaction
                            // visibly rather than dropping it.
                            let mut b = Vec::with_capacity(4);
                            b.extend_from_slice(&BR_FAILED_REPLY.to_le_bytes());
                            mem.write_slice(read_ptr + written, &b);
                            written += 4;
                            continue;
                        }
                    };
                    mem.write_slice(buf, &data);
                    let off_ptr = buf + data.len() as u32;
                    for (k, o) in offsets.iter().enumerate() {
                        mem.write_u32(off_ptr + 4 * k as u32, *o);
                    }
                    let mut td = [0u8; 44];
                    put32(&mut td, 0, cmd);
                    put32(&mut td, 4, target_ptr);
                    put32(&mut td, 8, cookie);
                    put32(&mut td, 12, code);
                    put32(&mut td, 16, flags);
                    put32(&mut td, 20, sender_pid);
                    put32(&mut td, 24, 0); // sender_euid: all root here
                    put32(&mut td, 28, data.len() as u32);
                    put32(&mut td, 32, (offsets.len() * 4) as u32);
                    put32(&mut td, 36, buf);
                    put32(&mut td, 40, off_ptr);
                    mem.write_slice(read_ptr + written, &td);
                    written += 44;
                    if cmd == BR_TRANSACTION {
                        self.proc(pid).inflight.push(InFlight {
                            from: sender_pid,
                        });
                    }
                    let _ = front_is_txn;
                }
            }
        }
        written
    }

    /// A process (thread group) is gone: kill its nodes, notify
    /// death listeners, drop its state, clear the manager slot.
    pub fn proc_died(&mut self, pid: u32) {
        let dead_nodes: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.owner == pid)
            .map(|(&id, _)| id)
            .collect();
        for &dn in &dead_nodes {
            self.nodes.remove(&dn);
            self.by_owner_ptr.retain(|_, v| *v != dn);
            if self.ctx_mgr == Some(dn) {
                self.ctx_mgr = None;
            }
        }
        // Death notifications + handle cleanup in other procs.
        let pids: Vec<u32> = self.procs.keys().copied().collect();
        for other in pids {
            if other == pid {
                continue;
            }
            let mut notes = Vec::new();
            {
                let p = self.proc(other);
                for &(dn, cookie) in &p.death_reqs {
                    if dead_nodes.contains(&dn) {
                        let mut b = Vec::with_capacity(8);
                        b.extend_from_slice(&BR_DEAD_BINDER.to_le_bytes());
                        b.extend_from_slice(&cookie.to_le_bytes());
                        notes.push(b);
                    }
                }
                p.death_reqs.retain(|&(dn, _)| !dead_nodes.contains(&dn));
                let dead_handles: Vec<u32> = p
                    .handles
                    .iter()
                    .filter(|(_, hi)| dead_nodes.contains(&hi.node))
                    .map(|(&h, _)| h)
                    .collect();
                for h in dead_handles {
                    if let Some(hi) = p.handles.remove(&h) {
                        p.by_node.remove(&hi.node);
                    }
                }
            }
            for b in notes {
                self.queue_simple(other, b);
            }
        }
        self.procs.remove(&pid);
    }
}
