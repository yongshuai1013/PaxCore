/* binderprobe: raw binder-protocol probe (freestanding, no libc).
 * Modes:
 *   serve  register "pax.test" with the service manager, then
 *          answer code-1 transactions: request parcel carries an
 *          int32 after the interface token; reply parcel is a
 *          single int32 = value + 0x4444.
 *   ping   look up "pax.test", transact with 0x1234, expect the
 *          reply int32 0x5678; exit 0 only on an exact match.
 * Exit codes: 11 open fail, 12 no service, 13 bad reply,
 *             14 add-service fail, 15 transact fail. */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

static int sc0(int n) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = 0;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}
static int sc1(int n, int a) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}
static int sc2(int n, int a, int b) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    register int r1 __asm__("r1") = b;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1) : "memory");
    return r0;
}
static int sc3(int n, int a, int b, int c) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    register int r1 __asm__("r1") = b;
    register int r2 __asm__("r2") = c;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
}
static int sc6(int n, int a, int b, int c, int d, int e, int f) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    register int r1 __asm__("r1") = b;
    register int r2 __asm__("r2") = c;
    register int r3 __asm__("r3") = d;
    register int r4 __asm__("r4") = e;
    register int r5 __asm__("r5") = f;
    __asm__ volatile("svc #0" : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory");
    return r0;
}

#define SYS_write 4
#define SYS_open 5
#define SYS_exit_group 248
#define SYS_ioctl 54
#define SYS_mmap2 192
#define SYS_yield 158

#define BINDER_WRITE_READ 0xC0186201u
#define BINDER_SET_CONTEXT_MGR 0x40046207u
#define BC_TRANSACTION 0x40286300u
#define BC_REPLY 0x40286301u
#define BC_FREE_BUFFER 0x40046303u
#define BC_INCREFS_DONE 0x40086308u
#define BC_ACQUIRE_DONE 0x40086309u
#define BC_ENTER_LOOPER 0x0000630cu
#define BR_ERROR 0x80047200u
#define BR_OK 0x7201u
#define BR_TRANSACTION 0x80287202u
#define BR_REPLY 0x80287203u
#define BR_DEAD_REPLY 0x7205u
#define BR_TRANSACTION_COMPLETE 0x7206u
#define BR_INCREFS 0x80087207u
#define BR_ACQUIRE 0x80087208u
#define BR_RELEASE 0x80087209u
#define BR_DECREFS 0x8008720au
#define BR_NOOP 0x720cu
#define BR_SPAWN_LOOPER 0x720du
#define BR_DEAD_BINDER 0x8004720fu
#define BR_FAILED_REPLY 0x7211u

#define OBJ_BINDER 0x73622a85u
#define OBJ_HANDLE 0x73682a85u

struct bwr {
    u32 write_size, write_consumed, write_buffer;
    u32 read_size, read_consumed, read_buffer;
};

static void puts1(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sc3(SYS_write, 1, (int)s, n);
}
static void puthex(u32 v) {
    char b[11];
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; i++) {
        int d = (v >> (28 - 4 * i)) & 15;
        b[2 + i] = d < 10 ? '0' + d : 'a' + d - 10;
    }
    b[10] = '\n';
    sc3(SYS_write, 1, (int)b, 11);
}
static void die(int code, const char *msg) {
    puts1(msg);
    sc1(SYS_exit_group, code);
    __builtin_unreachable();
}

/* ---- parcel builder ---- */
struct parcel {
    u8 *data;
    u32 cap, len;
    u32 offs[8];
    u32 noffs;
};
static void p_init(struct parcel *p, u8 *buf, u32 cap) {
    p->data = buf; p->cap = cap; p->len = 0; p->noffs = 0;
}
static void p_u32(struct parcel *p, u32 v) {
    *(u32 *)(p->data + p->len) = v;
    p->len += 4;
}
static void p_str16(struct parcel *p, const char *s) {
    int n = 0;
    while (s[n]) n++;
    p_u32(p, (u32)n);
    for (int i = 0; i <= n; i++) {
        *(u16 *)(p->data + p->len) = (u16)(u8)s[i];
        p->len += 2;
    }
    while (p->len & 3) p->data[p->len++] = 0;
}
static void p_token(struct parcel *p, const char *iface) {
    p_u32(p, 0); /* strict-mode word the C manager skips */
    p_str16(p, iface);
}
static void p_binder(struct parcel *p, u32 ptr, u32 cookie) {
    p->offs[p->noffs++] = p->len;
    p_u32(p, OBJ_BINDER);
    p_u32(p, 0); /* flags */
    p_u32(p, ptr);
    p_u32(p, cookie);
}

/* ---- driver session ---- */
static int g_fd;
static u8 g_rbuf[4096];
static u8 g_wbuf[4096];

static int do_bwr_x(u8 *w, u32 wlen, u32 rsize) {
    struct bwr b;
    b.write_size = wlen;
    b.write_consumed = 0;
    b.write_buffer = (u32)w;
    b.read_size = rsize;
    b.read_consumed = 0;
    b.read_buffer = (u32)g_rbuf;
    int r = sc3(SYS_ioctl, g_fd, (int)BINDER_WRITE_READ, (int)&b);
    if (r < 0) return r;
    return (int)b.read_consumed;
}
static int do_bwr(u8 *w, u32 wlen) {
    return do_bwr_x(w, wlen, sizeof(g_rbuf));
}
/* Write-only BWR (read_size 0): for ENTER_LOOPER and
 * FREE_BUFFER flushes, whose read side must not drain --
 * a draining call here would swallow a pending transaction
 * nobody parses. */
static int do_bwr_wo(u8 *w, u32 wlen) { return do_bwr_x(w, wlen, 0); }

/* One synchronous transaction: fill write side with a single
 * BC_TRANSACTION, then keep calling BWR (empty write side)
 * until BR_REPLY / BR_DEAD_REPLY / BR_FAILED_REPLY arrives.
 * Reply parcel bytes land in out/outlen; leftover commands in
 * the read stream (INCREFS etc.) are answered inline. */
static u32 g_free_list[16];
static int g_nfree;

static int transact(u32 handle, u32 code, struct parcel *data,
                    u8 *out, u32 *outlen) {
    u32 tr[11];
    tr[0] = handle;
    tr[1] = 0; /* cookie */
    tr[2] = code;
    tr[3] = 0; /* flags */
    tr[4] = 0; /* sender pid (driver fills) */
    tr[5] = 0; /* sender euid */
    tr[6] = data->len;
    tr[7] = data->noffs * 4;
    tr[8] = (u32)data->data;
    tr[9] = (u32)data->offs;
    tr[10] = 0;
    u8 *w = g_wbuf;
    *(u32 *)w = BC_TRANSACTION;
    for (int i = 0; i < 11; i++) *(u32 *)(w + 4 + 4 * i) = tr[i];
    int first = 1;
    for (;;) {
        int n = do_bwr(first ? w : (u8 *)0, first ? 48 : 0);
        first = 0;
        if (n < 0) return -1;
        u32 pos = 0;
        while (pos + 4 <= (u32)n) {
            u32 cmd = *(u32 *)(g_rbuf + pos);
            pos += 4;
            switch (cmd) {
            case BR_TRANSACTION_COMPLETE:
            case BR_NOOP:
            case BR_OK:
                break;
            case BR_INCREFS:
            case BR_ACQUIRE: {
                /* peer took a ref on one of our objects */
                pos += 8; /* ptr + cookie: nothing to answer */
                break;
            }
            case BR_REPLY: {
                u32 *t = (u32 *)(g_rbuf + pos);
                u32 dsz = t[6];
                u8 *dp = (u8 *)t[8];
                for (u32 i = 0; i < dsz; i++) out[i] = dp[i];
                *outlen = dsz;
                if (g_nfree < 16) g_free_list[g_nfree++] = t[8];
                return 0;
            }
            case BR_DEAD_REPLY:
                return -2;
            case BR_FAILED_REPLY:
            case BR_ERROR:
                return -3;
            default:
                return -4;
            }
        }
        for (int i = 0; i < g_nfree; i++) {
            /* buffers are freed by the next write round below */
        }
        if (g_nfree) {
            u8 fb[16];
            *(u32 *)fb = BC_FREE_BUFFER;
            *(u32 *)(fb + 4) = g_free_list[0];
            g_nfree = 0;
            do_bwr_wo(fb, 8);
        }
    }
}

static u8 g_pbuf[1024];
static u8 g_out[1024];

static void open_driver(void) {
    g_fd = sc2(SYS_open, (int)"/dev/binder", 2);
    if (g_fd < 0) die(11, "open /dev/binder failed\n");
    int r = sc6(SYS_mmap2, 0, 128 * 1024, 1, 0x22, g_fd, 0);
    if (r < 0) die(11, "binder mmap failed\n");
}

static int add_service(void) {
    struct parcel p;
    p_init(&p, g_pbuf, sizeof(g_pbuf));
    p_token(&p, "android.os.IServiceManager");
    p_str16(&p, "pax.test");
    p_binder(&p, 0x1000, 0xC0FFEE);
    u32 olen = 0;
    int r = transact(0, 3, &p, g_out, &olen);
    if (r != 0) return r;
    if (olen < 4 || *(u32 *)g_out != 0) return -5;
    return 0;
}

static int serve(void) {
    open_driver();
    int ok = -1;
    for (int i = 0; i < 2000 && ok != 0; i++) {
        ok = add_service();
        if (ok != 0) sc0(SYS_yield);
    }
    if (ok != 0) die(14, "add_service failed\n");
    puts1("SERVE READY\n");
    u8 w[4];
    *(u32 *)w = BC_ENTER_LOOPER;
    do_bwr_wo(w, 4);
    u8 donebuf[64];
    u32 dlen = 0;
    int pend_reply = 0;
    u32 pend_val = 0, pend_free = 0;
    for (;;) {
        int n = do_bwr(donebuf, dlen);
        dlen = 0;
        if (n < 0) continue;
        u32 pos = 0;
        while (pos + 4 <= (u32)n) {
            u32 cmd = *(u32 *)(g_rbuf + pos);
            pos += 4;
            if (cmd == BR_NOOP || cmd == BR_OK) {
                continue;
            } else if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
                u32 ptr = *(u32 *)(g_rbuf + pos);
                u32 bc = cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE;
                *(u32 *)(donebuf + dlen) = bc;
                *(u32 *)(donebuf + dlen + 4) = ptr;
                *(u32 *)(donebuf + dlen + 8) = *(u32 *)(g_rbuf + pos + 4);
                dlen += 12;
                pos += 8;
            } else if (cmd == BR_TRANSACTION) {
                u32 *t = (u32 *)(g_rbuf + pos);
                u32 code = t[2];
                u32 dsz = t[6];
                u8 *dp = (u8 *)t[8];
                u32 val = 0xdeadbeef;
                if (dsz >= 4) {
                    /* skip strict word + interface string16 */
                    u32 q = 4;
                    u32 sl = *(u32 *)(dp + q);
                    q += 4 + (sl + 1) * 2;
                    q = (q + 3) & ~3u;
                    if (q + 4 <= dsz) val = *(u32 *)(dp + q);
                }
                pos += 44;
                /* Defer the reply until the batch is fully
                 * parsed: sending it now would refill g_rbuf
                 * (the buffer being parsed) on its read side. */
                pend_reply = 1;
                pend_val = val + 0x4444;
                pend_free = (u32)dp;
                (void)code;
            } else {
                /* unknown command: stop parsing this batch */
                pos = (u32)n;
            }
        }
        if (pend_reply) {
            pend_reply = 0;
            u8 rp[4];
            *(u32 *)rp = pend_val;
            u8 wb[64];
            *(u32 *)wb = BC_REPLY;
            u32 *rt = (u32 *)(wb + 4);
            for (int i = 0; i < 11; i++) rt[i] = 0;
            rt[6] = 4;
            rt[8] = (u32)rp;
            *(u32 *)(wb + 48) = BC_FREE_BUFFER;
            *(u32 *)(wb + 52) = pend_free;
            do_bwr_wo(wb, 56);
        }
    }
}

static int ping(void) {
    open_driver();
    u32 handle = 0;
    for (int i = 0; i < 4000 && !handle; i++) {
        struct parcel p;
        p_init(&p, g_pbuf, sizeof(g_pbuf));
        p_token(&p, "android.os.IServiceManager");
        p_str16(&p, "pax.test");
        u32 olen = 0;
        int r = transact(0, 1, &p, g_out, &olen);
        if (r == 0 && olen >= 16) {
            /* reply parcel: flat object for the service */
            u32 off = 0;
            /* a leading int32 status may precede the object */
            if (olen >= 20 && *(u32 *)(g_out + 4) == OBJ_HANDLE)
                off = 4;
            u32 *o = (u32 *)(g_out + off);
            if (o[0] == OBJ_HANDLE) handle = o[2];
        }
        if (!handle) sc0(SYS_yield);
    }
    if (!handle) die(12, "get_service: no handle\n");
    puts1("GOT HANDLE\n");
    struct parcel p;
    p_init(&p, g_pbuf, sizeof(g_pbuf));
    p_token(&p, "pax.test.iface");
    p_u32(&p, 0x1234);
    u32 olen = 0;
    int r = transact(handle, 1, &p, g_out, &olen);
    if (r != 0) die(15, "transact failed\n");
    if (olen < 4 || *(u32 *)g_out != 0x5678) {
        puts1("BAD REPLY ");
        puthex(olen >= 4 ? *(u32 *)g_out : 0xffffffff);
        die(13, "");
    }
    puts1("PING OK 0x5678\n");
    return 0;
}

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

int cmain(u32 *sp) {
    int argc = (int)sp[0];
    char **argv = (char **)(sp + 1);
    if (argc >= 2 && streq(argv[1], "serve")) return serve();
    if (argc >= 2 && streq(argv[1], "ping")) return ping();
    puts1("usage: binderprobe serve|ping\n");
    return 2;
}

__asm__(
    ".text\n"
    ".globl _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "    mov r0, sp\n"
    "    bl cmain\n"
    "    mov r7, #248\n"
    "    svc #0\n");
