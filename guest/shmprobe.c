/* shmprobe: MAP_SHARED semantics probe (freestanding).
 *   main : create+ftruncate /data/shmfile, mmap MAP_SHARED,
 *          plant patterns, fork (child verifies + writes,
 *          parent verifies child's writes after wait4), then
 *          fork+exec self in "check" mode (fresh address
 *          space, mmaps the same path, verifies everything
 *          and writes back; parent verifies after wait4).
 *   check: the exec'd role described above.
 * Exit code = failure bitmask (0 = all pass). Prints
 * SHM_MAIN_FAIL_<n> / SHM_OK markers on stdout. */
typedef unsigned int u32;
typedef unsigned char u8;

static int sc1(int n, int a) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
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
static int sc4(int n, int a, int b, int c, int d) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    register int r1 __asm__("r1") = b;
    register int r2 __asm__("r2") = c;
    register int r3 __asm__("r3") = d;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3)
                     : "memory");
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
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory");
    return r0;
}

static void puts1(const char *s) {
    int n = 0;
    while (s[n])
        n++;
    sc3(4, 1, (int)s, n);
}
static void exit_(int code) { sc1(248, code); __builtin_unreachable(); }

#define SIZE 131072
static volatile u32 *W;   /* word view of the mapping */
static volatile u8 *B;    /* byte view */

static void plant_p1(void) { /* 16 bytes crossing the 64K edge */
    for (int i = 0; i < 16; i++)
        B[65528 + i] = (u8)(0xA0 + i);
}
static int check_p1(void) {
    for (int i = 0; i < 16; i++)
        if (B[65528 + i] != (u8)(0xA0 + i))
            return 0;
    return 1;
}
static void plant_p2(void) {
    for (int i = 0; i < 16; i++)
        B[70000 + i] = (u8)(0x50 + i);
}
static int check_p2(void) {
    for (int i = 0; i < 16; i++)
        if (B[70000 + i] != (u8)(0x50 + i))
            return 0;
    return 1;
}

static int map_file(int creat) {
    int fd = sc3(5, (int)"/data/shmfile", creat ? (0x2 | 0x40) : 0x2, 0600);
    if (fd < 0)
        return -1;
    if (creat)
        sc3(93, fd, SIZE, 0); /* ftruncate(fd, SIZE) */
    int p = sc6(192, 0, SIZE, 3, 1 /*MAP_SHARED*/, fd, 0);
    if (p < 0)
        return -2;
    W = (volatile u32 *)(u32)p;
    B = (volatile u8 *)(u32)p;
    return 0;
}

static int role_check(void) {
    int mask = 0;
    if (map_file(0) != 0)
        return 64;
    if (W[0] != 0xA5A51111u)
        mask |= 1;
    if (W[16381] != 0x5A5A2222u)
        mask |= 2;
    if (!check_p1())
        mask |= 4;
    if (W[2] != 0xC0FFEE00u)
        mask |= 8;
    W[4] = 0xD15EA5E0u;
    return mask;
}

int cmain(u32 sp) {
    u32 argc = *(u32 *)sp;
    char **argv = (char **)(sp + 4);
    if (argc > 1 && argv[1][0] == 'c') { /* "check" */
        int m = role_check();
        if (m == 0)
            puts1("SHM_CHECK_OK\n");
        exit_(m);
    }

    int mask = 0;
    sc1(10, (int)"/data/shmfile"); /* unlink stale */
    if (map_file(1) != 0) {
        puts1("SHM_MAP_FAIL\n");
        exit_(32);
    }
    W[0] = 0xA5A51111u;
    W[1024] = 0x11112222u;
    W[16381] = 0x5A5A2222u; /* just before the P1 span */
    plant_p1();              /* bytes 65528..65543, crosses 64K */
    W[16386] = 0x5A5A3333u;  /* just after the P1 span */
    W[32767] = 0x7FFF3333u;

    { /* self-check: parent reads back through its own mapping */
        int sm = 0;
        if (W[0] != 0xA5A51111u)
            sm |= 1;
        if (W[1024] != 0x11112222u)
            sm |= 2;
        if (W[16381] != 0x5A5A2222u)
            sm |= 4;
        if (!check_p1())
            sm |= 8;
        if (W[16386] != 0x5A5A3333u)
            sm |= 16;
        if (W[32767] != 0x7FFF3333u)
            sm |= 32;
        if (sm) {
            puts1("SHM_SELF_FAIL\n");
            exit_(40 + sm);
        }
    }

    int pid = sc1(2, 0); /* fork */
    if (pid == 0) {
        int cm = 0;
        if (W[0] != 0xA5A51111u)
            cm |= 1;
        if (W[1024] != 0x11112222u)
            cm |= 2;
        if (W[16381] != 0x5A5A2222u)
            cm |= 4;
        if (!check_p1())
            cm |= 8;
        if (W[16386] != 0x5A5A3333u)
            cm |= 32;
        if (W[32767] != 0x7FFF3333u)
            cm |= 16;
        W[2] = 0xC0FFEE00u;
        plant_p2();
        exit_(cm);
    }
    if (pid < 0) {
        puts1("SHM_FORK_FAIL\n");
        exit_(33);
    }
    int status = 0;
    sc4(114, pid, (int)&status, 0, 0); /* wait4 */
    if (((status >> 8) & 0xff) != 0)
        mask |= 1; /* fork child verify/write failed */
    if (W[2] != 0xC0FFEE00u)
        mask |= 2; /* child's word write invisible */
    if (!check_p2())
        mask |= 4; /* child's byte writes invisible */

    int pid2 = sc1(2, 0);
    if (pid2 == 0) {
        char *args[3];
        args[0] = "shmprobe";
        args[1] = "check";
        args[2] = 0;
        char *env[1];
        env[0] = 0;
        sc3(11, (int)"/system/bin/shmprobe", (int)args, (int)env);
        exit_(90); /* exec failed */
    }
    status = 0;
    sc4(114, pid2, (int)&status, 0, 0);
    if (((status >> 8) & 0xff) != 0)
        mask |= 8; /* exec'd child verify failed */
    if (W[4] != 0xD15EA5E0u)
        mask |= 16; /* exec'd child's write invisible */

    if (mask == 0)
        puts1("SHM_OK\n");
    else
        puts1("SHM_FAIL\n");
    return mask;
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
