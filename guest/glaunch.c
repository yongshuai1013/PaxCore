/* glaunch: test orchestrator (freestanding, no libc).
 *   glaunch raw : fork servicemanager + binderprobe serve,
 *                 then exec binderprobe ping.
 *   glaunch lb  : fork servicemanager + lbprobe serve,
 *                 then exec lbprobe ping.
 * The initial process group is the launcher's own, so when
 * the exec'd ping finishes, the whole run ends. */
typedef unsigned int u32;

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
static int sc3(int n, int a, int b, int c) {
    register int r7 __asm__("r7") = n;
    register int r0 __asm__("r0") = a;
    register int r1 __asm__("r1") = b;
    register int r2 __asm__("r2") = c;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
}

#define SYS_fork 2
#define SYS_execve 11
#define SYS_yield 158
#define SYS_exit_group 248

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void spawn(const char *path, const char *arg) {
    int pid = sc0(SYS_fork);
    if (pid == 0) {
        char *argv[3];
        argv[0] = (char *)path;
        argv[1] = (char *)arg;
        argv[2] = 0;
        char *envp[1];
        envp[0] = 0;
        sc3(SYS_execve, (int)path, (int)argv, (int)envp);
        sc1(SYS_exit_group, 127);
    }
}

int cmain(u32 *sp) {
    int argc = (int)sp[0];
    char **argv = (char **)(sp + 1);
    const char *mode = argc >= 2 ? argv[1] : "raw";
    spawn("/system/bin/servicemanager", (const char *)0);
    if (streq(mode, "lb") || streq(mode, "lbgot") || streq(mode, "lbprep")) {
        spawn("/system/bin/lbprobe", "serve");
        for (int i = 0; i < 200000; i++) sc0(SYS_yield);
        char *av[3];
        av[0] = "/system/bin/lbprobe";
        av[1] = streq(mode, "lbgot") ? "got" : streq(mode, "lbprep") ? "prep" : "ping";
        av[2] = 0;
        char *ev[1];
        ev[0] = 0;
        sc3(SYS_execve, (int)av[0], (int)av, (int)ev);
    } else {
        spawn("/system/bin/binderprobe", "serve");
        for (int i = 0; i < 200000; i++) sc0(SYS_yield);
        char *av[3];
        av[0] = "/system/bin/binderprobe";
        av[1] = "ping";
        av[2] = 0;
        char *ev[1];
        ev[0] = 0;
        sc3(SYS_execve, (int)av[0], (int)av, (int)ev);
    }
    return 126;
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
