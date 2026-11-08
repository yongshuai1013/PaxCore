/* Minimal AEABI memory helpers for the freestanding probes
 * (clang emits these once auto-vectorization is off). */
typedef unsigned int u32;

void *__aeabi_memset(void *d, int n, int c) {
    unsigned char *p = (unsigned char *)d;
    for (int i = 0; i < n; i++) p[i] = (unsigned char)c;
    return d;
}
void *__aeabi_memclr(void *d, int n) { return __aeabi_memset(d, n, 0); }
void *__aeabi_memclr4(void *d, int n) { return __aeabi_memset(d, n, 0); }
void *__aeabi_memclr8(void *d, int n) { return __aeabi_memset(d, n, 0); }
void *__aeabi_memcpy(void *d, const void *s, int n) {
    unsigned char *dd = (unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    for (int i = 0; i < n; i++) dd[i] = ss[i];
    return d;
}
void *__aeabi_memcpy4(void *d, const void *s, int n) {
    return __aeabi_memcpy(d, s, n);
}
void *__aeabi_memcpy8(void *d, const void *s, int n) {
    return __aeabi_memcpy(d, s, n);
}
void *__aeabi_memmove(void *d, const void *s, int n) {
    unsigned char *dd = (unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    if (dd < ss) {
        for (int i = 0; i < n; i++) dd[i] = ss[i];
    } else {
        for (int i = n - 1; i >= 0; i--) dd[i] = ss[i];
    }
    return d;
}
