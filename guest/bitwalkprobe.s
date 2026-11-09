@ bitwalkprobe: Thumb-2 bit-scan operations as used by
@ Dalvik's HeapBitmap walk (ffs-style: find lowest set bit,
@ clear it, repeat). Boot5 PC sampling showed zygote trapped
@ inside a single dvmHeapScanMarkedObjects call for 24.5B
@ steps -- the classic signature of a bitmap walk that keeps
@ finding the same bit set.
@ Checks:
@   clz(0x80000000) == 0, clz(1) == 31, clz(0x00010000) == 15
@   rbit(0x80000000) == 1, rbit(0x12345678) == 0x1e6a2c48
@   ffs-walk over {0x00000009, 0x80000000}: visits bits
@   0, 3 (word 0), 31 (word 1) exactly once each, then ends.
    .text
    .thumb
    .globl _start
    .thumb_func
_start:
    @ --- CLZ ---
    ldr r0, =0x80000000
    clz r1, r0
    cmp r1, #0
    bne fail
    movs r0, #1
    clz r1, r0
    cmp r1, #31
    bne fail
    ldr r0, =0x00010000
    clz r1, r0
    cmp r1, #15
    bne fail
    @ --- RBIT ---
    ldr r0, =0x80000000
    rbit r1, r0
    cmp r1, #1
    bne fail
    ldr r0, =0x12345678
    rbit r1, r0
    ldr r2, =0x1e6a2c48
    cmp r1, r2
    bne fail
    @ --- ffs-style walk: r4 = word, count visits in r5 ---
    @ word0 = 0x9 (bits 0 and 3): ffs uses rbit+clz or
    @ neg-and-isolate; emulate the compiler's sequence:
    @   low = w & -w; idx via clz(rbit(low))
    ldr r4, =0x00000009
    movs r5, #0
walk0:
    cmp r4, #0
    beq walk1
    negs r0, r4
    ands r0, r4, r0        @ isolate lowest set bit
    rbit r1, r0
    clz r1, r1             @ bit index
    @ expect sequence 0 then 3
    cmp r5, #0
    bne 1f
    cmp r1, #0
    bne fail
    b 2f
1:  cmp r5, #1
    bne fail
    cmp r1, #3
    bne fail
2:  adds r5, #1
    eors r4, r4, r0        @ clear the bit
    b walk0
walk1:
    cmp r5, #2
    bne fail
    @ word1 = 0x80000000: single visit, index 31
    ldr r4, =0x80000000
    negs r0, r4
    ands r0, r4, r0
    rbit r1, r0
    clz r1, r1
    cmp r1, #31
    bne fail
    mov r7, #1
    movs r0, #0
    svc #0
fail:
    mov r7, #1
    movs r0, #1
    svc #0
