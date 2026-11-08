    .syntax unified
    .thumb
    .global _start
    .thumb_func
_start:
    movs r5, #0          @ failure counter

    @ ubfx r2, r0, #1, #1 with r0=0 -> 0  (the dlmalloc case)
    movs r0, #0
    ubfx r2, r0, #1, #1
    cmp r2, #0
    it ne
    orrne r5, r5, #1

    @ ubfx r0, r7, #20, #11 with r7=0x7EA00000 -> 0x7EA
    ldr r7, =0x7EA00000
    ubfx r0, r7, #20, #11
    ldr r1, =0x7EA
    cmp r0, r1
    it ne
    orrne r5, r5, #2

    @ ubfx r3, r4, #0, #32 with r4=0xDEADBEEF -> 0xDEADBEEF
    ldr r4, =0xDEADBEEF
    ubfx r3, r4, #0, #32
    ldr r1, =0xDEADBEEF
    cmp r3, r1
    it ne
    orrne r5, r5, #4

    @ sbfx r0, r1, #0, #8 with r1=0xF0 -> 0xFFFFFFF0
    movs r1, #0xF0
    sbfx r0, r1, #0, #8
    ldr r2, =0xFFFFFFF0
    cmp r0, r2
    it ne
    orrne r5, r5, #8

    @ sbfx r0, r1, #4, #8 with r1=0x70 -> 0x07
    movs r1, #0x70
    sbfx r0, r1, #4, #8
    cmp r0, #7
    it ne
    orrne r5, r5, #16

    @ bfi r0, r1, #8, #8: r0=0xAAAAAAAA, r1=0x3C -> 0xAAAA3CAA
    ldr r0, =0xAAAAAAAA
    movs r1, #0x3C
    bfi r0, r1, #8, #8
    ldr r2, =0xAAAA3CAA
    cmp r0, r2
    it ne
    orrne r5, r5, #32

    @ bfc r0, #8, #8: r0=0xAAAAAAAA -> 0xAAAA00AA
    ldr r0, =0xAAAAAAAA
    bfc r0, #8, #8
    ldr r2, =0xAAAA00AA
    cmp r0, r2
    it ne
    orrne r5, r5, #64

    @ exit(failures)
    mov r0, r5
    movs r7, #1
    svc #0
