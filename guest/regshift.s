    .syntax unified
    .thumb
    .global _start
    .thumb_func
_start:
    movs r5, #0          @ failure bitmask

    @ lsr.w by register amount 0 -> value unchanged (dlmalloc case)
    ldr r0, =0x1
    movs r1, #0
    lsr.w r2, r0, r1
    cmp r2, #1
    it ne
    orrne r5, r5, #1

    @ lsr.w by 1 sanity: 0x80000000 -> 0x40000000
    ldr r0, =0x80000000
    movs r1, #1
    lsr.w r2, r0, r1
    ldr r3, =0x40000000
    cmp r2, r3
    it ne
    orrne r5, r5, #2

    @ asr.w by register amount 0 -> value unchanged (sign intact)
    ldr r0, =0x80000001
    movs r1, #0
    asr.w r2, r0, r1
    ldr r3, =0x80000001
    cmp r2, r3
    it ne
    orrne r5, r5, #4

    @ ror.w by register amount 0 -> value unchanged (NOT rrx)
    ldr r0, =0x12345678
    movs r1, #0
    ror.w r2, r0, r1
    ldr r3, =0x12345678
    cmp r2, r3
    it ne
    orrne r5, r5, #8

    @ lsl.w by register amount 0 -> value unchanged
    ldr r0, =0xABCDEF01
    movs r1, #0
    lsl.w r2, r0, r1
    ldr r3, =0xABCDEF01
    cmp r2, r3
    it ne
    orrne r5, r5, #16

    @ lsr.w by 32 (register form) -> 0
    ldr r0, =0xFFFFFFFF
    movs r1, #32
    lsr.w r2, r0, r1
    cmp r2, #0
    it ne
    orrne r5, r5, #32

    @ asr.w by 31 of negative -> 0xFFFFFFFF
    ldr r0, =0x80000000
    movs r1, #31
    asr.w r2, r0, r1
    ldr r3, =0xFFFFFFFF
    cmp r2, r3
    it ne
    orrne r5, r5, #64

    mov r0, r5
    movs r7, #1
    svc #0
