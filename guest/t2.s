    .syntax unified
    .thumb
    .global _start
    .text
_start:
    sdiv r0, r1, r2
    udiv r0, r1, r2
    mls r0, r1, r2, r3
    ldrd r0, r1, [r2, #8]
    ldr.w r0, [r1, r2, lsl #2]
    pld [r1, #32]
