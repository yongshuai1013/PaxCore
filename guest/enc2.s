    .syntax unified
    .thumb
    .global _start
    .text
_start:
    sdiv r0, r1, r2
    udiv r0, r1, r2
    mls r0, r1, r2, r3
    ldr.w r0, [r1, #-8]
    ldr.w r0, [r1, #8]!
    ldr.w r0, [r1], #8
    ldr.w r0, [r1, r2, lsl #2]
    str.w r0, [r1, #-4]!
    ldrd r0, r1, [r2, #8]
    strd r0, r1, [r2]
    ldrb.w r0, [r1, #-1]
    pld [r1, #32]
    umaal r0, r3, r1, r2
