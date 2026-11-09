@ mul64probe: 64-bit multiply / divide family under sign
@ torture. FreeType's TT interpreter and auto-hinter run on
@ FT_MulDiv (64-bit) and fixed-point divides; a subtle
@ miscompute there poisons glyph outlines. Expected values
@ are exact 64-bit results computed independently.
@ Register plan: results in r0(lo)/r1(hi), compared against
@ literal constants loaded from the pool at the end.
    .text
    .globl _start
_start:
    @ SMULL: -16 * 16 = -256 -> lo 0xFFFFFF00 hi 0xFFFFFFFF
    mov r2, #-16
    mov r3, #16
    smull r0, r1, r2, r3
    ldr r4, =0xffffff00
    cmp r0, r4
    bne fail
    cmn r1, #1
    bne fail
    @ UMULL: 0x80000000 * 2 = 0x1_00000000 -> lo 0 hi 1
    ldr r2, =0x80000000
    mov r3, #2
    umull r0, r1, r2, r3
    cmp r0, #0
    bne fail
    cmp r1, #1
    bne fail
    @ SMLAL: acc 5 + (-3 * 7) = -16 -> lo 0xFFFFFFF0 hi -1
    mov r0, #5
    mov r1, #0
    mov r2, #-3
    mov r3, #7
    smlal r0, r1, r2, r3
    ldr r4, =0xfffffff0
    cmp r0, r4
    bne fail
    cmn r1, #1
    bne fail
    @ UMLAL: acc 0xFFFFFFFF_FFFFFFFF + (2*3) wraps -> lo 5 hi 0
    mvn r0, #0
    mvn r1, #0
    mov r2, #2
    mov r3, #3
    umlal r0, r1, r2, r3
    cmp r0, #5
    bne fail
    cmp r1, #0
    bne fail
    @ SMULH-ish via SMULL hi: -1 * -1 = 1 -> lo 1 hi 0 (done above pattern)
    @ UMULL big: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE_00000001
    mvn r2, #0
    mvn r3, #0
    umull r0, r1, r2, r3
    cmp r0, #1
    bne fail
    ldr r4, =0xfffffffe
    cmp r1, r4
    bne fail
    @ SDIV: -100 / 7 = -14 (trunc toward zero)
    mov r0, #-100
    mov r1, #7
    sdiv r0, r0, r1
    cmp r0, #-14
    bne fail
    @ SDIV: INT_MIN / -1 = INT_MIN (ARM: no trap, result = dividend)
    ldr r0, =0x80000000
    mvn r1, #0
    sdiv r0, r0, r1
    ldr r4, =0x80000000
    cmp r0, r4
    bne fail
    @ UDIV: 0xFFFFFFF0 / 16 = 0x0FFFFFFF
    ldr r0, =0xfffffff0
    mov r1, #16
    udiv r0, r0, r1
    ldr r4, =0x0fffffff
    cmp r0, r4
    bne fail
    @ SDIV by zero -> 0 on ARMv7
    mov r0, #42
    mov r1, #0
    sdiv r0, r0, r1
    cmp r0, #0
    bne fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
