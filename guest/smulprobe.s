@ smulprobe: ARMv5TE DSP signed halfword multiplies.
@ Core bug #14: this whole family used to fall through
@ every dispatcher and get silently skipped, which broke
@ FreeType's contour-end computation (smulbb of
@ contours[0] * 40) and sent zygote preload into a spin.
@ Expected values are exact small-integer results.
    .text
    .globl _start
_start:
    @ 1. SMULBB exact FreeType case, poisoned high half:
    @    low(0xDEAD0013)=19, 19 * 40 = 760
    ldr r2, =0xdead0013
    mov r3, #40
    smulbb r0, r2, r3
    ldr r4, =760
    cmp r0, r4
    bne fail
    @ 2. SMULBB negatives: (-3) * (-7) = 21
    ldr r2, =0x0000fffd
    ldr r3, =0x0000fff9
    smulbb r0, r2, r3
    cmp r0, #21
    bne fail
    @ 3. SMULTB: top(Rm)=3 * bottom(Rs)=5 = 15
    ldr r2, =0x00030000
    mov r3, #5
    smultb r0, r2, r3
    cmp r0, #15
    bne fail
    @ 4. SMULBT: bottom(Rm)=6 * top(Rs)=-2 = -12
    mov r2, #6
    ldr r3, =0xfffe0000
    smulbt r0, r2, r3
    cmn r0, #12
    bne fail
    @ 5. SMULTT: (-2) * 7 = -14
    ldr r2, =0xfffe0000
    ldr r3, =0x00070000
    smultt r0, r2, r3
    cmn r0, #14
    bne fail
    @ 6. SMLABB: 100 + 6 * 7 = 142
    mov r2, #6
    mov r3, #7
    mov r4, #100
    smlabb r0, r2, r3, r4
    cmp r0, #142
    bne fail
    @ 7. SMULWB: (0x10000 * 2) >> 16 = 2
    ldr r2, =0x00010000
    mov r3, #2
    smulwb r0, r2, r3
    cmp r0, #2
    bne fail
    @ 8. SMLAWT: 10 + (0x20000 * 3) >> 16 = 10 + 6 = 16
    ldr r2, =0x00020000
    ldr r3, =0x00030000
    mov r4, #10
    smlawt r0, r2, r3, r4
    cmp r0, #16
    bne fail
    @ 9. SMLALBB: acc 5 + (-1) * 10 = -5 (borrow into hi)
    mov r0, #5
    mov r1, #0
    ldr r2, =0x0000ffff
    mov r3, #10
    smlalbb r0, r1, r2, r3
    ldr r4, =0xfffffffb
    cmp r0, r4
    bne fail
    cmn r1, #1
    bne fail
    @ 10. SMULBB clean regs, guest's exact registers:
    @     smulbb r5, r3, r1 with r3=19, r1=40 -> r5=760
    mov r3, #19
    mov r1, #40
    mov r5, #-1
    smulbb r5, r3, r1
    ldr r4, =760
    cmp r5, r4
    bne fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
