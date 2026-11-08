@ vcmpprobe: VCMP.F32 (register form) + VMRS flag semantics.
@ The Dalvik portable interpreter's cmpg/cmpl-float rely on C
@ float compares, which compile to vcmp.f32/vmrs under softfp.
@ A T3 Java repro (cross-jar virtual call of a method checking
@ f <= 0.0f || f >= 1.0f) throws for f = 0.8: the value arrives
@ intact (the exception message prints 8.0E-1) but a compare
@ verdict is wrong.
@ Checks: for (0.8, 0.0): GT -> N=0 Z=0 C=1 V=0
@         for (0.8, 1.0): LT -> N=1 Z=0 C=0 V=0
@         for (0.8, 0.8): EQ -> N=0 Z=1 C=1 V=0
@ Also checks the operands survive (vcmp must not write Sd).
    .text
    .globl _start
_start:
    ldr r0, =0x3f4ccccd    @ 0.8f
    vmov s0, r0
    mov r0, #0
    vmov s1, r0            @ 0.0f
    vcmp.f32 s0, s1
    vmrs APSR_nzcv, FPSCR
    @ expect GT: Z=0, C=1, N=0
    bcs 1f
    b fail
1:  beq fail
    bmi fail
    @ (0.8, 1.0): expect LT: N=1, C=0
    ldr r0, =0x3f800000    @ 1.0f
    vmov s1, r0
    vcmp.f32 s0, s1
    vmrs APSR_nzcv, FPSCR
    bmi 2f
    b fail
2:  bcs fail
    @ (0.8, 0.8): expect EQ: Z=1, C=1
    vmov s1, s0
    vcmp.f32 s0, s1
    vmrs APSR_nzcv, FPSCR
    beq 3f
    b fail
3:  bcs 4f
    b fail
4:  @ operands intact: s0 still 0.8f
    vmov r0, s0
    ldr r1, =0x3f4ccccd
    cmp r0, r1
    bne fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
