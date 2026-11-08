@ vfp3probe: VFP three-register arithmetic (VMUL/VADD/VSUB/VDIV)
@ with destination registers whose packed number sets bit 22 of
@ the instruction word (odd S registers, D registers >= 16).
@ The ARM decoder gate must mask that bleed out of the opcode
@ field; libdvm dvmGetTargetHeapUtilization died on
@ vmul.f32 s15, s14, s15 (word EE677A27, op field reads 6).
@ Expected values are exact binary fractions -- no rounding fuzz.
    .text
    .globl _start
_start:
    @ load constants via vmov immediates
    vmov.f32 s14, #2.0
    vmov.f32 s13, #3.0
    vmov.f32 s12, #0.5
    @ case 1: vmul.f32 s15, s14, s13 -> 6.0 (odd dst; this is
    @ the libdvm case -- in a Thumb stream its bytes are
    @ EE67 7A27, the same word 0xEE677A27 the ARM decoder sees)
    vmul.f32 s15, s14, s13
    vmov r0, s15
    ldr r1, =0x40c00000 @ 6.0
    cmp r0, r1
    bne fail
    @ case 2: vadd.f32 s15, s14, s13 -> 5.0 (odd dst)
    vadd.f32 s15, s14, s13
    vmov r0, s15
    ldr r1, =0x40a00000 @ 5.0
    cmp r0, r1
    bne fail
    @ case 3: vsub.f32 s13, s14, s12 -> 1.5 (odd dst)
    vsub.f32 s13, s14, s12
    vmov r0, s13
    ldr r1, =0x3fc00000 @ 1.5
    cmp r0, r1
    bne fail
    @ case 4: vdiv.f32 s15, s14, s12 -> 4.0 (odd dst)
    vdiv.f32 s15, s14, s12
    vmov r0, s15
    ldr r1, =0x40800000 @ 4.0
    cmp r0, r1
    bne fail
    @ case 5: vmul.f32 s14, s14, s12 -> 1.0 (even dst, control)
    vmul.f32 s14, s14, s12
    vmov r0, s14
    ldr r1, =0x3f800000 @ 1.0
    cmp r0, r1
    bne fail
    @ case 6: vmul.f64 d7, d6, d6 -> 4.0 (f64 control; the GB
    @ target is vfpv3-d16, so Dd >= 16 encodings cannot occur)
    vmov.f64 d6, #2.0
    vmul.f64 d7, d6, d6
    vmov r0, r1, d7
    ldr r2, =0x40100000 @ high word of 4.0
    cmp r1, r2
    bne fail
    cmp r0, #0
    bne fail
    @ pass
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
