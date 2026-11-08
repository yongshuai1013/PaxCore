@ vcmpeprobe: VCMPE.F32 (E bit set) register form.
@ (0.8, 1.0) must give LT: N=1, C=0. If the decoder mistakes
@ the E bit for a compare-with-zero selector, it compares
@ against 0.0 instead and reports GT.
    .text
    .globl _start
_start:
    ldr r0, =0x3f4ccccd    @ 0.8f
    vmov s0, r0
    ldr r0, =0x3f800000    @ 1.0f
    vmov s1, r0
    vcmpe.f32 s0, s1
    vmrs APSR_nzcv, FPSCR
    bmi 1f
    b fail
1:  bcs fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
