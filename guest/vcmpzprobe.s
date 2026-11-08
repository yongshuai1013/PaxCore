@ vcmpzprobe: VCMP.F32 with the +0.0 immediate form (bits 19-16
@ == 0101), isolated: it panicked as unimplemented (0xEEB50A40)
@ when appended to vcmpprobe.
    .text
    .globl _start
_start:
    ldr r0, =0x3f4ccccd    @ 0.8f
    vmov s0, r0
    vcmp.f32 s0, #0.0
    vmrs APSR_nzcv, FPSCR
    bcs 1f
    b fail
1:  beq fail
    bmi fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
