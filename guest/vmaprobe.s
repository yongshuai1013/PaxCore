@ vmaprobe: VFP multiply-accumulate family.
@ vmla.f32 in Skia's font-scaling path panicked the core
@ (0xEE470A08 at a guest library). Cases (exact binary
@ fractions, bit-pattern compared):
@   acc=1.5, n=2.0, m=3.0 (prod=6.0):
@   vmla  ->  7.5  (0x40F00000)
@   vmls  -> -4.5  (0xC0900000)
@   vnmls ->  4.5  (0x40900000)
@   vnmla -> -7.5  (0xC0F00000)
@   vnmla.f64 -> -7.5 (0xC01E000000000000)
    .text
    .globl _start
_start:
    ldr r0, =0x3fc00000      @ 1.5f
    vmov s0, r0              @ acc
    ldr r0, =0x40000000      @ 2.0f
    vmov s1, r0              @ n
    ldr r0, =0x40400000      @ 3.0f
    vmov s2, r0              @ m
    vmov s3, s0
    vmla.f32 s3, s1, s2
    vmov r1, s3
    ldr r0, =0x40f00000
    cmp r1, r0
    bne fail
    vmov s3, s0
    vmls.f32 s3, s1, s2
    vmov r1, s3
    ldr r0, =0xc0900000
    cmp r1, r0
    bne fail
    vmov s3, s0
    vnmls.f32 s3, s1, s2
    vmov r1, s3
    ldr r0, =0x40900000
    cmp r1, r0
    bne fail
    vmov s3, s0
    vnmla.f32 s3, s1, s2
    vmov r1, s3
    ldr r0, =0xc0f00000
    cmp r1, r0
    bne fail
    @ Even destination registers: Vd's low bit is 0, so
    @ op reads 0x0/0x1 instead of 0x4/0x5 (the guest's
    @ actual failing case: vmla.f32 s6, s7, s16).
    vmov s7, s1              @ n = 2.0
    vmov s16, s2             @ m = 3.0
    vmov s6, s0
    vmla.f32 s6, s7, s16
    vmov r1, s6
    ldr r0, =0x40f00000
    cmp r1, r0
    bne fail
    vmov s8, s0
    vmls.f32 s8, s7, s16
    vmov r1, s8
    ldr r0, =0xc0900000
    cmp r1, r0
    bne fail
    vmov s10, s0
    vnmls.f32 s10, s7, s16
    vmov r1, s10
    ldr r0, =0x40900000
    cmp r1, r0
    bne fail
    vmov s12, s0
    vnmla.f32 s12, s7, s16
    vmov r1, s12
    ldr r0, =0xc0f00000
    cmp r1, r0
    bne fail
    @ f64 VNMLA (was unimplemented in the f64 block)
    ldr r0, =0x00000000
    ldr r1, =0x3ff80000      @ 1.5
    vmov d0, r0, r1          @ acc
    ldr r1, =0x40000000      @ 2.0 hi
    vmov d1, r0, r1          @ n
    ldr r1, =0x40080000      @ 3.0 hi
    vmov d2, r0, r1          @ m
    vnmla.f64 d0, d1, d2
    vmov r2, r3, d0
    ldr r0, =0x00000000
    cmp r2, r0
    bne fail
    ldr r0, =0xc01e0000      @ -7.5 hi
    cmp r3, r0
    bne fail
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r7, #1
    mov r0, #1
    svc #0
