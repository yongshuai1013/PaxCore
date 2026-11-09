@ vfp9probe: the exact VFP sequences from libdvm's
@ dvmGetTargetHeapUtilization / dvmSetTargetHeapUtilization.
@ T4 showed getTargetHeapUtilization() returns 0.0 even after
@ set(0.6f): the getter converts a stored u32 count (util*1024)
@ back via vcvt.f32.u32 + vmul by 1/1024, using s14/s15.
@ Expected bit patterns are exact IEEE-754 values.
    .text
    .globl _start
_start:
    @ storage word = 768 (0.75 * 1024)
    ldr r1, =storage
    mov r0, #768
    str r0, [r1]
    @ ---- getter sequence ----
    vldr s0, [r1]
    vcvt.f32.u32 s14, s0
    vmov r0, s14
    ldr r4, =0x44400000      @ 768.0f
    cmp r0, r4
    bne fail
    vldr s15, .Linv1024      @ 1/1024 as f32
    vmul.f32 s15, s14, s15
    vmov r0, s15
    ldr r4, =0x3f400000      @ 0.75f
    cmp r0, r4
    bne fail
    @ odd-reg store round trip: vstr s15 then integer ldr
    ldr r1, =storage2
    vstr s15, [r1]
    ldr r0, [r1]
    ldr r4, =0x3f400000
    cmp r0, r4
    bne fail
    @ vcvt.f32.u32 with odd destination s15
    ldr r1, =storage
    vldr s0, [r1]
    vcvt.f32.u32 s15, s0
    vmov r0, s15
    ldr r4, =0x44400000
    cmp r0, r4
    bne fail
    @ ---- setter sequence ----
    ldr r0, =0x3f19999a      @ 0.6f
    vmov s15, r0
    vldr s0, .L1024f         @ 1024.0f
    vmul.f32 s15, s15, s0    @ 614.4
    vcvt.u32.f32 s15, s15    @ 614 (round to zero)
    ldr r1, =storage2
    vstr s15, [r1]
    ldr r0, [r1]
    ldr r4, =614
    cmp r0, r4
    bne fail
    @ clamp compare: vcvt.f64.f32 + vcmpe.f64 vs 0.2 -> GT
    ldr r0, =0x3f19999a      @ 0.6f
    vmov s15, r0
    vcvt.f64.f32 d6, s15
    vldr d5, .Ld02           @ 0.2
    vcmpe.f64 d6, d5
    vmrs APSR_nzcv, fpscr
    movgt r0, #1
    movle r0, #2
    cmp r0, #1
    bne fail
    mov r7, #1
    mov r0, #0
    svc #0
.Linv1024: .word 0x3a800000
.L1024f:   .word 0x44800000
.Ld02:     .double 0.2
fail:
    mov r7, #1
    mov r0, #1
    svc #0
    .data
storage:  .word 0
storage2: .word 0
