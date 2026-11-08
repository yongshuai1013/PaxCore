    .text
    .globl _start
_start:
    vmov.f32 s15, #0.5
    vmov r0, s15
    ldr r1, =0x3F000000
    cmp r0, r1
    beq 1f
    mov r0, #1
    b out
1:
    vmov.f64 d9, #0.5
    vmov r0, r1, d9
    ldr r2, =0x3FE00000
    cmp r1, r2
    beq 2f
    mov r0, #2
    b out
2:
    mov r0, #0
out:
    mov r7, #248
    svc #0
