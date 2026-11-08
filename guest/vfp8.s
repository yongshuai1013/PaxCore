    .thumb
    .globl _start
    .thumb_func
_start:
    ldr r4, =fails
    movs r5, #0
    str r5, [r4]
    /* load d0=A, d1=B from literal data */
    ldr r0, =dvals
    vldr d0, [r0, #0]
    vldr d1, [r0, #8]
    vpush {d0-d1}
    /* clobber d0, d1 with C, D */
    vldr d0, [r0, #16]
    vldr d1, [r0, #24]
    vpop {d0-d1}
    ldr r1, =outbuf
    vstr d0, [r1, #0]
    vstr d1, [r1, #8]
    /* expect A, B back */
    ldr r2, [r0, #0]
    ldr r3, [r1, #0]
    cmp r2, r3
    bne 1f
    b 2f
1:  adds r5, #1
2:  ldr r2, [r0, #4]
    ldr r3, [r1, #4]
    cmp r2, r3
    beq 3f
    adds r5, #1
3:  ldr r2, [r0, #8]
    ldr r3, [r1, #8]
    cmp r2, r3
    beq 4f
    adds r5, #1
4:  ldr r2, [r0, #12]
    ldr r3, [r1, #12]
    cmp r2, r3
    beq 5f
    adds r5, #1
5:  /* vstmia/vldmia with writeback */
    ldr r1, =outbuf
    vstmia r1!, {d0-d1}
    ldr r2, =outbuf
    adds r2, #16
    cmp r1, r2
    beq 6f
    adds r5, #1
6:  vldr d0, [r0, #16]
    vldr d1, [r0, #24]
    ldr r1, =outbuf
    vldmia r1, {d0-d1}
    vstr d1, [r1, #24]
    ldr r2, [r0, #12]
    ldr r3, [r1, #28]
    cmp r2, r3
    beq 7f
    adds r5, #1
7:  /* singles through push/pop with aliasing: s0 -> stack -> s1 */
    ldr r0, =dvals
    vldr s0, [r0, #0]
    vpush {s0}
    vldr s0, [r0, #8]
    vpop {s1}
    ldr r1, =outbuf
    vstr s1, [r1, #0]
    ldr r2, [r0, #0]
    ldr r3, [r1, #0]
    cmp r2, r3
    beq 8f
    adds r5, #1
8:  mov r0, r5
    movs r7, #1
    svc #0

    .data
    .balign 8
dvals:
    .word 0x11111111, 0x22222222
    .word 0x33333333, 0x44444444
    .word 0x55555555, 0x66666666
    .word 0x77777777, 0x88888888
outbuf:
    .space 32
fails:
    .word 0
