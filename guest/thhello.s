    .syntax unified
    .thumb
    .global _start
    .thumb_func
_start:
    movs r0, #1
    ldr r1, =msg
    movs r2, #18
    movs r7, #4
    svc #0
    movw r0, #0x2a
    movs r7, #1
    svc #0
msg:
    .ascii "hello from thumb!\n"
