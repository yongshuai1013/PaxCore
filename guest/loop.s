    .syntax unified
    .arch armv7-a
    .arm
    .global _start
    .text
_start:
    ldr r0, =10000000       @ 10M iterations
    mov r1, #0
1:
    add r1, r1, #1
    subs r0, r0, #1
    bne 1b
    mov r0, r1              @ low byte of count becomes exit code path
    and r0, r0, #0xff
    mov r7, #1              @ __NR_exit
    svc 0
