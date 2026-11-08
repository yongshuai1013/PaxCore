    .syntax unified
    .arch armv7-a
    .arm
    .global _start
    .text
_start:
    mov r0, #1              @ fd = stdout
    ldr r1, =msg            @ buf
    mov r2, #19             @ len
    mov r7, #4              @ __NR_write
    svc 0
    mov r0, #42             @ exit code
    mov r7, #1              @ __NR_exit
    svc 0
msg:
    .ascii "hello from guest!\n"
