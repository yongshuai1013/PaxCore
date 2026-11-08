    .text
    .globl _start
_start:
    /* case 1: bfi r12, r0, #16, #16, r0=0xABCD, r12=0x11111111 -> 0xABCD1111 */
    ldr r0, =0xABCD
    ldr r12, =0x11111111
    bfi r12, r0, #16, #16
    ldr r1, =0xABCD1111
    cmp r12, r1
    bne fail1
    /* case 2: bfi r12, r0, #0, #16, r0=7, r12=0xFFFF0000 -> 0xFFFF0007 */
    mov r0, #7
    ldr r12, =0xFFFF0000
    bfi r12, r0, #0, #16
    ldr r1, =0xFFFF0007
    cmp r12, r1
    bne fail2
    /* case 3: ubfx r0, r1, #0, #20, r1=0xABCDE -> 0xABCDE */
    ldr r1, =0xABCDE
    ubfx r0, r1, #0, #20
    ldr r2, =0xABCDE
    cmp r0, r2
    bne fail3
    /* case 4: sbfx r0, r1, #0, #20, r1=0x80000 -> 0xFFF80000 */
    ldr r1, =0x80000
    sbfx r0, r1, #0, #20
    ldr r2, =0xFFF80000
    cmp r0, r2
    bne fail4
    /* case 5: bfc r12, #16, #16, r12=0xFFFFFFFF -> 0x0000FFFF */
    ldr r12, =0xFFFFFFFF
    bfc r12, #16, #16
    ldr r1, =0x0000FFFF
    cmp r12, r1
    bne fail5
    mov r0, #0
    b out
fail1: mov r0, #1
    b out
fail2: mov r0, #2
    b out
fail3: mov r0, #3
    b out
fail4: mov r0, #4
    b out
fail5: mov r0, #5
out:
    mov r7, #248
    svc #0
