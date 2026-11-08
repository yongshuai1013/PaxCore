    .syntax unified
    .thumb
    .global _start
    .thumb_func
    .text
_start:
    push {r4, r5, lr}
    pop {r4, r5, r6}
    stmia r0!, {r2, r3}
    ldmia r1!, {r2, r3}
    push.w {r4, r5, r6, lr}
    pop.w {r4, r5, r6, r7}
    ldr.w r0, [r1, #36]
    str.w r2, [r3, #40]
    ldrb.w r0, [r1, #7]
    ldrh.w r0, [r1, #8]
    ldrsb.w r0, [r1, #3]
    ldrsh.w r0, [r1, #4]
    ldr.w r0, [pc, #16]
    movw r0, #0x5678
    movt r0, #0x1234
    add.w r0, r1, #0xABABABAB
    sub.w r0, r1, #0xFF00FF00
    cmp.w r1, #0xFF
    mov.w r0, #0x80000000
    and.w r0, r1, r2
    orr.w r0, r1, r2, lsl #3
    eor.w r0, r1, r2
    add.w r0, r1, r2, lsr #5
    sub.w r3, r4, r5
    rsb.w r0, r1, #0
    mul r0, r1, r2
    umull r0, r3, r1, r2
    smull r0, r3, r1, r2
    b.w 1f
1:
    bl 2f
2:
    movs r0, #1
    it eq
    moveq r0, #2
    itt ne
    movne r0, #3
    movne r1, #4
    clz r0, r1
    nop.w
    movs r0, #7
    movs r7, #1
    svc #0
