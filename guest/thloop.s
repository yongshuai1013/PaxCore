    .syntax unified
    .thumb
    .global _start
    .thumb_func
_start:
    movw r1, #0x9680
    movt r1, #0x0098
1:
    subs.w r1, r1, #1
    bne.w 1b
    movs r0, #9
    cmp r1, #0
    itt eq
    moveq r0, #5
    addeq r0, r0, #0
    movs r7, #1
    svc #0
