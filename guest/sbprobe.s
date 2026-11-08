@ sbprobe: Thumb-2 signed loads (LDRSB/LDRSH) in every addressing
@ form, against a data block holding known signed values.
@ A wrong (zero-extending) LDRSB makes libdvm's width table read
@ 253 instead of -3; this probe pins the semantics directly.
@ Data layout (at `tab`, 4-aligned):
@   +0x00: byte 0xFD (-3)      +0x01: byte 0x7F (127)
@   +0x40: half 0xFF9A (-102)  +0x42: half 0x1234
@   +0x80: byte 0x80 (-128)    +0x82: half 0x8001 (-32767)
.syntax unified
.thumb
.global _start
.thumb_func
_start:
    ldr r5, =tab
    @ 1: ldrsb register offset, negative byte
    mov r2, #0
    ldrsb.w r0, [r5, r2]
    ldr r1, =0xfffffffd
    cmp r0, r1
    bne fail
    @ 2: ldrsb register offset, positive byte
    mov r2, #1
    ldrsb.w r0, [r5, r2]
    cmp r0, #0x7f
    bne fail
    @ 3: ldrb control (must stay zero-extended)
    mov r2, #0
    ldrb.w r0, [r5, r2]
    cmp r0, #0xfd
    bne fail
    @ 4: ldrsh register offset, negative half
    mov r2, #0x40
    ldrsh.w r0, [r5, r2]
    ldr r1, =0xffffff9a
    cmp r0, r1
    bne fail
    @ 5: ldrsh register offset, positive half
    mov r2, #0x42
    ldrsh.w r0, [r5, r2]
    ldr r1, =0x1234
    cmp r0, r1
    bne fail
    @ 6: ldrsb imm12, most-negative byte
    ldrsb.w r0, [r5, #0x80]
    ldr r1, =0xffffff80
    cmp r0, r1
    bne fail
    @ 7: ldrsh imm12, negative half
    ldrsh.w r0, [r5, #0x82]
    ldr r1, =0xffff8001
    cmp r0, r1
    bne fail
    @ 8: ldrsb imm8 negative-offset form ([rn, #-imm])
    add r6, r5, #0x40
    ldrsb r0, [r6, #-0x40]
    ldr r1, =0xfffffffd
    cmp r0, r1
    bne fail
    @ 9: ldrsb pre-index with writeback
    mov r6, r5
    ldrsb r0, [r6, #0x40]!
    @ byte at +0x40 is the low byte of 0xFF9A = 0x9A (-102)
    ldr r1, =0xffffff9a
    cmp r0, r1
    bne fail
    cmp r6, r5
    beq fail
    @ 10: ldrsb post-index
    mov r6, r5
    ldrsb r0, [r6], #1
    ldr r1, =0xfffffffd
    cmp r0, r1
    bne fail
    add r1, r5, #1
    cmp r6, r1
    bne fail
    @ pass
    mov r0, #42
    ldr r1, =msg_ok
    bl puts
    mov r7, #1
    mov r0, #0
    svc #0
fail:
    mov r0, #99
    ldr r1, =msg_bad
    bl puts
    mov r7, #1
    mov r0, #1
    svc #0
puts: @ (r0=len ignored, r1=str) -- write(1, r1, len by scan)
    push {r4, lr}
    mov r4, r1
    mov r2, #0
1:  ldrb r3, [r4, r2]
    cmp r3, #0
    it ne
    addne r2, r2, #1
    bne 1b
    mov r0, #1
    mov r1, r4
    mov r7, #4
    svc #0
    pop {r4, pc}
    .align 2
tab:
    .byte 0xFD, 0x7F
    .space 0x3e, 0
    .hword 0xFF9A, 0x1234
    .space 0x3c, 0
    .byte 0x80, 0x00
    .hword 0x8001
msg_ok: .asciz "SB_OK\n"
msg_bad: .asciz "SB_BAD\n"
