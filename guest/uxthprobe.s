@ uxthprobe: Thumb-2 sign/zero-extend family (0xFAxx with
@ hw2[7:6]==0b10). Case 1 uses the exact bytes from
@ libdvm.so dvmLinkClass (fa1f fe83 = uxth.w lr, r3) whose
@ misexecution as a register shift of the PC produced
@ garbage in lr and made dvm's interface method-count
@ check fire on every interface. Remaining cases use
@ assembler mnemonics. Exit code = failure bitmask.
    .text
    .globl _start
    .thumb_func
_start:
    @ case 1 (bit 1): raw libdvm bytes, r3=1 -> lr must be 1
    movs r3, #1
    .hword 0xfa1f
    .hword 0xfe83
    cmp lr, #1
    beq 1f
    movs r0, #1
    b out
1:
    @ case 2 (bit 2): uxth r3=0x12345678 -> 0x5678
    ldr r3, =0x12345678
    uxth.w r4, r3
    ldr r2, =0x5678
    cmp r4, r2
    beq 2f
    movs r0, #2
    b out
2:
    @ case 3 (bit 4): sxth r3=0x8001 -> 0xFFFF8001
    ldr r3, =0x8001
    sxth.w r4, r3
    ldr r2, =0xFFFF8001
    cmp r4, r2
    beq 3f
    movs r0, #4
    b out
3:
    @ case 4 (bit 8): uxtb r3=0x1FF -> 0xFF ; sxtb 0x80 -> -128
    movs r3, #0xFF
    adds r3, r3, #0x100
    uxtb.w r4, r3
    cmp r4, #0xFF
    bne 4f
    movs r3, #0x80
    sxtb.w r4, r3
    ldr r2, =0xFFFFFF80
    cmp r4, r2
    beq 5f
4:
    movs r0, #8
    b out
5:
    @ case 5 (bit 16): uxth ror#8: 0x12345678 -> ror 0x78123456 -> 0x3456
    ldr r3, =0x12345678
    uxth.w r4, r3, ror #8
    ldr r2, =0x3456
    cmp r4, r2
    beq 6f
    movs r0, #16
    b out
6:
    @ case 6 (bit 32): uxtah: 0x1000 + uxth(0x12345678) = 0x6678
    ldr r3, =0x12345678
    ldr r5, =0x1000
    uxtah r4, r5, r3
    ldr r2, =0x6678
    cmp r4, r2
    beq 7f
    movs r0, #32
    b out
7:
    movs r0, #0
out:
    movs r7, #248
    svc #0
