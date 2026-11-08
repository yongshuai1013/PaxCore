	.text
	.syntax unified
	.thumb
	.globl _start
_start:
	ldr.w	r0, [r1, #8]
	ldr.w	r0, [pc, #16]
	ldr.w	r0, [pc, #-16]
	str.w	r2, [r3, #260]
	ldr.w	r0, [r1, #-8]!
	ldr.w	r0, [r1, #8]!
	str.w	r2, [r3], #12
	ldrb.w	r0, [r1, #5]
	strb.w	r2, [r3, #5]
	ldrh.w	r0, [r1, #6]
	strh.w	r2, [r3, #6]
	ldr.w	r0, [r1, r2, lsl #2]
