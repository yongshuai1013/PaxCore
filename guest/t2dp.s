	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	lsrs.w	r2, r0, r3
	lsls.w	r2, r0, r3
	asrs.w	r2, r0, r3
	rors.w	r2, r0, r3
	mov.w	r2, r0, lsr #5
	mov.w	r2, r0, lsl r3
	eor.w	r2, r0, r1
	add.w	r2, r0, r1, lsl #2
	sdiv	r2, r0, r1
	udiv	r2, r0, r1
