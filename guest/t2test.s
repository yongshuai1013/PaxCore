	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	ldr	r8, =table
	ldr.w	r4, [r8]
	ldr	r5, =want
	ldr	r5, [r5]
	cmp	r4, r5
	bne	fail
	ldr.w	r4, [r8, #4]
	ldr	r5, =want2
	ldr	r5, [r5]
	cmp	r4, r5
	bne	fail
	movs	r0, #0
	movs	r7, #1
	svc	#0
fail:
	movs	r0, #9
	movs	r7, #1
	svc	#0
	.data
	.align 2
table:	.word 0x11223344, 0x55667788
want:	.word 0x11223344
want2:	.word 0x55667788
