	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	@ Stage 1: set_tls(0xF0005) then TPIDRURO read-back.
	ldr	r0, =0x10008000
	ldr	r7, =0xF0005
	svc	#0
	mrc	p15, 0, r1, c13, c0, 3
	ldr	r2, =0x10008000
	cmp	r1, r2
	beq	s1ok
	movs	r0, #1
	b.w	fail
s1ok:
	@ Stage 2: MCR writes the thread pointer, MRC reads
	@ it back.
	ldr	r3, =0x10009000
	mcr	p15, 0, r3, c13, c0, 3
	mrc	p15, 0, r4, c13, c0, 3
	cmp	r4, r3
	beq	s2ok
	movs	r0, #2
	b.w	fail
s2ok:
	movs	r0, #0
fail:
	movs	r7, #1
	svc	#0
