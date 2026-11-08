	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	@ Stage 1: plain blt after cmp of the linker's exact
	@ values: r4 = -1544 (0xFFFFF9F8), r6 = -767
	@ (0xFFFFFD01). Signed LT must be TRUE.
	ldr	r4, =0xFFFFF9F8
	ldr	r6, =0xFFFFFD01
	cmp	r4, r6
	blt	s1ok
	movs	r0, #1
	b.w	fail
s1ok:
	@ Stage 2: it lt + movlt with the same values;
	@ r6 must become r4.
	ldr	r4, =0xFFFFF9F8
	ldr	r6, =0xFFFFFD01
	cmp	r4, r6
	it	lt
	movlt	r6, r4
	ldr	r5, =0xFFFFF9F8
	cmp	r6, r5
	beq	s2ok
	movs	r0, #2
	b.w	fail
s2ok:
	movs	r0, #0
fail:
	movs	r7, #1
	svc	#0
