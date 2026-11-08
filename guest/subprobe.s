	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	@ Stage 1: subs rd, rn, rm (register form):
	@ 20 - 7 = 13. A swapped decode gives 7 - 20.
	movs	r6, #20
	movs	r0, #7
	subs	r6, r6, r0
	cmp	r6, #13
	beq	s1ok
	movs	r0, #1
	b.w	fail
s1ok:
	@ Stage 2: adds rd, rn, #imm3 with Rn != imm3:
	@ r2 = 100 + 4 = 104. Reading r[imm3] as the
	@ source would give r4 + 4 = 5 instead.
	movs	r2, #100
	movs	r4, #1
	adds	r2, r2, #4
	cmp	r2, #104
	beq	s2ok
	movs	r0, #2
	b.w	fail
s2ok:
	@ Stage 3: subs rd, rn, #imm3: 100 - 5 = 95.
	movs	r3, #100
	subs	r3, r3, #5
	cmp	r3, #95
	beq	s3ok
	movs	r0, #3
	b.w	fail
s3ok:
	@ Stage 4: adds rd, rn, rm (register form):
	@ 30 + 12 = 42.
	movs	r5, #30
	movs	r1, #12
	adds	r5, r5, r1
	cmp	r5, #42
	beq	s4ok
	movs	r0, #4
	b.w	fail
s4ok:
	movs	r0, #0
fail:
	movs	r7, #1
	svc	#0
