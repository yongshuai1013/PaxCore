	.text
	.syntax unified
	.thumb
	.globl _start
	.thumb_func
_start:
	@ Test 1: backward bne.w loop (S=1, small negative offset)
	movs	r0, #0
loop1:
	adds	r0, #1
	cmp	r0, #5
	bne.w	loop1
	cmp	r0, #5
	bne	fail
	@ Test 2: forward beq.w over a poison gap (imm6 == 0)
	cmp	r0, #5
	beq.w	t2ok
	movs	r0, #2
	b.w	fail
	.fill	120, 1, 0xFF
t2ok:
	@ Test 3: forward beq.w over a 20KB gap (imm6 != 0)
	cmp	r0, #5
	beq.w	t3ok
	movs	r0, #3
	b.w	fail
	.fill	20000, 1, 0xFF
t3ok:
	@ Test 4: b.w unconditional over a gap (T4, collateral)
	b.w	t4ok
	.fill	60, 1, 0xFF
t4ok:
	@ Test 5: beq.w, offset has bit18 only (hw2[13] set)
	cmp	r0, #5
	beq.w	t5ok
	movs	r0, #5
	b.w	fail
	.fill	262100, 1, 0xFF
t5ok:
	@ Test 6: beq.w, offset has bit19 only (hw2[11] set)
	cmp	r0, #5
	beq.w	t6ok
	movs	r0, #6
	b.w	fail
	.fill	524200, 1, 0xFF
t6ok:
	@ success
	movs	r0, #0
	movs	r7, #1
	svc	#0
fail:
	movs	r7, #1
	svc	#0
