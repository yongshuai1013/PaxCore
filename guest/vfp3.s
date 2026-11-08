	.text
	.syntax unified
	.arm
	.globl _start
@ check(d0) -> r0 = biased exponent field; r1 = path code
@ (1 = bne path taken at entry check, 2 = vcmpe said equal, 3 = vcmpe said not equal)
check:
	vstr	d0, [r4]
	ldrd	r6, r7, [r4]
	ubfx	r0, r7, #0x14, #0xb
	cmp	r0, #0
	bne	1f
	vcmpe.f64	d0, #0
	vmrs	r2, fpscr
	ands	r2, r2, #0x40000000
	bne	2f
	mov	r1, #3
	bx	lr
2:	mov	r1, #2
	bx	lr
1:	mov	r1, #1
	bx	lr
_start:
	ldr	r4, =scratch
	ldr	r10, =outbuf
	@ d0 = 1.5
	mov	r0, #0
	ldr	r1, =0x3FF80000
	vmov	d0, r0, r1
	bl	check
	str	r0, [r10, #0]	@ expect 0x3FF
	str	r1, [r10, #4]	@ expect 1
	@ d0 = 0.0
	mov	r0, #0
	mov	r1, #0
	vmov	d0, r0, r1
	bl	check
	str	r0, [r10, #8]	@ expect 0
	str	r1, [r10, #12]	@ expect 2
	@ d0 = smallest subnormal (bits 1)
	mov	r0, #1
	mov	r1, #0
	vmov	d0, r0, r1
	bl	check
	str	r0, [r10, #16]	@ expect 0
	str	r1, [r10, #20]	@ expect 3
	@ d0 = -2.25
	mov	r0, #0
	ldr	r1, =0xC0020000
	vmov	d0, r0, r1
	bl	check
	str	r0, [r10, #24]	@ expect 0x400
	str	r1, [r10, #28]	@ expect 1
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
scratch:
	.space	16
outbuf:
	.space	64
