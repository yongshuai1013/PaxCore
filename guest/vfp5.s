	.text
	.syntax unified
	.arm
	.globl _start
@ replicates musl fmt_fp digit loop shape:
@ in: d8 = value, d7 = 10.0 ; buffer r6 (advancing), count in outbuf[0]
digloop:
	vcvt.u32.f64	s0, d8
	vstmia	r6!, {s0}
	vcvt.f64.u32	d0, s0
	vsub.f64	d8, d8, d0
	vmul.f64	d8, d8, d7
	vcmp.f64	d8, #0
	vmrs	r2, fpscr
	tst	r2, #0x40000000
	beq	digdone
	b	digloop
digdone:
	bx	lr
_start:
	ldr	r4, =digits
	ldr	r10, =outbuf
	@ multiplier 10.0 into d7
	mov	r0, #0
	ldr	r1, =0x40240000
	vmov	d7, r0, r1
	@ case 1: d8 = 1.5
	mov	r0, #0
	ldr	r1, =0x3FF80000
	vmov	d8, r0, r1
	mov	r6, r4
	bl	digloop
	sub	r0, r6, r4
	lsr	r0, r0, #2
	str	r0, [r10, #0]	@ expect 2 digits (1, then fraction .5 -> *10 = 5)
	ldr	r0, [r4, #0]
	str	r0, [r10, #4]	@ expect 1
	ldr	r0, [r4, #4]
	str	r0, [r10, #8]	@ expect 5
	@ case 2: d8 = 20.0 -> 1 digit then zero fraction
	mov	r0, #0
	ldr	r1, =0x40340000
	vmov	d8, r0, r1
	mov	r6, r4
	bl	digloop
	sub	r0, r6, r4
	lsr	r0, r0, #2
	str	r0, [r10, #12]	@ expect 1
	ldr	r0, [r4, #0]
	str	r0, [r10, #16]	@ expect 20
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
digits:
	.space	256
outbuf:
	.space	64
