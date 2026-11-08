	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r4, =digits
	ldr	r10, =outbuf
	mov	r0, #0
	ldr	r1, =0x40240000
	vmov	d7, r0, r1	@ 10.0
	mov	r0, #0
	ldr	r1, =0x3FF80000
	vmov	d8, r0, r1	@ 1.5
	mov	r6, r4
	@ round 1
	vcvt.u32.f64	s0, d8
	vstmia	r6!, {s0}
	vcvt.f64.u32	d0, s0
	vsub.f64	d8, d8, d0
	vmul.f64	d8, d8, d7
	vstr	d8, [r10, #0]	@ expect 5.0
	@ round 2
	vcvt.u32.f64	s0, d8
	vstmia	r6!, {s0}
	vcvt.f64.u32	d0, s0
	vsub.f64	d8, d8, d0
	vmul.f64	d8, d8, d7
	vstr	d8, [r10, #8]	@ expect 0.0
	ldr	r0, [r4, #0]
	str	r0, [r10, #16]	@ expect 1
	ldr	r0, [r4, #4]
	str	r0, [r10, #20]	@ expect 5
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
digits:
	.space	64
outbuf:
	.space	64
