	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r4, =outbuf
	@ s0 = 7 (bits)
	mov	r0, #7
	vmov	s0, r0
	vcvt.f64.s32	d1, s0
	vcvt.f64.u32	d0, s0
	vstr	d0, [r4]
	vstr	d1, [r4, #8]
	@ s0 = -3 (bits 0xFFFFFFFD)
	ldr	r0, =0xFFFFFFFD
	vmov	s0, r0
	vcvt.f64.s32	d2, s0
	vcvt.f64.u32	d3, s0
	vstr	d2, [r4, #16]
	vstr	d3, [r4, #24]
	@ also: vcvt.u32.f64 (B half, FPSCR) and (F half, trunc) of 7.9
	ldr	r0, =0x9A999999
	ldr	r1, =0x401F9999
	vmov	d4, r0, r1	@ d4 = 7.9 approx (bits 0x401F99999999999A)
	vcvt.u32.f64	s5, d4
	vcvtr.u32.f64	s6, d4
	vmov	r2, s5
	vmov	r3, s6
	str	r2, [r4, #32]
	str	r3, [r4, #36]
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
outbuf:
	.space	64
