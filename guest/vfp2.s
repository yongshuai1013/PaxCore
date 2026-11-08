	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r4, =outbuf
	@ --- vmov core<->single, assorted numbers/parities
	ldr	r0, =0x3FC00000	@ 1.5f bits
	vmov	s5, r0
	vmov	r1, s5
	str	r1, [r4, #0]	@ expect 0x3FC00000
	ldr	r0, =0x40200000	@ 2.5f bits
	vmov	s14, r0
	vmov	r1, s14
	str	r1, [r4, #4]	@ expect 0x40200000
	ldr	r0, =0x3F800000	@ 1.0f
	vmov	s15, r0
	vmov	r1, s15
	str	r1, [r4, #8]	@ expect 0x3F800000
	ldr	r0, =0xC0000000	@ -2.0f
	vmov	s0, r0
	vmov	r1, s0
	str	r1, [r4, #12]	@ expect 0xC0000000
	@ --- vmov double <-> two core regs
	ldr	r0, =0x9999999A
	ldr	r1, =0x401F9999	@ d7 := 7.9
	vmov	d7, r0, r1
	vmov	r2, r3, d7
	str	r2, [r4, #16]	@ expect 0x9999999A
	str	r3, [r4, #20]	@ expect 0x401F9999
	@ --- vstr/vldr double round trip via memory
	vstr	d7, [r4, #24]
	vldr	d6, [r4, #24]
	vmov	r2, r3, d6
	str	r2, [r4, #32]
	str	r3, [r4, #36]	@ expect same pair
	@ --- vpush/vpop doubles
	vmov	d8, r0, r1
	mov	r0, #0
	mov	r1, #0
	vmov	d9, r0, r1
	vpush	{d8, d9}
	vmov	d8, r0, r1	@ clobber d8 with 0.0
	vpop	{d8, d9}
	vmov	r2, r3, d8
	str	r2, [r4, #40]	@ expect 0x9999999A
	str	r3, [r4, #44]	@ expect 0x401F9999
	@ --- arithmetic f64: a=1.5, b=2.25
	ldr	r0, =0x00000000
	ldr	r1, =0x3FF80000	@ d0 = 1.5
	vmov	d0, r0, r1
	ldr	r1, =0x40020000	@ d1 = 2.25
	vmov	d1, r0, r1
	vadd.f64	d2, d0, d1	@ 3.75
	vsub.f64	d3, d1, d0	@ 0.75
	vmul.f64	d4, d0, d1	@ 3.375
	vdiv.f64	d5, d1, d0	@ 1.5
	vstr	d2, [r4, #48]	@ 0x400E000000000000
	vstr	d3, [r4, #56]	@ 0x3FE8000000000000
	vstr	d4, [r4, #64]	@ 0x400B000000000000
	vstr	d5, [r4, #72]	@ 0x3FF8000000000000
	@ --- vneg / vabs / vsqrt
	vneg.f64	d6, d0		@ -1.5
	vstr	d6, [r4, #80]	@ 0xBFF8000000000000
	vabs.f64	d6, d6		@ 1.5
	vstr	d6, [r4, #88]	@ 0x3FF8000000000000
	ldr	r1, =0x40100000	@ d6 = 4.0
	vmov	d6, r0, r1
	vsqrt.f64	d6, d6		@ 2.0
	vstr	d6, [r4, #96]	@ 0x4000000000000000
	@ --- vmov.f64 reg-reg and immediate
	vmov.f64	d9, d0
	vstr	d9, [r4, #104]	@ 1.5
	vmov.f64	d9, #0.5
	vstr	d9, [r4, #112]	@ 0x3FE0000000000000
	@ --- vcmp + vmrs: 1.5 vs 2.25 -> N=1,Z=0,C=0,V=0 in APSR copy
	vcmp.f64	d0, d1
	vmrs	r2, fpscr
	str	r2, [r4, #120]	@ expect bit31 set only (N)
	vcmp.f64	d0, d0
	vmrs	r2, fpscr
	str	r2, [r4, #124]	@ expect Z|C (bits 30,29)
	vcmpe.f64	d1, #0
	vmrs	r2, fpscr
	str	r2, [r4, #128]	@ 2.25 vs 0 -> C only (bit29)
	@ --- vcvt f32<->f64
	vcvt.f64.f32	d9, s5		@ s5 = 1.5f -> 1.5
	vstr	d9, [r4, #136]	@ 0x3FF8000000000000
	vcvt.f32.f64	s16, d1		@ 2.25 -> 2.25f bits in s16
	vmov	r2, s16
	str	r2, [r4, #144]	@ expect 0x40100000
	@ --- vmla / vmls / vnmls: acc=1.0, n=2.0, m=3.0
	ldr	r1, =0x3FF00000	@ 1.0
	vmov	d10, r0, r1
	ldr	r1, =0x40000000	@ 2.0
	vmov	d11, r0, r1
	ldr	r1, =0x40080000	@ 3.0
	vmov	d12, r0, r1
	vmla.f64	d10, d11, d12	@ 1 + 6 = 7
	vstr	d10, [r4, #152]	@ 0x401C000000000000
	ldr	r1, =0x3FF00000
	vmov	d10, r0, r1
	vmls.f64	d10, d11, d12	@ 1 - 6 = -5
	vstr	d10, [r4, #160]	@ 0xC014000000000000
	ldr	r1, =0x3FF00000
	vmov	d10, r0, r1
	vnmls.f64	d10, d11, d12	@ -1 + 6 = 5
	vstr	d10, [r4, #168]	@ 0x4014000000000000
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
outbuf:
	.space	256
