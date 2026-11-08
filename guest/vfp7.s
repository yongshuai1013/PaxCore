	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r10, =outbuf
	@ d8 = 345246651.121664 (bits 0x41B4940BBB1F255F)
	ldr	r0, =0xBB1F255F
	ldr	r1, =0x41B4940B
	vmov	d8, r0, r1
	vcvt.u32.f64	s0, d8
	vmov	r2, s0
	str	r2, [r10, #0]	@ expect 345246651
	@ d8 = 121663987.63656616 (bits 0x419D01C7CE8BD800)
	ldr	r0, =0xCE8BD800
	ldr	r1, =0x419D01C7
	vmov	d8, r0, r1
	vcvt.u32.f64	s0, d8
	vmov	r2, s0
	str	r2, [r10, #4]	@ expect 121663988 (RN) 
	@ d8 = 0.63656616 -> expect 1 (RN) 
	ldr	r0, =0xD70A3D70
	ldr	r1, =0x3FE45E8F
	vmov	d8, r0, r1
	vcvt.u32.f64	s0, d8
	vmov	r2, s0
	str	r2, [r10, #8]	@ value ~0.6366 -> expect 1
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
outbuf:
	.space	32
