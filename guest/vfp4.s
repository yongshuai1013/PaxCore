	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r4, =scratch
	ldr	r10, =outbuf
	mov	r0, #0
	ldr	r1, =0x3FF80000
	vmov	d0, r0, r1	@ d0 = 1.5
	vstr	d0, [r4]
	@ plain loads
	ldr	r2, [r4]
	ldr	r3, [r4, #4]
	str	r2, [r10, #0]	@ expect 0x00000000
	str	r3, [r10, #4]	@ expect 0x3FF80000
	@ ldrd into r6,r7
	ldrd	r6, r7, [r4]
	str	r6, [r10, #8]	@ expect 0x00000000
	str	r7, [r10, #12]	@ expect 0x3FF80000
	@ strd round trip via core regs
	ldr	r0, =0x11111111
	ldr	r1, =0x22222222
	strd	r0, r1, [r4]
	ldrd	r6, r7, [r4]
	str	r6, [r10, #16]	@ expect 0x11111111
	str	r7, [r10, #20]	@ expect 0x22222222
	mov	r0, #0
	mov	r7, #1
	svc	#0
	.data
scratch:
	.space	16
outbuf:
	.space	64
