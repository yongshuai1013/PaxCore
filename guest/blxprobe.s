	.text
	.syntax unified
	.thumb
	.globl _start
_start:
	blx	target_a
	blx	target_b
	blx	target_c
	.space 0x200
target_a:
	.space 0x1000
target_b:
	.space 0x40
target_c:
	bx	lr
