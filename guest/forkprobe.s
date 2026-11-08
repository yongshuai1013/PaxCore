	.text
	.syntax unified
	.arm
	.globl _start
_start:
	@ fork()
	mov	r7, #190
	svc	#0
	cmp	r0, #0
	blt	fail
	beq	child
	@ parent: r4 = child pid
	mov	r4, r0
	@ parent writes "P1\n" first (ordering not guaranteed,
	@ but child waits for nothing; content check is on C/P2)
	ldr	r1, =msg_p1
	mov	r2, #3
	bl	write_str
	@ wait4(-1, &status, 0, 0)
	mov	r0, #-1
	ldr	r1, =status
	mov	r2, #0
	mov	r3, #0
	mov	r7, #114
	svc	#0
	cmp	r0, r4
	bne	fail		@ reaped pid must be the child
	ldr	r0, =status
	ldr	r0, [r0]
	lsr	r0, r0, #8
	cmp	r0, #7
	bne	fail		@ exit code must be 7
	ldr	r1, =msg_p2
	mov	r2, #3
	bl	write_str
	mov	r0, #0
	mov	r7, #248
	svc	#0
child:
	@ getpid must equal parent's fork return; parent checks
	@ only reap/code, child just marks and exits 7.
	ldr	r1, =msg_c
	mov	r2, #3
	bl	write_str
	mov	r0, #7
	mov	r7, #248
	svc	#0
fail:
	mov	r0, #1
	mov	r7, #248
	svc	#0
write_str:
	@ r1 = buf, r2 = len
	mov	r0, #1
	mov	r7, #4
	svc	#0
	bx	lr
	.data
msg_p1:	.ascii "P1\n"
msg_c:	.ascii "C\n\0"
msg_p2:	.ascii "P2\n"
status:	.word 0
