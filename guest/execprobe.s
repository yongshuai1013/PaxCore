	.text
	.syntax unified
	.arm
	.globl _start
_start:
	ldr	r1, =msg_a
	mov	r2, #2
	bl	write_str
	@ execve("/bin/target", argv, envp)
	ldr	r0, =path
	ldr	r1, =argv
	ldr	r2, =envp
	mov	r7, #11
	svc	#0
	@ execve only returns on failure
	mov	r0, #99
	mov	r7, #248
	svc	#0
write_str:
	mov	r0, #1
	mov	r7, #4
	svc	#0
	bx	lr
	.data
msg_a:	.ascii "A\n"
path:	.asciz "/bin/target"
argv:	.word aname, 0
envp:	.word eenv, 0
aname:	.asciz "target"
eenv:	.asciz "PATH=/bin"
