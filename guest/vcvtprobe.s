	.text
	.syntax unified
	.arm
	.globl _start
_start:
	vcvt.u32.f64 s0, d0
	vcvtr.u32.f64 s0, d0
	vcvt.s32.f64 s0, d0
	vcvtr.s32.f64 s0, d0
	vcvt.f64.u32 d0, s0
	vcvt.f64.s32 d0, s0
	vcvt.f32.u32 s0, s0
	vcmp.f64 d0, d1
	vcmpe.f64 d0, #0
	vnmls.f64 d0, d1, d2
	vnmla.f64 d0, d1, d2
