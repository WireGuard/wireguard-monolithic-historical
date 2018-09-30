/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2018 Google, Inc.
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2006-2017 CRYPTOGAMS by <appro@openssl.org>. All Rights Reserved.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

/*
 * The following scalar routine was written by Eric Biggers.
 *
 * Design notes:
 *
 * 16 registers would be needed to hold the state matrix, but only 14 are
 * available because 'sp' and 'pc' cannot be used.  So we spill the elements
 * (x8, x9) to the stack and swap them out with (x10, x11).  This adds one
 * 'ldrd' and one 'strd' instruction per round.
 *
 * All rotates are performed using the implicit rotate operand accepted by the
 * 'add' and 'eor' instructions.  This is faster than using explicit rotate
 * instructions.  To make this work, we allow the values in the second and last
 * rows of the ChaCha state matrix (rows 'b' and 'd') to temporarily have the
 * wrong rotation amount.  The rotation amount is then fixed up just in time
 * when the values are used.  'brot' is the number of bits the values in row 'b'
 * need to be rotated right to arrive at the correct values, and 'drot'
 * similarly for row 'd'.  (brot, drot) start out as (0, 0) but we make it such
 * that they end up as (25, 24) after every round.
 */

	// ChaCha state registers
	X0	.req	r0
	X1	.req	r1
	X2	.req	r2
	X3	.req	r3
	X4	.req	r4
	X5	.req	r5
	X6	.req	r6
	X7	.req	r7
	X8_X10	.req	r8	// shared by x8 and x10
	X9_X11	.req	r9	// shared by x9 and x11
	X12	.req	r10
	X13	.req	r11
	X14	.req	r12
	X15	.req	r14

.Lexpand_32byte_k:
	// "expand 32-byte k"
	.word	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

#ifdef __thumb2__
#  define adrl adr
#endif

.macro __rev		out, in,  t0, t1, t2
.if __LINUX_ARM_ARCH__ >= 6
	rev		\out, \in
.else
	lsl		\t0, \in, #24
	and		\t1, \in, #0xff00
	and		\t2, \in, #0xff0000
	orr		\out, \t0, \in, lsr #24
	orr		\out, \out, \t1, lsl #8
	orr		\out, \out, \t2, lsr #8
.endif
.endm

.macro _le32_bswap	x,  t0, t1, t2
#ifdef __ARMEB__
	__rev		\x, \x,  \t0, \t1, \t2
#endif
.endm

.macro _le32_bswap_4x	a, b, c, d,  t0, t1, t2
	_le32_bswap	\a,  \t0, \t1, \t2
	_le32_bswap	\b,  \t0, \t1, \t2
	_le32_bswap	\c,  \t0, \t1, \t2
	_le32_bswap	\d,  \t0, \t1, \t2
.endm

.macro __ldrd		a, b, src, offset
#if __LINUX_ARM_ARCH__ >= 6
	ldrd		\a, \b, [\src, #\offset]
#else
	ldr		\a, [\src, #\offset]
	ldr		\b, [\src, #\offset + 4]
#endif
.endm

.macro __strd		a, b, dst, offset
#if __LINUX_ARM_ARCH__ >= 6
	strd		\a, \b, [\dst, #\offset]
#else
	str		\a, [\dst, #\offset]
	str		\b, [\dst, #\offset + 4]
#endif
.endm

.macro _halfround	a1, b1, c1, d1,  a2, b2, c2, d2

	// a += b; d ^= a; d = rol(d, 16);
	add		\a1, \a1, \b1, ror #brot
	add		\a2, \a2, \b2, ror #brot
	eor		\d1, \a1, \d1, ror #drot
	eor		\d2, \a2, \d2, ror #drot
	// drot == 32 - 16 == 16

	// c += d; b ^= c; b = rol(b, 12);
	add		\c1, \c1, \d1, ror #16
	add		\c2, \c2, \d2, ror #16
	eor		\b1, \c1, \b1, ror #brot
	eor		\b2, \c2, \b2, ror #brot
	// brot == 32 - 12 == 20

	// a += b; d ^= a; d = rol(d, 8);
	add		\a1, \a1, \b1, ror #20
	add		\a2, \a2, \b2, ror #20
	eor		\d1, \a1, \d1, ror #16
	eor		\d2, \a2, \d2, ror #16
	// drot == 32 - 8 == 24

	// c += d; b ^= c; b = rol(b, 7);
	add		\c1, \c1, \d1, ror #24
	add		\c2, \c2, \d2, ror #24
	eor		\b1, \c1, \b1, ror #20
	eor		\b2, \c2, \b2, ror #20
	// brot == 32 - 7 == 25
.endm

.macro _doubleround

	// column round

	// quarterrounds: (x0, x4, x8, x12) and (x1, x5, x9, x13)
	_halfround	X0, X4, X8_X10, X12,  X1, X5, X9_X11, X13

	// save (x8, x9); restore (x10, x11)
	__strd		X8_X10, X9_X11, sp, 0
	__ldrd		X8_X10, X9_X11, sp, 8

	// quarterrounds: (x2, x6, x10, x14) and (x3, x7, x11, x15)
	_halfround	X2, X6, X8_X10, X14,  X3, X7, X9_X11, X15

	.set brot, 25
	.set drot, 24

	// diagonal round

	// quarterrounds: (x0, x5, x10, x15) and (x1, x6, x11, x12)
	_halfround	X0, X5, X8_X10, X15,  X1, X6, X9_X11, X12

	// save (x10, x11); restore (x8, x9)
	__strd		X8_X10, X9_X11, sp, 8
	__ldrd		X8_X10, X9_X11, sp, 0

	// quarterrounds: (x2, x7, x8, x13) and (x3, x4, x9, x14)
	_halfround	X2, X7, X8_X10, X13,  X3, X4, X9_X11, X14
.endm

.macro _chacha_permute	nrounds
	.set brot, 0
	.set drot, 0
	.rept \nrounds / 2
	 _doubleround
	.endr
.endm

.macro _chacha		nrounds

.Lnext_block\@:
	// Stack: unused0-unused1 x10-x11 x0-x15 OUT IN LEN
	// Registers contain x0-x9,x12-x15.

	// Do the core ChaCha permutation to update x0-x15.
	_chacha_permute	\nrounds

	add		sp, #8
	// Stack: x10-x11 orig_x0-orig_x15 OUT IN LEN
	// Registers contain x0-x9,x12-x15.
	// x4-x7 are rotated by 'brot'; x12-x15 are rotated by 'drot'.

	// Free up some registers (r8-r12,r14) by pushing (x8-x9,x12-x15).
	push		{X8_X10, X9_X11, X12, X13, X14, X15}

	// Load (OUT, IN, LEN).
	ldr		r14, [sp, #96]
	ldr		r12, [sp, #100]
	ldr		r11, [sp, #104]

	orr		r10, r14, r12

	// Use slow path if fewer than 64 bytes remain.
	cmp		r11, #64
	blt		.Lxor_slowpath\@

	// Use slow path if IN and/or OUT isn't 4-byte aligned.  Needed even on
	// ARMv6+, since ldmia and stmia (used below) still require alignment.
	tst		r10, #3
	bne		.Lxor_slowpath\@

	// Fast path: XOR 64 bytes of aligned data.

	// Stack: x8-x9 x12-x15 x10-x11 orig_x0-orig_x15 OUT IN LEN
	// Registers: r0-r7 are x0-x7; r8-r11 are free; r12 is IN; r14 is OUT.
	// x4-x7 are rotated by 'brot'; x12-x15 are rotated by 'drot'.

	// x0-x3
	__ldrd		r8, r9, sp, 32
	__ldrd		r10, r11, sp, 40
	add		X0, X0, r8
	add		X1, X1, r9
	add		X2, X2, r10
	add		X3, X3, r11
	_le32_bswap_4x	X0, X1, X2, X3,  r8, r9, r10
	ldmia		r12!, {r8-r11}
	eor		X0, X0, r8
	eor		X1, X1, r9
	eor		X2, X2, r10
	eor		X3, X3, r11
	stmia		r14!, {X0-X3}

	// x4-x7
	__ldrd		r8, r9, sp, 48
	__ldrd		r10, r11, sp, 56
	add		X4, r8, X4, ror #brot
	add		X5, r9, X5, ror #brot
	ldmia		r12!, {X0-X3}
	add		X6, r10, X6, ror #brot
	add		X7, r11, X7, ror #brot
	_le32_bswap_4x	X4, X5, X6, X7,  r8, r9, r10
	eor		X4, X4, X0
	eor		X5, X5, X1
	eor		X6, X6, X2
	eor		X7, X7, X3
	stmia		r14!, {X4-X7}

	// x8-x15
	pop		{r0-r7}			// (x8-x9,x12-x15,x10-x11)
	__ldrd		r8, r9, sp, 32
	__ldrd		r10, r11, sp, 40
	add		r0, r0, r8		// x8
	add		r1, r1, r9		// x9
	add		r6, r6, r10		// x10
	add		r7, r7, r11		// x11
	_le32_bswap_4x	r0, r1, r6, r7,  r8, r9, r10
	ldmia		r12!, {r8-r11}
	eor		r0, r0, r8		// x8
	eor		r1, r1, r9		// x9
	eor		r6, r6, r10		// x10
	eor		r7, r7, r11		// x11
	stmia		r14!, {r0,r1,r6,r7}
	ldmia		r12!, {r0,r1,r6,r7}
	__ldrd		r8, r9, sp, 48
	__ldrd		r10, r11, sp, 56
	add		r2, r8, r2, ror #drot	// x12
	add		r3, r9, r3, ror #drot	// x13
	add		r4, r10, r4, ror #drot	// x14
	add		r5, r11, r5, ror #drot	// x15
	_le32_bswap_4x	r2, r3, r4, r5,  r9, r10, r11
	  ldr		r9, [sp, #72]		// load LEN
	eor		r2, r2, r0		// x12
	eor		r3, r3, r1		// x13
	eor		r4, r4, r6		// x14
	eor		r5, r5, r7		// x15
	  subs		r9, #64			// decrement and check LEN
	stmia		r14!, {r2-r5}

	beq		.Ldone\@

.Lprepare_for_next_block\@:

	// Stack: x0-x15 OUT IN LEN

	// Increment block counter (x12)
	add		r8, #1

	// Store updated (OUT, IN, LEN)
	str		r14, [sp, #64]
	str		r12, [sp, #68]
	str		r9, [sp, #72]

	  mov		r14, sp

	// Store updated block counter (x12)
	str		r8, [sp, #48]

	  sub		sp, #16

	// Reload state and do next block
	ldmia		r14!, {r0-r11}		// load x0-x11
	__strd		r10, r11, sp, 8		// store x10-x11 before state
	ldmia		r14, {r10-r12,r14}	// load x12-x15
	b		.Lnext_block\@

.Lxor_slowpath\@:
	// Slow path: < 64 bytes remaining, or unaligned input or output buffer.
	// We handle it by storing the 64 bytes of keystream to the stack, then
	// XOR-ing the needed portion with the data.

	// Allocate keystream buffer
	sub		sp, #64
	mov		r14, sp

	// Stack: ks0-ks15 x8-x9 x12-x15 x10-x11 orig_x0-orig_x15 OUT IN LEN
	// Registers: r0-r7 are x0-x7; r8-r11 are free; r12 is IN; r14 is &ks0.
	// x4-x7 are rotated by 'brot'; x12-x15 are rotated by 'drot'.

	// Save keystream for x0-x3
	__ldrd		r8, r9, sp, 96
	__ldrd		r10, r11, sp, 104
	add		X0, X0, r8
	add		X1, X1, r9
	add		X2, X2, r10
	add		X3, X3, r11
	_le32_bswap_4x	X0, X1, X2, X3,  r8, r9, r10
	stmia		r14!, {X0-X3}

	// Save keystream for x4-x7
	__ldrd		r8, r9, sp, 112
	__ldrd		r10, r11, sp, 120
	add		X4, r8, X4, ror #brot
	add		X5, r9, X5, ror #brot
	add		X6, r10, X6, ror #brot
	add		X7, r11, X7, ror #brot
	_le32_bswap_4x	X4, X5, X6, X7,  r8, r9, r10
	  add		r8, sp, #64
	stmia		r14!, {X4-X7}

	// Save keystream for x8-x15
	ldm		r8, {r0-r7}		// (x8-x9,x12-x15,x10-x11)
	__ldrd		r8, r9, sp, 128
	__ldrd		r10, r11, sp, 136
	add		r0, r0, r8		// x8
	add		r1, r1, r9		// x9
	add		r6, r6, r10		// x10
	add		r7, r7, r11		// x11
	_le32_bswap_4x	r0, r1, r6, r7,  r8, r9, r10
	stmia		r14!, {r0,r1,r6,r7}
	__ldrd		r8, r9, sp, 144
	__ldrd		r10, r11, sp, 152
	add		r2, r8, r2, ror #drot	// x12
	add		r3, r9, r3, ror #drot	// x13
	add		r4, r10, r4, ror #drot	// x14
	add		r5, r11, r5, ror #drot	// x15
	_le32_bswap_4x	r2, r3, r4, r5,  r9, r10, r11
	stmia		r14, {r2-r5}

	// Stack: ks0-ks15 unused0-unused7 x0-x15 OUT IN LEN
	// Registers: r8 is block counter, r12 is IN.

	ldr		r9, [sp, #168]		// LEN
	ldr		r14, [sp, #160]		// OUT
	cmp		r9, #64
	  mov		r0, sp
	movle		r1, r9
	movgt		r1, #64
	// r1 is number of bytes to XOR, in range [1, 64]

.if __LINUX_ARM_ARCH__ < 6
	orr		r2, r12, r14
	tst		r2, #3			// IN or OUT misaligned?
	bne		.Lxor_next_byte\@
.endif

	// XOR a word at a time
.rept 16
	subs		r1, #4
	blt		.Lxor_words_done\@
	ldr		r2, [r12], #4
	ldr		r3, [r0], #4
	eor		r2, r2, r3
	str		r2, [r14], #4
.endr
	b		.Lxor_slowpath_done\@
.Lxor_words_done\@:
	ands		r1, r1, #3
	beq		.Lxor_slowpath_done\@

	// XOR a byte at a time
.Lxor_next_byte\@:
	ldrb		r2, [r12], #1
	ldrb		r3, [r0], #1
	eor		r2, r2, r3
	strb		r2, [r14], #1
	subs		r1, #1
	bne		.Lxor_next_byte\@

.Lxor_slowpath_done\@:
	subs		r9, #64
	add		sp, #96
	bgt		.Lprepare_for_next_block\@

.Ldone\@:
.endm	// _chacha

/*
 * void chacha20_arm(u8 *out, const u8 *in, size_t len, const u32 key[8],
 *		     const u32 iv[4]);
 */
ENTRY(chacha20_arm)
	cmp		r2, #0			// len == 0?
	reteq		lr

	push		{r0-r2,r4-r11,lr}

	// Push state x0-x15 onto stack.
	// Also store an extra copy of x10-x11 just before the state.

	ldr		r4, [sp, #48]		// iv
	mov		r0, sp
	sub		sp, #80

	// iv: x12-x15
	ldm		r4, {X12,X13,X14,X15}
	stmdb		r0!, {X12,X13,X14,X15}

	// key: x4-x11
	__ldrd		X8_X10, X9_X11, r3, 24
	__strd		X8_X10, X9_X11, sp, 8
	stmdb		r0!, {X8_X10, X9_X11}
	ldm		r3, {X4-X9_X11}
	stmdb		r0!, {X4-X9_X11}

	// constants: x0-x3
	adrl		X3, .Lexpand_32byte_k
	ldm		X3, {X0-X3}
	__strd		X0, X1, sp, 16
	__strd		X2, X3, sp, 24

	_chacha		20

	add		sp, #76
	pop		{r4-r11, pc}
ENDPROC(chacha20_arm)

/*
 * void hchacha20_arm(const u32 state[16], u32 out[8]);
 */
ENTRY(hchacha20_arm)
	push		{r1,r4-r11,lr}

	mov		r14, r0
	ldmia		r14!, {r0-r11}		// load x0-x11
	push		{r10-r11}		// store x10-x11 to stack
	ldm		r14, {r10-r12,r14}	// load x12-x15
	sub		sp, #8

	_chacha_permute	20

	// Skip over (unused0-unused1, x10-x11)
	add		sp, #16

	// Fix up rotations of x12-x15
	ror		X12, X12, #drot
	ror		X13, X13, #drot
	  pop		{r4}			// load 'out'
	ror		X14, X14, #drot
	ror		X15, X15, #drot

	// Store (x0-x3,x12-x15) to 'out'
	stm		r4, {X0,X1,X2,X3,X12,X13,X14,X15}

	pop		{r4-r11,pc}
ENDPROC(hchacha20_arm)

#ifdef CONFIG_KERNEL_MODE_NEON
/*
 * This following NEON routine was ported from Andy Polyakov's implementation
 * from CRYPTOGAMS. It begins with parts of the CRYPTOGAMS scalar routine,
 * since certain NEON code paths actually branch to it.
 */

.text
#if defined(__thumb2__) || defined(__clang__)
.syntax	unified
#endif
#if defined(__thumb2__)
.thumb
#else
.code	32
#endif

#if defined(__thumb2__) || defined(__clang__)
#define ldrhsb	ldrbhs
#endif

.align	4
.Loop_outer:
	ldmia	sp,{r0-r9}		@ load key material
	str	r11,[sp,#4*(32+2)]	@ save len
	str	r12,  [sp,#4*(32+1)]	@ save inp
	str	r14,  [sp,#4*(32+0)]	@ save out
.Loop_outer_enter:
	ldr	r11, [sp,#4*(15)]
	 mov	r4,r4,ror#19	@ twist b[0..3]
	ldr	r12,[sp,#4*(12)]	@ modulo-scheduled load
	 mov	r5,r5,ror#19
	ldr	r10, [sp,#4*(13)]
	 mov	r6,r6,ror#19
	ldr	r14,[sp,#4*(14)]
	 mov	r7,r7,ror#19
	mov	r11,r11,ror#8	@ twist d[0..3]
	mov	r12,r12,ror#8
	mov	r10,r10,ror#8
	mov	r14,r14,ror#8
	str	r11, [sp,#4*(16+15)]
	mov	r11,#10
	b	.Loop

.align	4
.Loop:
	subs	r11,r11,#1
	add	r0,r0,r4,ror#13
	add	r1,r1,r5,ror#13
	eor	r12,r0,r12,ror#24
	eor	r10,r1,r10,ror#24
	add	r8,r8,r12,ror#16
	add	r9,r9,r10,ror#16
	eor	r4,r8,r4,ror#13
	eor	r5,r9,r5,ror#13
	add	r0,r0,r4,ror#20
	add	r1,r1,r5,ror#20
	eor	r12,r0,r12,ror#16
	eor	r10,r1,r10,ror#16
	add	r8,r8,r12,ror#24
	str	r10,[sp,#4*(16+13)]
	add	r9,r9,r10,ror#24
	ldr	r10,[sp,#4*(16+15)]
	str	r8,[sp,#4*(16+8)]
	eor	r4,r4,r8,ror#12
	str	r9,[sp,#4*(16+9)]
	eor	r5,r5,r9,ror#12
	ldr	r8,[sp,#4*(16+10)]
	add	r2,r2,r6,ror#13
	ldr	r9,[sp,#4*(16+11)]
	add	r3,r3,r7,ror#13
	eor	r14,r2,r14,ror#24
	eor	r10,r3,r10,ror#24
	add	r8,r8,r14,ror#16
	add	r9,r9,r10,ror#16
	eor	r6,r8,r6,ror#13
	eor	r7,r9,r7,ror#13
	add	r2,r2,r6,ror#20
	add	r3,r3,r7,ror#20
	eor	r14,r2,r14,ror#16
	eor	r10,r3,r10,ror#16
	add	r8,r8,r14,ror#24
	add	r9,r9,r10,ror#24
	eor	r6,r6,r8,ror#12
	eor	r7,r7,r9,ror#12
	add	r0,r0,r5,ror#13
	add	r1,r1,r6,ror#13
	eor	r10,r0,r10,ror#24
	eor	r12,r1,r12,ror#24
	add	r8,r8,r10,ror#16
	add	r9,r9,r12,ror#16
	eor	r5,r8,r5,ror#13
	eor	r6,r9,r6,ror#13
	add	r0,r0,r5,ror#20
	add	r1,r1,r6,ror#20
	eor	r10,r0,r10,ror#16
	eor	r12,r1,r12,ror#16
	str	r10,[sp,#4*(16+15)]
	add	r8,r8,r10,ror#24
	ldr	r10,[sp,#4*(16+13)]
	add	r9,r9,r12,ror#24
	str	r8,[sp,#4*(16+10)]
	eor	r5,r5,r8,ror#12
	str	r9,[sp,#4*(16+11)]
	eor	r6,r6,r9,ror#12
	ldr	r8,[sp,#4*(16+8)]
	add	r2,r2,r7,ror#13
	ldr	r9,[sp,#4*(16+9)]
	add	r3,r3,r4,ror#13
	eor	r10,r2,r10,ror#24
	eor	r14,r3,r14,ror#24
	add	r8,r8,r10,ror#16
	add	r9,r9,r14,ror#16
	eor	r7,r8,r7,ror#13
	eor	r4,r9,r4,ror#13
	add	r2,r2,r7,ror#20
	add	r3,r3,r4,ror#20
	eor	r10,r2,r10,ror#16
	eor	r14,r3,r14,ror#16
	add	r8,r8,r10,ror#24
	add	r9,r9,r14,ror#24
	eor	r7,r7,r8,ror#12
	eor	r4,r4,r9,ror#12
	bne	.Loop

	ldr	r11,[sp,#4*(32+2)]	@ load len

	str	r8, [sp,#4*(16+8)]	@ modulo-scheduled store
	str	r9, [sp,#4*(16+9)]
	str	r12,[sp,#4*(16+12)]
	str	r10, [sp,#4*(16+13)]
	str	r14,[sp,#4*(16+14)]

	@ at this point we have first half of 512-bit result in
	@ rx and second half at sp+4*(16+8)

	cmp	r11,#64		@ done yet?
#ifdef __thumb2__
	itete	lo
#endif
	addlo	r12,sp,#4*(0)		@ shortcut or ...
	ldrhs	r12,[sp,#4*(32+1)]	@ ... load inp
	addlo	r14,sp,#4*(0)		@ shortcut or ...
	ldrhs	r14,[sp,#4*(32+0)]	@ ... load out

	ldr	r8,[sp,#4*(0)]	@ load key material
	ldr	r9,[sp,#4*(1)]

#if __LINUX_ARM_ARCH__ >= 6 || !defined(__ARMEB__)
#if __LINUX_ARM_ARCH__ < 7
	orr	r10,r12,r14
	tst	r10,#3		@ are input and output aligned?
	ldr	r10,[sp,#4*(2)]
	bne	.Lunaligned
	cmp	r11,#64		@ restore flags
#else
	ldr	r10,[sp,#4*(2)]
#endif
	ldr	r11,[sp,#4*(3)]

	add	r0,r0,r8	@ accumulate key material
	add	r1,r1,r9
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r8,[r12],#16		@ load input
	ldrhs	r9,[r12,#-12]

	add	r2,r2,r10
	add	r3,r3,r11
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r10,[r12,#-8]
	ldrhs	r11,[r12,#-4]
#if __LINUX_ARM_ARCH__ >= 6 && defined(__ARMEB__)
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r0,r0,r8	@ xor with input
	eorhs	r1,r1,r9
	 add	r8,sp,#4*(4)
	str	r0,[r14],#16		@ store output
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r2,r2,r10
	eorhs	r3,r3,r11
	 ldmia	r8,{r8-r11}	@ load key material
	str	r1,[r14,#-12]
	str	r2,[r14,#-8]
	str	r3,[r14,#-4]

	add	r4,r8,r4,ror#13 @ accumulate key material
	add	r5,r9,r5,ror#13
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r8,[r12],#16		@ load input
	ldrhs	r9,[r12,#-12]
	add	r6,r10,r6,ror#13
	add	r7,r11,r7,ror#13
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r10,[r12,#-8]
	ldrhs	r11,[r12,#-4]
#if __LINUX_ARM_ARCH__ >= 6 && defined(__ARMEB__)
	rev	r4,r4
	rev	r5,r5
	rev	r6,r6
	rev	r7,r7
#endif
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r4,r4,r8
	eorhs	r5,r5,r9
	 add	r8,sp,#4*(8)
	str	r4,[r14],#16		@ store output
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r6,r6,r10
	eorhs	r7,r7,r11
	str	r5,[r14,#-12]
	 ldmia	r8,{r8-r11}	@ load key material
	str	r6,[r14,#-8]
	 add	r0,sp,#4*(16+8)
	str	r7,[r14,#-4]

	ldmia	r0,{r0-r7}	@ load second half

	add	r0,r0,r8	@ accumulate key material
	add	r1,r1,r9
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r8,[r12],#16		@ load input
	ldrhs	r9,[r12,#-12]
#ifdef __thumb2__
	itt	hi
#endif
	 strhi	r10,[sp,#4*(16+10)]	@ copy "rx" while at it
	 strhi	r11,[sp,#4*(16+11)]	@ copy "rx" while at it
	add	r2,r2,r10
	add	r3,r3,r11
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r10,[r12,#-8]
	ldrhs	r11,[r12,#-4]
#if __LINUX_ARM_ARCH__ >= 6 && defined(__ARMEB__)
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r0,r0,r8
	eorhs	r1,r1,r9
	 add	r8,sp,#4*(12)
	str	r0,[r14],#16		@ store output
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r2,r2,r10
	eorhs	r3,r3,r11
	str	r1,[r14,#-12]
	 ldmia	r8,{r8-r11}	@ load key material
	str	r2,[r14,#-8]
	str	r3,[r14,#-4]

	add	r4,r8,r4,ror#24 @ accumulate key material
	add	r5,r9,r5,ror#24
#ifdef __thumb2__
	itt	hi
#endif
	 addhi	r8,r8,#1		@ next counter value
	 strhi	r8,[sp,#4*(12)]	@ save next counter value
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r8,[r12],#16		@ load input
	ldrhs	r9,[r12,#-12]
	add	r6,r10,r6,ror#24
	add	r7,r11,r7,ror#24
#ifdef __thumb2__
	itt	hs
#endif
	ldrhs	r10,[r12,#-8]
	ldrhs	r11,[r12,#-4]
#if __LINUX_ARM_ARCH__ >= 6 && defined(__ARMEB__)
	rev	r4,r4
	rev	r5,r5
	rev	r6,r6
	rev	r7,r7
#endif
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r4,r4,r8
	eorhs	r5,r5,r9
#ifdef __thumb2__
	 it	ne
#endif
	 ldrne	r8,[sp,#4*(32+2)]	@ re-load len
#ifdef __thumb2__
	itt	hs
#endif
	eorhs	r6,r6,r10
	eorhs	r7,r7,r11
	str	r4,[r14],#16		@ store output
	str	r5,[r14,#-12]
#ifdef __thumb2__
	it	hs
#endif
	 subhs	r11,r8,#64		@ len-=64
	str	r6,[r14,#-8]
	str	r7,[r14,#-4]
	bhi	.Loop_outer

	beq	.Ldone
#if __LINUX_ARM_ARCH__ < 7
	b	.Ltail

.align	4
.Lunaligned:				@ unaligned endian-neutral path
	cmp	r11,#64		@ restore flags
#endif
#endif
#if __LINUX_ARM_ARCH__ < 7
	ldr	r11,[sp,#4*(3)]
	add	r0,r8,r0	@ accumulate key material
	add	r1,r9,r1
	add	r2,r10,r2
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r8,r8,r8		@ zero or ...
	ldrhsb	r8,[r12],#16			@ ... load input
	eorlo	r9,r9,r9
	ldrhsb	r9,[r12,#-12]

	add	r3,r11,r3
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r10,r10,r10
	ldrhsb	r10,[r12,#-8]
	eorlo	r11,r11,r11
	ldrhsb	r11,[r12,#-4]

	eor	r0,r8,r0		@ xor with input (or zero)
	eor	r1,r9,r1
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-15]		@ load more input
	ldrhsb	r9,[r12,#-11]
	eor	r2,r10,r2
	 strb	r0,[r14],#16		@ store output
	eor	r3,r11,r3
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-7]
	ldrhsb	r11,[r12,#-3]
	 strb	r1,[r14,#-12]
	eor	r0,r8,r0,lsr#8
	 strb	r2,[r14,#-8]
	eor	r1,r9,r1,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-14]		@ load more input
	ldrhsb	r9,[r12,#-10]
	 strb	r3,[r14,#-4]
	eor	r2,r10,r2,lsr#8
	 strb	r0,[r14,#-15]
	eor	r3,r11,r3,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-6]
	ldrhsb	r11,[r12,#-2]
	 strb	r1,[r14,#-11]
	eor	r0,r8,r0,lsr#8
	 strb	r2,[r14,#-7]
	eor	r1,r9,r1,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-13]		@ load more input
	ldrhsb	r9,[r12,#-9]
	 strb	r3,[r14,#-3]
	eor	r2,r10,r2,lsr#8
	 strb	r0,[r14,#-14]
	eor	r3,r11,r3,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-5]
	ldrhsb	r11,[r12,#-1]
	 strb	r1,[r14,#-10]
	 strb	r2,[r14,#-6]
	eor	r0,r8,r0,lsr#8
	 strb	r3,[r14,#-2]
	eor	r1,r9,r1,lsr#8
	 strb	r0,[r14,#-13]
	eor	r2,r10,r2,lsr#8
	 strb	r1,[r14,#-9]
	eor	r3,r11,r3,lsr#8
	 strb	r2,[r14,#-5]
	 strb	r3,[r14,#-1]
	add	r8,sp,#4*(4+0)
	ldmia	r8,{r8-r11}		@ load key material
	add	r0,sp,#4*(16+8)
	add	r4,r8,r4,ror#13	@ accumulate key material
	add	r5,r9,r5,ror#13
	add	r6,r10,r6,ror#13
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r8,r8,r8		@ zero or ...
	ldrhsb	r8,[r12],#16			@ ... load input
	eorlo	r9,r9,r9
	ldrhsb	r9,[r12,#-12]

	add	r7,r11,r7,ror#13
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r10,r10,r10
	ldrhsb	r10,[r12,#-8]
	eorlo	r11,r11,r11
	ldrhsb	r11,[r12,#-4]

	eor	r4,r8,r4		@ xor with input (or zero)
	eor	r5,r9,r5
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-15]		@ load more input
	ldrhsb	r9,[r12,#-11]
	eor	r6,r10,r6
	 strb	r4,[r14],#16		@ store output
	eor	r7,r11,r7
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-7]
	ldrhsb	r11,[r12,#-3]
	 strb	r5,[r14,#-12]
	eor	r4,r8,r4,lsr#8
	 strb	r6,[r14,#-8]
	eor	r5,r9,r5,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-14]		@ load more input
	ldrhsb	r9,[r12,#-10]
	 strb	r7,[r14,#-4]
	eor	r6,r10,r6,lsr#8
	 strb	r4,[r14,#-15]
	eor	r7,r11,r7,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-6]
	ldrhsb	r11,[r12,#-2]
	 strb	r5,[r14,#-11]
	eor	r4,r8,r4,lsr#8
	 strb	r6,[r14,#-7]
	eor	r5,r9,r5,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-13]		@ load more input
	ldrhsb	r9,[r12,#-9]
	 strb	r7,[r14,#-3]
	eor	r6,r10,r6,lsr#8
	 strb	r4,[r14,#-14]
	eor	r7,r11,r7,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-5]
	ldrhsb	r11,[r12,#-1]
	 strb	r5,[r14,#-10]
	 strb	r6,[r14,#-6]
	eor	r4,r8,r4,lsr#8
	 strb	r7,[r14,#-2]
	eor	r5,r9,r5,lsr#8
	 strb	r4,[r14,#-13]
	eor	r6,r10,r6,lsr#8
	 strb	r5,[r14,#-9]
	eor	r7,r11,r7,lsr#8
	 strb	r6,[r14,#-5]
	 strb	r7,[r14,#-1]
	add	r8,sp,#4*(4+4)
	ldmia	r8,{r8-r11}		@ load key material
	ldmia	r0,{r0-r7}		@ load second half
#ifdef __thumb2__
	itt	hi
#endif
	strhi	r10,[sp,#4*(16+10)]		@ copy "rx"
	strhi	r11,[sp,#4*(16+11)]		@ copy "rx"
	add	r0,r8,r0	@ accumulate key material
	add	r1,r9,r1
	add	r2,r10,r2
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r8,r8,r8		@ zero or ...
	ldrhsb	r8,[r12],#16			@ ... load input
	eorlo	r9,r9,r9
	ldrhsb	r9,[r12,#-12]

	add	r3,r11,r3
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r10,r10,r10
	ldrhsb	r10,[r12,#-8]
	eorlo	r11,r11,r11
	ldrhsb	r11,[r12,#-4]

	eor	r0,r8,r0		@ xor with input (or zero)
	eor	r1,r9,r1
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-15]		@ load more input
	ldrhsb	r9,[r12,#-11]
	eor	r2,r10,r2
	 strb	r0,[r14],#16		@ store output
	eor	r3,r11,r3
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-7]
	ldrhsb	r11,[r12,#-3]
	 strb	r1,[r14,#-12]
	eor	r0,r8,r0,lsr#8
	 strb	r2,[r14,#-8]
	eor	r1,r9,r1,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-14]		@ load more input
	ldrhsb	r9,[r12,#-10]
	 strb	r3,[r14,#-4]
	eor	r2,r10,r2,lsr#8
	 strb	r0,[r14,#-15]
	eor	r3,r11,r3,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-6]
	ldrhsb	r11,[r12,#-2]
	 strb	r1,[r14,#-11]
	eor	r0,r8,r0,lsr#8
	 strb	r2,[r14,#-7]
	eor	r1,r9,r1,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-13]		@ load more input
	ldrhsb	r9,[r12,#-9]
	 strb	r3,[r14,#-3]
	eor	r2,r10,r2,lsr#8
	 strb	r0,[r14,#-14]
	eor	r3,r11,r3,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-5]
	ldrhsb	r11,[r12,#-1]
	 strb	r1,[r14,#-10]
	 strb	r2,[r14,#-6]
	eor	r0,r8,r0,lsr#8
	 strb	r3,[r14,#-2]
	eor	r1,r9,r1,lsr#8
	 strb	r0,[r14,#-13]
	eor	r2,r10,r2,lsr#8
	 strb	r1,[r14,#-9]
	eor	r3,r11,r3,lsr#8
	 strb	r2,[r14,#-5]
	 strb	r3,[r14,#-1]
	add	r8,sp,#4*(4+8)
	ldmia	r8,{r8-r11}		@ load key material
	add	r4,r8,r4,ror#24	@ accumulate key material
#ifdef __thumb2__
	itt	hi
#endif
	addhi	r8,r8,#1			@ next counter value
	strhi	r8,[sp,#4*(12)]		@ save next counter value
	add	r5,r9,r5,ror#24
	add	r6,r10,r6,ror#24
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r8,r8,r8		@ zero or ...
	ldrhsb	r8,[r12],#16			@ ... load input
	eorlo	r9,r9,r9
	ldrhsb	r9,[r12,#-12]

	add	r7,r11,r7,ror#24
#ifdef __thumb2__
	itete	lo
#endif
	eorlo	r10,r10,r10
	ldrhsb	r10,[r12,#-8]
	eorlo	r11,r11,r11
	ldrhsb	r11,[r12,#-4]

	eor	r4,r8,r4		@ xor with input (or zero)
	eor	r5,r9,r5
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-15]		@ load more input
	ldrhsb	r9,[r12,#-11]
	eor	r6,r10,r6
	 strb	r4,[r14],#16		@ store output
	eor	r7,r11,r7
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-7]
	ldrhsb	r11,[r12,#-3]
	 strb	r5,[r14,#-12]
	eor	r4,r8,r4,lsr#8
	 strb	r6,[r14,#-8]
	eor	r5,r9,r5,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-14]		@ load more input
	ldrhsb	r9,[r12,#-10]
	 strb	r7,[r14,#-4]
	eor	r6,r10,r6,lsr#8
	 strb	r4,[r14,#-15]
	eor	r7,r11,r7,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-6]
	ldrhsb	r11,[r12,#-2]
	 strb	r5,[r14,#-11]
	eor	r4,r8,r4,lsr#8
	 strb	r6,[r14,#-7]
	eor	r5,r9,r5,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r8,[r12,#-13]		@ load more input
	ldrhsb	r9,[r12,#-9]
	 strb	r7,[r14,#-3]
	eor	r6,r10,r6,lsr#8
	 strb	r4,[r14,#-14]
	eor	r7,r11,r7,lsr#8
#ifdef __thumb2__
	itt	hs
#endif
	ldrhsb	r10,[r12,#-5]
	ldrhsb	r11,[r12,#-1]
	 strb	r5,[r14,#-10]
	 strb	r6,[r14,#-6]
	eor	r4,r8,r4,lsr#8
	 strb	r7,[r14,#-2]
	eor	r5,r9,r5,lsr#8
	 strb	r4,[r14,#-13]
	eor	r6,r10,r6,lsr#8
	 strb	r5,[r14,#-9]
	eor	r7,r11,r7,lsr#8
	 strb	r6,[r14,#-5]
	 strb	r7,[r14,#-1]
#ifdef __thumb2__
	it	ne
#endif
	ldrne	r8,[sp,#4*(32+2)]		@ re-load len
#ifdef __thumb2__
	it	hs
#endif
	subhs	r11,r8,#64			@ len-=64
	bhi	.Loop_outer

	beq	.Ldone
#endif

.Ltail:
	ldr	r12,[sp,#4*(32+1)]	@ load inp
	add	r9,sp,#4*(0)
	ldr	r14,[sp,#4*(32+0)]	@ load out

.Loop_tail:
	ldrb	r10,[r9],#1	@ read buffer on stack
	ldrb	r11,[r12],#1		@ read input
	subs	r8,r8,#1
	eor	r11,r11,r10
	strb	r11,[r14],#1		@ store output
	bne	.Loop_tail

.Ldone:
	add	sp,sp,#4*(32+3)
	ldmia	sp!,{r4-r11,pc}

.align	5
.Lsigma2:
.long	0x61707865,0x3320646e,0x79622d32,0x6b206574	@ endian-neutral
.Lone2:
.long	1,0,0,0
.word	-1

.arch	armv7-a
.fpu	neon

.align	5
ENTRY(chacha20_neon)
	ldr		r12,[sp,#0]		@ pull pointer to counter and nonce
	stmdb		sp!,{r0-r2,r4-r11,lr}
	cmp		r2,#0			@ len==0?
#ifdef	__thumb2__
	itt		eq
#endif
	addeq		sp,sp,#4*3
	beq		.Lno_data_neon
.Lchacha20_neon_begin:
	adr		r14,.Lsigma2
	vstmdb		sp!,{d8-d15}		@ ABI spec says so
	stmdb		sp!,{r0-r3}

	vld1.32		{q1-q2},[r3]		@ load key
	ldmia		r3,{r4-r11}		@ load key

	sub		sp,sp,#4*(16+16)
	vld1.32		{q3},[r12]		@ load counter and nonce
	add		r12,sp,#4*8
	ldmia		r14,{r0-r3}		@ load sigma
	vld1.32		{q0},[r14]!		@ load sigma
	vld1.32		{q12},[r14]!		@ one
	@ vld1.32	{d30},[r14]		@ rot8
	vst1.32		{q2-q3},[r12]		@ copy 1/2key|counter|nonce
	vst1.32		{q0-q1},[sp]		@ copy sigma|1/2key

	str		r10,[sp,#4*(16+10)]	@ off-load "rx"
	str		r11,[sp,#4*(16+11)]	@ off-load "rx"
	vshl.i32	d26,d24,#1	@ two
	vstr		d24,[sp,#4*(16+0)]
	vshl.i32	d28,d24,#2	@ four
	vstr		d26,[sp,#4*(16+2)]
	vmov		q4,q0
	vstr		d28,[sp,#4*(16+4)]
	vmov		q8,q0
	@ vstr		d30,[sp,#4*(16+6)]
	vmov		q5,q1
	vmov		q9,q1
	b		.Loop_neon_enter

.align	4
.Loop_neon_outer:
	ldmia		sp,{r0-r9}		@ load key material
	cmp		r11,#64*2		@ if len<=64*2
	bls		.Lbreak_neon		@ switch to integer-only
	@ vldr		d30,[sp,#4*(16+6)]	@ rot8
	vmov		q4,q0
	str		r11,[sp,#4*(32+2)]	@ save len
	vmov		q8,q0
	str		r12,  [sp,#4*(32+1)]	@ save inp
	vmov		q5,q1
	str		r14,  [sp,#4*(32+0)]	@ save out
	vmov		q9,q1
.Loop_neon_enter:
	ldr		r11, [sp,#4*(15)]
	 mov		r4,r4,ror#19	@ twist b[0..3]
	vadd.i32	q7,q3,q12		@ counter+1
	ldr		r12,[sp,#4*(12)]	@ modulo-scheduled load
	 mov		r5,r5,ror#19
	vmov		q6,q2
	ldr		r10, [sp,#4*(13)]
	 mov		r6,r6,ror#19
	vmov		q10,q2
	ldr		r14,[sp,#4*(14)]
	 mov		r7,r7,ror#19
	vadd.i32	q11,q7,q12		@ counter+2
	add		r12,r12,#3	@ counter+3
	mov		r11,r11,ror#8	@ twist d[0..3]
	mov		r12,r12,ror#8
	mov		r10,r10,ror#8
	mov		r14,r14,ror#8
	str		r11, [sp,#4*(16+15)]
	mov		r11,#10
	b		.Loop_neon

.align	4
.Loop_neon:
	subs		r11,r11,#1
	vadd.i32	q0,q0,q1
	add	r0,r0,r4,ror#13
	vadd.i32	q4,q4,q5
	add	r1,r1,r5,ror#13
	vadd.i32	q8,q8,q9
	eor	r12,r0,r12,ror#24
	veor	q3,q3,q0
	eor	r10,r1,r10,ror#24
	veor	q7,q7,q4
	add	r8,r8,r12,ror#16
	veor	q11,q11,q8
	add	r9,r9,r10,ror#16
	vrev32.16	q3,q3
	eor	r4,r8,r4,ror#13
	vrev32.16	q7,q7
	eor	r5,r9,r5,ror#13
	vrev32.16	q11,q11
	add	r0,r0,r4,ror#20
	vadd.i32	q2,q2,q3
	add	r1,r1,r5,ror#20
	vadd.i32	q6,q6,q7
	eor	r12,r0,r12,ror#16
	vadd.i32	q10,q10,q11
	eor	r10,r1,r10,ror#16
	veor	q12,q1,q2
	add	r8,r8,r12,ror#24
	veor	q13,q5,q6
	str	r10,[sp,#4*(16+13)]
	veor	q14,q9,q10
	add	r9,r9,r10,ror#24
	vshr.u32	q1,q12,#20
	ldr	r10,[sp,#4*(16+15)]
	vshr.u32	q5,q13,#20
	str	r8,[sp,#4*(16+8)]
	vshr.u32	q9,q14,#20
	eor	r4,r4,r8,ror#12
	vsli.32	q1,q12,#12
	str	r9,[sp,#4*(16+9)]
	vsli.32	q5,q13,#12
	eor	r5,r5,r9,ror#12
	vsli.32	q9,q14,#12
	ldr	r8,[sp,#4*(16+10)]
	vadd.i32	q0,q0,q1
	add	r2,r2,r6,ror#13
	vadd.i32	q4,q4,q5
	ldr	r9,[sp,#4*(16+11)]
	vadd.i32	q8,q8,q9
	add	r3,r3,r7,ror#13
	veor	q12,q3,q0
	eor	r14,r2,r14,ror#24
	veor	q13,q7,q4
	eor	r10,r3,r10,ror#24
	veor	q14,q11,q8
	add	r8,r8,r14,ror#16
	vshr.u32	q3,q12,#24
	add	r9,r9,r10,ror#16
	vshr.u32	q7,q13,#24
	eor	r6,r8,r6,ror#13
	vshr.u32	q11,q14,#24
	eor	r7,r9,r7,ror#13
	vsli.32	q3,q12,#8
	add	r2,r2,r6,ror#20
	vsli.32	q7,q13,#8
	add	r3,r3,r7,ror#20
	vsli.32	q11,q14,#8
	eor	r14,r2,r14,ror#16
	vadd.i32	q2,q2,q3
	eor	r10,r3,r10,ror#16
	vadd.i32	q6,q6,q7
	add	r8,r8,r14,ror#24
	vadd.i32	q10,q10,q11
	add	r9,r9,r10,ror#24
	veor	q12,q1,q2
	eor	r6,r6,r8,ror#12
	veor	q13,q5,q6
	eor	r7,r7,r9,ror#12
	veor	q14,q9,q10
	vshr.u32	q1,q12,#25
	vshr.u32	q5,q13,#25
	vshr.u32	q9,q14,#25
	vsli.32	q1,q12,#7
	vsli.32	q5,q13,#7
	vsli.32	q9,q14,#7
	vext.8	q2,q2,q2,#8
	vext.8	q6,q6,q6,#8
	vext.8	q10,q10,q10,#8
	vext.8	q1,q1,q1,#4
	vext.8	q5,q5,q5,#4
	vext.8	q9,q9,q9,#4
	vext.8	q3,q3,q3,#12
	vext.8	q7,q7,q7,#12
	vext.8	q11,q11,q11,#12
	vadd.i32	q0,q0,q1
	add	r0,r0,r5,ror#13
	vadd.i32	q4,q4,q5
	add	r1,r1,r6,ror#13
	vadd.i32	q8,q8,q9
	eor	r10,r0,r10,ror#24
	veor	q3,q3,q0
	eor	r12,r1,r12,ror#24
	veor	q7,q7,q4
	add	r8,r8,r10,ror#16
	veor	q11,q11,q8
	add	r9,r9,r12,ror#16
	vrev32.16	q3,q3
	eor	r5,r8,r5,ror#13
	vrev32.16	q7,q7
	eor	r6,r9,r6,ror#13
	vrev32.16	q11,q11
	add	r0,r0,r5,ror#20
	vadd.i32	q2,q2,q3
	add	r1,r1,r6,ror#20
	vadd.i32	q6,q6,q7
	eor	r10,r0,r10,ror#16
	vadd.i32	q10,q10,q11
	eor	r12,r1,r12,ror#16
	veor	q12,q1,q2
	str	r10,[sp,#4*(16+15)]
	veor	q13,q5,q6
	add	r8,r8,r10,ror#24
	veor	q14,q9,q10
	ldr	r10,[sp,#4*(16+13)]
	vshr.u32	q1,q12,#20
	add	r9,r9,r12,ror#24
	vshr.u32	q5,q13,#20
	str	r8,[sp,#4*(16+10)]
	vshr.u32	q9,q14,#20
	eor	r5,r5,r8,ror#12
	vsli.32	q1,q12,#12
	str	r9,[sp,#4*(16+11)]
	vsli.32	q5,q13,#12
	eor	r6,r6,r9,ror#12
	vsli.32	q9,q14,#12
	ldr	r8,[sp,#4*(16+8)]
	vadd.i32	q0,q0,q1
	add	r2,r2,r7,ror#13
	vadd.i32	q4,q4,q5
	ldr	r9,[sp,#4*(16+9)]
	vadd.i32	q8,q8,q9
	add	r3,r3,r4,ror#13
	veor	q12,q3,q0
	eor	r10,r2,r10,ror#24
	veor	q13,q7,q4
	eor	r14,r3,r14,ror#24
	veor	q14,q11,q8
	add	r8,r8,r10,ror#16
	vshr.u32	q3,q12,#24
	add	r9,r9,r14,ror#16
	vshr.u32	q7,q13,#24
	eor	r7,r8,r7,ror#13
	vshr.u32	q11,q14,#24
	eor	r4,r9,r4,ror#13
	vsli.32	q3,q12,#8
	add	r2,r2,r7,ror#20
	vsli.32	q7,q13,#8
	add	r3,r3,r4,ror#20
	vsli.32	q11,q14,#8
	eor	r10,r2,r10,ror#16
	vadd.i32	q2,q2,q3
	eor	r14,r3,r14,ror#16
	vadd.i32	q6,q6,q7
	add	r8,r8,r10,ror#24
	vadd.i32	q10,q10,q11
	add	r9,r9,r14,ror#24
	veor	q12,q1,q2
	eor	r7,r7,r8,ror#12
	veor	q13,q5,q6
	eor	r4,r4,r9,ror#12
	veor	q14,q9,q10
	vshr.u32	q1,q12,#25
	vshr.u32	q5,q13,#25
	vshr.u32	q9,q14,#25
	vsli.32	q1,q12,#7
	vsli.32	q5,q13,#7
	vsli.32	q9,q14,#7
	vext.8	q2,q2,q2,#8
	vext.8	q6,q6,q6,#8
	vext.8	q10,q10,q10,#8
	vext.8	q1,q1,q1,#12
	vext.8	q5,q5,q5,#12
	vext.8	q9,q9,q9,#12
	vext.8	q3,q3,q3,#4
	vext.8	q7,q7,q7,#4
	vext.8	q11,q11,q11,#4
	bne		.Loop_neon

	add		r11,sp,#32
	vld1.32		{q12-q13},[sp]		@ load key material
	vld1.32		{q14-q15},[r11]

	ldr		r11,[sp,#4*(32+2)]	@ load len

	str		r8, [sp,#4*(16+8)]	@ modulo-scheduled store
	str		r9, [sp,#4*(16+9)]
	str		r12,[sp,#4*(16+12)]
	str		r10, [sp,#4*(16+13)]
	str		r14,[sp,#4*(16+14)]

	@ at this point we have first half of 512-bit result in
	@ rx and second half at sp+4*(16+8)

	ldr		r12,[sp,#4*(32+1)]	@ load inp
	ldr		r14,[sp,#4*(32+0)]	@ load out

	vadd.i32	q0,q0,q12		@ accumulate key material
	vadd.i32	q4,q4,q12
	vadd.i32	q8,q8,q12
	vldr		d24,[sp,#4*(16+0)]	@ one

	vadd.i32	q1,q1,q13
	vadd.i32	q5,q5,q13
	vadd.i32	q9,q9,q13
	vldr		d26,[sp,#4*(16+2)]	@ two

	vadd.i32	q2,q2,q14
	vadd.i32	q6,q6,q14
	vadd.i32	q10,q10,q14
	vadd.i32	d14,d14,d24	@ counter+1
	vadd.i32	d22,d22,d26	@ counter+2

	vadd.i32	q3,q3,q15
	vadd.i32	q7,q7,q15
	vadd.i32	q11,q11,q15

	cmp		r11,#64*4
	blo		.Ltail_neon

	vld1.8		{q12-q13},[r12]!	@ load input
	 mov		r11,sp
	vld1.8		{q14-q15},[r12]!
	veor		q0,q0,q12		@ xor with input
	veor		q1,q1,q13
	vld1.8		{q12-q13},[r12]!
	veor		q2,q2,q14
	veor		q3,q3,q15
	vld1.8		{q14-q15},[r12]!

	veor		q4,q4,q12
	 vst1.8		{q0-q1},[r14]!	@ store output
	veor		q5,q5,q13
	vld1.8		{q12-q13},[r12]!
	veor		q6,q6,q14
	 vst1.8		{q2-q3},[r14]!
	veor		q7,q7,q15
	vld1.8		{q14-q15},[r12]!

	veor		q8,q8,q12
	 vld1.32	{q0-q1},[r11]!	@ load for next iteration
	 veor		d25,d25,d25
	 vldr		d24,[sp,#4*(16+4)]	@ four
	veor		q9,q9,q13
	 vld1.32	{q2-q3},[r11]
	veor		q10,q10,q14
	 vst1.8		{q4-q5},[r14]!
	veor		q11,q11,q15
	 vst1.8		{q6-q7},[r14]!

	vadd.i32	d6,d6,d24	@ next counter value
	vldr		d24,[sp,#4*(16+0)]	@ one

	ldmia		sp,{r8-r11}	@ load key material
	add		r0,r0,r8	@ accumulate key material
	ldr		r8,[r12],#16		@ load input
	 vst1.8		{q8-q9},[r14]!
	add		r1,r1,r9
	ldr		r9,[r12,#-12]
	 vst1.8		{q10-q11},[r14]!
	add		r2,r2,r10
	ldr		r10,[r12,#-8]
	add		r3,r3,r11
	ldr		r11,[r12,#-4]
#ifdef	__ARMEB__
	rev		r0,r0
	rev		r1,r1
	rev		r2,r2
	rev		r3,r3
#endif
	eor		r0,r0,r8	@ xor with input
	 add		r8,sp,#4*(4)
	eor		r1,r1,r9
	str		r0,[r14],#16		@ store output
	eor		r2,r2,r10
	str		r1,[r14,#-12]
	eor		r3,r3,r11
	 ldmia		r8,{r8-r11}	@ load key material
	str		r2,[r14,#-8]
	str		r3,[r14,#-4]

	add		r4,r8,r4,ror#13 @ accumulate key material
	ldr		r8,[r12],#16		@ load input
	add		r5,r9,r5,ror#13
	ldr		r9,[r12,#-12]
	add		r6,r10,r6,ror#13
	ldr		r10,[r12,#-8]
	add		r7,r11,r7,ror#13
	ldr		r11,[r12,#-4]
#ifdef	__ARMEB__
	rev		r4,r4
	rev		r5,r5
	rev		r6,r6
	rev		r7,r7
#endif
	eor		r4,r4,r8
	 add		r8,sp,#4*(8)
	eor		r5,r5,r9
	str		r4,[r14],#16		@ store output
	eor		r6,r6,r10
	str		r5,[r14,#-12]
	eor		r7,r7,r11
	 ldmia		r8,{r8-r11}	@ load key material
	str		r6,[r14,#-8]
	 add		r0,sp,#4*(16+8)
	str		r7,[r14,#-4]

	ldmia		r0,{r0-r7}	@ load second half

	add		r0,r0,r8	@ accumulate key material
	ldr		r8,[r12],#16		@ load input
	add		r1,r1,r9
	ldr		r9,[r12,#-12]
#ifdef __thumb2__
	it	hi
#endif
	 strhi		r10,[sp,#4*(16+10)]	@ copy "rx" while at it
	add		r2,r2,r10
	ldr		r10,[r12,#-8]
#ifdef __thumb2__
	it	hi
#endif
	 strhi		r11,[sp,#4*(16+11)]	@ copy "rx" while at it
	add		r3,r3,r11
	ldr		r11,[r12,#-4]
#ifdef	__ARMEB__
	rev		r0,r0
	rev		r1,r1
	rev		r2,r2
	rev		r3,r3
#endif
	eor		r0,r0,r8
	 add		r8,sp,#4*(12)
	eor		r1,r1,r9
	str		r0,[r14],#16		@ store output
	eor		r2,r2,r10
	str		r1,[r14,#-12]
	eor		r3,r3,r11
	 ldmia		r8,{r8-r11}	@ load key material
	str		r2,[r14,#-8]
	str		r3,[r14,#-4]

	add		r4,r8,r4,ror#24 @ accumulate key material
	 add		r8,r8,#4		@ next counter value
	add		r5,r9,r5,ror#24
	 str		r8,[sp,#4*(12)]	@ save next counter value
	ldr		r8,[r12],#16		@ load input
	add		r6,r10,r6,ror#24
	 add		r4,r4,#3		@ counter+3
	ldr		r9,[r12,#-12]
	add		r7,r11,r7,ror#24
	ldr		r10,[r12,#-8]
	ldr		r11,[r12,#-4]
#ifdef	__ARMEB__
	rev		r4,r4
	rev		r5,r5
	rev		r6,r6
	rev		r7,r7
#endif
	eor		r4,r4,r8
#ifdef __thumb2__
	it	hi
#endif
	 ldrhi		r8,[sp,#4*(32+2)]	@ re-load len
	eor		r5,r5,r9
	eor		r6,r6,r10
	str		r4,[r14],#16		@ store output
	eor		r7,r7,r11
	str		r5,[r14,#-12]
	 sub		r11,r8,#64*4	@ len-=64*4
	str		r6,[r14,#-8]
	str		r7,[r14,#-4]
	bhi		.Loop_neon_outer

	b		.Ldone_neon

.align	4
.Lbreak_neon:
	@ harmonize NEON and integer-only stack frames: load data
	@ from NEON frame, but save to integer-only one; distance
	@ between the two is 4*(32+4+16-32)=4*(20).

	str		r11, [sp,#4*(20+32+2)]	@ save len
	 add		r11,sp,#4*(32+4)
	str		r12,   [sp,#4*(20+32+1)]	@ save inp
	str		r14,   [sp,#4*(20+32+0)]	@ save out

	ldr		r12,[sp,#4*(16+10)]
	ldr		r14,[sp,#4*(16+11)]
	 vldmia		r11,{d8-d15}			@ fulfill ABI requirement
	str		r12,[sp,#4*(20+16+10)]	@ copy "rx"
	str		r14,[sp,#4*(20+16+11)]	@ copy "rx"

	ldr		r11, [sp,#4*(15)]
	 mov		r4,r4,ror#19		@ twist b[0..3]
	ldr		r12,[sp,#4*(12)]		@ modulo-scheduled load
	 mov		r5,r5,ror#19
	ldr		r10, [sp,#4*(13)]
	 mov		r6,r6,ror#19
	ldr		r14,[sp,#4*(14)]
	 mov		r7,r7,ror#19
	mov		r11,r11,ror#8		@ twist d[0..3]
	mov		r12,r12,ror#8
	mov		r10,r10,ror#8
	mov		r14,r14,ror#8
	str		r11, [sp,#4*(20+16+15)]
	add		r11,sp,#4*(20)
	vst1.32		{q0-q1},[r11]!		@ copy key
	add		sp,sp,#4*(20)			@ switch frame
	vst1.32		{q2-q3},[r11]
	mov		r11,#10
	b		.Loop				@ go integer-only

.align	4
.Ltail_neon:
	cmp		r11,#64*3
	bhs		.L192_or_more_neon
	cmp		r11,#64*2
	bhs		.L128_or_more_neon
	cmp		r11,#64*1
	bhs		.L64_or_more_neon

	add		r8,sp,#4*(8)
	vst1.8		{q0-q1},[sp]
	add		r10,sp,#4*(0)
	vst1.8		{q2-q3},[r8]
	b		.Loop_tail_neon

.align	4
.L64_or_more_neon:
	vld1.8		{q12-q13},[r12]!
	vld1.8		{q14-q15},[r12]!
	veor		q0,q0,q12
	veor		q1,q1,q13
	veor		q2,q2,q14
	veor		q3,q3,q15
	vst1.8		{q0-q1},[r14]!
	vst1.8		{q2-q3},[r14]!

	beq		.Ldone_neon

	add		r8,sp,#4*(8)
	vst1.8		{q4-q5},[sp]
	add		r10,sp,#4*(0)
	vst1.8		{q6-q7},[r8]
	sub		r11,r11,#64*1	@ len-=64*1
	b		.Loop_tail_neon

.align	4
.L128_or_more_neon:
	vld1.8		{q12-q13},[r12]!
	vld1.8		{q14-q15},[r12]!
	veor		q0,q0,q12
	veor		q1,q1,q13
	vld1.8		{q12-q13},[r12]!
	veor		q2,q2,q14
	veor		q3,q3,q15
	vld1.8		{q14-q15},[r12]!

	veor		q4,q4,q12
	veor		q5,q5,q13
	 vst1.8		{q0-q1},[r14]!
	veor		q6,q6,q14
	 vst1.8		{q2-q3},[r14]!
	veor		q7,q7,q15
	vst1.8		{q4-q5},[r14]!
	vst1.8		{q6-q7},[r14]!

	beq		.Ldone_neon

	add		r8,sp,#4*(8)
	vst1.8		{q8-q9},[sp]
	add		r10,sp,#4*(0)
	vst1.8		{q10-q11},[r8]
	sub		r11,r11,#64*2	@ len-=64*2
	b		.Loop_tail_neon

.align	4
.L192_or_more_neon:
	vld1.8		{q12-q13},[r12]!
	vld1.8		{q14-q15},[r12]!
	veor		q0,q0,q12
	veor		q1,q1,q13
	vld1.8		{q12-q13},[r12]!
	veor		q2,q2,q14
	veor		q3,q3,q15
	vld1.8		{q14-q15},[r12]!

	veor		q4,q4,q12
	veor		q5,q5,q13
	vld1.8		{q12-q13},[r12]!
	veor		q6,q6,q14
	 vst1.8		{q0-q1},[r14]!
	veor		q7,q7,q15
	vld1.8		{q14-q15},[r12]!

	veor		q8,q8,q12
	 vst1.8		{q2-q3},[r14]!
	veor		q9,q9,q13
	 vst1.8		{q4-q5},[r14]!
	veor		q10,q10,q14
	 vst1.8		{q6-q7},[r14]!
	veor		q11,q11,q15
	vst1.8		{q8-q9},[r14]!
	vst1.8		{q10-q11},[r14]!

	beq		.Ldone_neon

	ldmia		sp,{r8-r11}	@ load key material
	add		r0,r0,r8	@ accumulate key material
	 add		r8,sp,#4*(4)
	add		r1,r1,r9
	add		r2,r2,r10
	add		r3,r3,r11
	 ldmia		r8,{r8-r11}	@ load key material

	add		r4,r8,r4,ror#13 @ accumulate key material
	 add		r8,sp,#4*(8)
	add		r5,r9,r5,ror#13
	add		r6,r10,r6,ror#13
	add		r7,r11,r7,ror#13
	 ldmia		r8,{r8-r11}	@ load key material
#ifdef	__ARMEB__
	rev		r0,r0
	rev		r1,r1
	rev		r2,r2
	rev		r3,r3
	rev		r4,r4
	rev		r5,r5
	rev		r6,r6
	rev		r7,r7
#endif
	stmia		sp,{r0-r7}
	 add		r0,sp,#4*(16+8)

	ldmia		r0,{r0-r7}	@ load second half

	add		r0,r0,r8	@ accumulate key material
	 add		r8,sp,#4*(12)
	add		r1,r1,r9
	add		r2,r2,r10
	add		r3,r3,r11
	 ldmia		r8,{r8-r11}	@ load key material

	add		r4,r8,r4,ror#24 @ accumulate key material
	 add		r8,sp,#4*(8)
	add		r5,r9,r5,ror#24
	 add		r4,r4,#3		@ counter+3
	add		r6,r10,r6,ror#24
	add		r7,r11,r7,ror#24
	 ldr		r11,[sp,#4*(32+2)]	@ re-load len
#ifdef	__ARMEB__
	rev		r0,r0
	rev		r1,r1
	rev		r2,r2
	rev		r3,r3
	rev		r4,r4
	rev		r5,r5
	rev		r6,r6
	rev		r7,r7
#endif
	stmia		r8,{r0-r7}
	 add		r10,sp,#4*(0)
	 sub		r11,r11,#64*3	@ len-=64*3

.Loop_tail_neon:
	ldrb		r8,[r10],#1	@ read buffer on stack
	ldrb		r9,[r12],#1		@ read input
	subs		r11,r11,#1
	eor		r8,r8,r9
	strb		r8,[r14],#1		@ store output
	bne		.Loop_tail_neon

.Ldone_neon:
	add		sp,sp,#4*(32+4)
	vldmia		sp,{d8-d15}
	add		sp,sp,#4*(16+3)
.Lno_data_neon:
	ldmia		sp!,{r4-r11,pc}
ENDPROC(chacha20_neon)
#endif
