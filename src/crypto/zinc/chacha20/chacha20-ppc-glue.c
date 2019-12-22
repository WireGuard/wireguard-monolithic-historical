// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>. All Rights Reserved.
 */

asmlinkage void ChaCha20_ctr32_int(u8 *out, const u8 *inp,
				   size_t len, const u32 key[8],
				   const u32 counter[4]);
asmlinkage void ChaCha20_ctr32_vmx(u8 *out, const u8 *inp,
				   size_t len, const u32 key[8],
				   const u32 counter[4]);
asmlinkage void ChaCha20_ctr32_vsx(u8 *out, const u8 *inp,
				   size_t len, const u32 key[8],
				   const u32 counter[4]);
static bool *const chacha20_nobs[] __initconst = { };
static void __init chacha20_fpu_init(void) {}

static inline bool chacha20_arch(struct chacha20_ctx *ctx, u8 *dst,
				 const u8 *src, size_t len,
				 simd_context_t *simd_context)
{
	void (*ChaCha20SIMD)(u8 *out, const u8 *inp,
			     size_t len, const u32 key[8],
			     const u32 counter[4]);

	/* SIMD disables preemption, so relax after processing each page. */
	BUILD_BUG_ON(PAGE_SIZE < CHACHA20_BLOCK_SIZE ||
		     PAGE_SIZE % CHACHA20_BLOCK_SIZE);

	if (cpu_has_feature(CPU_FTR_VSX_COMP))
		ChaCha20SIMD = &ChaCha20_ctr32_vsx;
	else if (cpu_has_feature(CPU_FTR_ALTIVEC_COMP))
                ChaCha20SIMD = &ChaCha20_ctr32_vmx;
	else {
		ChaCha20_ctr32_int(dst, src, len, ctx->key, ctx->counter);
		return true;
	}

	for (;;) {
		if (len >= CHACHA20_BLOCK_SIZE * 3 && simd_use(simd_context)) {
			const size_t bytes = min_t(size_t, len, PAGE_SIZE);

			ChaCha20SIMD(dst, src, bytes, ctx->key, ctx->counter);
			ctx->counter[0] += (bytes + 63) / 64;
			len -= bytes;
			if (!len)
				break;
			dst += bytes;
			src += bytes;
			simd_relax(simd_context);
		} else {
			ChaCha20_ctr32_int(dst, src, len, ctx->key, ctx->counter);
			ctx->counter[0] += (len + 63) / 64;
			return true;
		}
	}
	return true;
}

static inline bool hchacha20_arch(u32 derived_key[CHACHA20_KEY_WORDS],
				  const u8 nonce[HCHACHA20_NONCE_SIZE],
				  const u8 key[HCHACHA20_KEY_SIZE],
				  simd_context_t *simd_context)
{
	return false;
}
