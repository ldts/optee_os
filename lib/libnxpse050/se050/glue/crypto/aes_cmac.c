// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include "aes.h"
#include "aes_cmac.h"
#include <kernel/panic.h>

static void xor(uint8_t *a, uint8_t *b, uint8_t *c, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		c[i] = a[i] ^ b[i];
}

static void left_shift(uint8_t *dest, uint8_t *src, size_t len)
{
	uint8_t overflow = 0;
	int i = 0;

	for (i = len - 1; i >= 0; i--) {
		dest[i] = src[i] << 1 | overflow;
		overflow = (src[i] >> 7) & 1;
	}
}

void gen_subkey(struct aes_ctx *aes_ctx, uint8_t *key, uint8_t *sk_1,
		uint8_t *sk_2)
{
	uint8_t zeros[AES_BLOCKSIZE] = { 0 };
	uint8_t L[AES_BLOCKSIZE] = { 0 };

	AES_encrypt(aes_ctx, zeros, L);

	left_shift(sk_1, L, AES_BLOCKSIZE);
	if (L[0] & 0x80)
		sk_1[15] ^= 0x87;

	left_shift(sk_2, sk_1, AES_BLOCKSIZE);
	if (sk_1[0] & 0x80)
		sk_2[15] ^= 0x87;
}

void aes_cmac_update(struct aes_ctx *context, uint8_t *input, uint8_t *iv,
		     size_t len, uint8_t *key, uint8_t *mac)
{
	uint8_t temp[AES_BLOCKSIZE] = { 0 };

	xor(input, iv, temp, AES_BLOCKSIZE);
	AES_encrypt(context, temp, mac);
}

void aes_cmac_finish(struct aes_ctx *context, uint8_t *input, uint8_t *iv,
		     size_t len, uint8_t *key, uint8_t *mac)
{
	uint8_t sk_1[AES_BLOCKSIZE], sk_2[AES_BLOCKSIZE];
	uint8_t temp[AES_BLOCKSIZE] = { 0 };
	uint8_t *subkey = sk_1;

	gen_subkey(context, key, sk_1, sk_2);
	memcpy(temp, input, len);

	if (len % AES_BLOCKSIZE) {
		temp[len] = 0x80;
		subkey = sk_2;
	}

	xor(temp, subkey, temp, AES_BLOCKSIZE);
	aes_cmac_update(context, temp, iv, 0, NULL, mac);
}

void aes_cmac(uint8_t *input, unsigned long len, uint8_t *key, uint8_t *mac)
{
	uint8_t iv[AES_BLOCKSIZE] = { 0 };
	struct aes_ctx *aes_ctx = NULL;
	size_t i = 0;

	aes_ctx = AES_ctx_alloc(key, 16);
	if (!aes_ctx)
		panic();

	for (i = 0; i < len; i += AES_BLOCKSIZE, input += AES_BLOCKSIZE) {
		if (i + AES_BLOCKSIZE >= len) {
			aes_cmac_finish(aes_ctx, input, iv,
					AES_BLOCKSIZE - len % AES_BLOCKSIZE,
					key, mac);
			free(aes_ctx);
			return;
		}
		aes_cmac_update(aes_ctx, input, iv, AES_BLOCKSIZE, key, iv);
	}
}
