/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __AES_H
#define __AES_H

#include <stdint.h>
#include <stdlib.h>

#define AES_BLOCKSIZE 16

struct aes_ctx {
	uint8_t round_key[(10 + 1) * AES_BLOCKSIZE];
	uint8_t state[4][4];
	int key_len;
	int rounds;
};

void AES_encrypt(struct aes_ctx *ctx, uint8_t *in, uint8_t *out);
void AES_decrypt(struct aes_ctx *ctx, uint8_t *in, uint8_t *out);
struct aes_ctx *AES_ctx_alloc(uint8_t *key, size_t len);

#endif /* __AES_H */
