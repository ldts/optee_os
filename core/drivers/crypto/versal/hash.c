// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>

#include "ipi.h"

#define FIRST_PACKET	BIT(30)
#define NEXT_PACKET	BIT(31)

enum versal_sha3_state { SHA3_STNDBY = 0, SHA3_INIT , SHA3_RUN };

struct versal_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	enum versal_sha3_state state;
};

static const struct crypto_hash_ops versal_ops;

static struct versal_hash_ctx* to_versal_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &versal_ops);

	return container_of(ctx, struct versal_hash_ctx, hash_ctx);
}

static TEE_Result do_hash_init(struct crypto_hash_ctx *ctx)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);

	c->state = SHA3_INIT;

	return TEE_SUCCESS;
}

static TEE_Result do_hash_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);
	struct cmd_args arg = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t init_mask = 0;
	struct versal_crypto_mem p = { };

	if (c->state == SHA3_STNDBY)
		return TEE_ERROR_GENERIC;

	if (c->state == SHA3_INIT)
		init_mask = FIRST_PACKET;

	versal_crypto_alloc(len, data, &p);

	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;
	arg.data[0] = NEXT_PACKET | init_mask | len;
	arg.dlen = 1;

	if (versal_crypto_request(SHA3_UPDATE, &arg))
		ret = TEE_ERROR_GENERIC;
	else
		c->state = SHA3_RUN;

	free(p.buf);

	return ret;
}

static TEE_Result do_hash_final(struct crypto_hash_ctx *ctx,
				uint8_t *digest, size_t len)
{
	struct versal_hash_ctx *c = to_versal_ctx(ctx);
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	struct versal_crypto_mem p = { };

	if (c->state == SHA3_STNDBY)
		return TEE_ERROR_GENERIC;

	versal_crypto_alloc(len, NULL, &p);

	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (versal_crypto_request(SHA3_UPDATE, &arg))
		ret = TEE_ERROR_GENERIC;
	else
		c->state = SHA3_STNDBY;

	memcpy(digest, p.buf, p.len);

	free(p.buf);

	return ret;
}

static void do_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct versal_hash_ctx *src_hctx = NULL;
	struct versal_hash_ctx *dst_hctx = NULL;

	src_hctx = container_of(src_ctx, struct versal_hash_ctx, hash_ctx);
	dst_hctx = container_of(dst_ctx, struct versal_hash_ctx, hash_ctx);

	memcpy(dst_hctx, src_hctx, sizeof(*dst_hctx));
}

static void do_hash_free(struct crypto_hash_ctx *ctx)
{
	struct versal_hash_ctx *hctx = NULL;

	hctx = container_of(ctx, struct versal_hash_ctx, hash_ctx);

	free(hctx);
}

static TEE_Result versal_hash_alloc(struct crypto_hash_ctx **ctx,
				    uint32_t algo)
{
	struct versal_hash_ctx *vctx = NULL;

	if (algo != TEE_ALG_SHA384)
		return TEE_ERROR_NOT_IMPLEMENTED;

	vctx = calloc(1, sizeof(*vctx));
	if (!vctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	vctx->hash_ctx.ops = &versal_ops;
	*ctx = &vctx->hash_ctx;

	return TEE_SUCCESS;
}


static const struct crypto_hash_ops versal_ops = {
	.init = do_hash_init,
	.update = do_hash_update,
	.final = do_hash_final,
	.free_ctx = do_hash_free,
	.copy_state = do_hash_copy_state,
};

static TEE_Result sha3_init(void)
{
	struct cmd_args arg = { };

	if (versal_crypto_request(SHA3_KAT, &arg))
		panic();

	return drvcrypt_register_hash(versal_hash_alloc);
}

driver_init(sha3_init);
