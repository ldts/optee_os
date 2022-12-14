// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt_hash.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <se050.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <utee_defines.h>
#include <util.h>

struct se050_digest_ctx {
	struct crypto_hash_ctx hash_ctx;
	sss_se05x_digest_t digest_ctx;
	sss_algorithm_t algorithm;
	uint8_t *cnt;
};

static const struct crypto_hash_ops se050_digest_ops;

static struct se050_digest_ctx *to_digest_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &se050_digest_ops);

	return container_of(ctx, struct se050_digest_ctx, hash_ctx);
}

static TEE_Result se050_digest_init(struct crypto_hash_ctx *ctx)
{
	struct se050_digest_ctx *c = to_digest_ctx(ctx);
	sss_status_t status = kStatus_SSS_Success;

	memset(&c->digest_ctx, 0, sizeof(c->digest_ctx));

	status = sss_se05x_digest_context_init(&c->digest_ctx,
					       se050_session,
					       c->algorithm,
					       kMode_SSS_Digest);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	status = sss_se05x_digest_init(&c->digest_ctx);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se050_digest_update(struct crypto_hash_ctx *ctx,
				      const uint8_t *data, size_t len)
{
	struct se050_digest_ctx *c = to_digest_ctx(ctx);
	const size_t max_buffer = 800; /* max buffer of the i2c transport */
	uint8_t *p = (uint8_t *)data;
	sss_status_t status = kStatus_SSS_Success;
	size_t tx = 0;

	do {
		tx = len > max_buffer ? max_buffer : len;

		status = sss_se05x_digest_update(&c->digest_ctx, p, tx);
		if (status != kStatus_SSS_Success)
			return TEE_ERROR_GENERIC;

		p = p + tx;
		len = len - tx;
	} while (len);

	return TEE_SUCCESS;
}

static TEE_Result se050_digest_final(struct crypto_hash_ctx *ctx,
				     uint8_t *digest, size_t len)
{
	struct se050_digest_ctx *c = to_digest_ctx(ctx);
	sss_status_t status = kStatus_SSS_Success;
	size_t l = len;

	if (len == 0 || len < TEE_MD5_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	status = sss_se05x_digest_finish(&c->digest_ctx, digest, &l);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static void se050_digest_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct se050_digest_ctx *c = to_digest_ctx(ctx);
	int val = se050_refcount_final_ctx(c->cnt);

	if (val)
		sss_se05x_digest_context_free(&c->digest_ctx);

	free(c);
}

static void se050_digest_copy_state(struct crypto_hash_ctx *dst_ctx,
				    struct crypto_hash_ctx *src_ctx)
{
	struct se050_digest_ctx *src = to_digest_ctx(src_ctx);
	struct se050_digest_ctx *dst = to_digest_ctx(dst_ctx);

	se050_refcount_init_ctx(&src->cnt);
	memcpy(dst, src, sizeof(*dst));
}

static const struct crypto_hash_ops se050_digest_ops = {
	.copy_state = se050_digest_copy_state,
	.free_ctx = se050_digest_free_ctx,
	.update = se050_digest_update,
	.final = se050_digest_final,
	.init = se050_digest_init,
};

static TEE_Result se05x_hash_alloc(struct crypto_hash_ctx **ctx_ret,
				   uint32_t algorithm)
{
	struct se050_digest_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	switch (algorithm) {
	case TEE_ALG_SHA1:
		c->algorithm = kAlgorithm_SSS_SHA1;
		break;
	case TEE_ALG_SHA224:
		c->algorithm = kAlgorithm_SSS_SHA224;
		break;
	case TEE_ALG_SHA256:
		c->algorithm = kAlgorithm_SSS_SHA256;
		break;
	case TEE_ALG_SHA384:
		c->algorithm = kAlgorithm_SSS_SHA384;
		break;
	case TEE_ALG_SHA512:
		c->algorithm = kAlgorithm_SSS_SHA512;
		break;
	default:
		free(c);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	c->hash_ctx.ops = &se050_digest_ops;
	*ctx_ret = &c->hash_ctx;

	return TEE_SUCCESS;
}

static TEE_Result hash_init(void)
{
	return drvcrypt_register_hash(se05x_hash_alloc);
}

service_init(hash_init);

