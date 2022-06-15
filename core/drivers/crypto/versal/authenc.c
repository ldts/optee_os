// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <crypto/internal_aes-gcm.h>
#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

#include "ipi.h"

#define GCM_TAG_LEN		16

#define	XSECURE_AES_KEY_SIZE_128  0   /* Key Length = 32 bytes = 256 bits */
#define	XSECURE_AES_KEY_SIZE_256  2   /* Key Length = 16 bytes = 128 bits */

#define XSECURE_ENCRYPT 0
#define XSECURE_DECRYPT 1

enum aes_key_src {
	XSECURE_AES_BBRAM_KEY = 0,              /* BBRAM Key */
	XSECURE_AES_BBRAM_RED_KEY,              /* BBRAM Red Key */
	XSECURE_AES_BH_KEY,                     /* BH Key */
	XSECURE_AES_BH_RED_KEY,                 /* BH Red Key */
	XSECURE_AES_EFUSE_KEY,                  /* eFUSE Key */
	XSECURE_AES_EFUSE_RED_KEY,              /* eFUSE Red Key */
	XSECURE_AES_EFUSE_USER_KEY_0,           /* eFUSE User Key 0 */
	XSECURE_AES_EFUSE_USER_KEY_1,           /* eFUSE User Key 1 */
	XSECURE_AES_EFUSE_USER_RED_KEY_0,       /* eFUSE User Red Key 0 */
	XSECURE_AES_EFUSE_USER_RED_KEY_1,       /* eFUSE User Red Key 1 */
	XSECURE_AES_KUP_KEY,                    /* KUP key */
	XSECURE_AES_PUF_KEY,                    /* PUF key */
	XSECURE_AES_USER_KEY_0,                 /* User Key 0 */
	XSECURE_AES_USER_KEY_1,                 /* User Key 1 */
	XSECURE_AES_USER_KEY_2,                 /* User Key 2 */
	XSECURE_AES_USER_KEY_3,                 /* User Key 3 */
	XSECURE_AES_USER_KEY_4,                 /* User Key 4 */
	XSECURE_AES_USER_KEY_5,                 /* User Key 5 */
	XSECURE_AES_USER_KEY_6,                 /* User Key 6 */
	XSECURE_AES_USER_KEY_7,                 /* User Key 7 */
	XSECURE_AES_EXPANDED_KEYS,              /* Expanded keys */
	XSECURE_AES_ALL_KEYS,                   /* AES All keys */
};

struct versal_aes_key {
	enum aes_key_src id;
	struct refcount refc;
	SLIST_ENTRY(versal_aes_key) link;
};

static unsigned int key_list_lock = SPINLOCK_UNLOCK;
static SLIST_HEAD(, versal_aes_key) key_list = SLIST_HEAD_INITIALIZER(key_list);

struct versal_ae_ctx {
	struct crypto_authenc_ctx a_ctx;
	struct versal_aes_key *key;
};

static struct versal_ae_ctx *to_versal_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx);

	return container_of(ctx, struct versal_ae_ctx, a_ctx);
}

static TEE_Result do_init(struct drvcrypt_authenc_init *dinit)
{
	struct versal_ae_ctx *c = to_versal_ctx(dinit->ctx);
	uint32_t key_len = XSECURE_AES_KEY_SIZE_128;
	struct versal_aes_init *init = NULL;
	struct versal_mbox_mem init_buf = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	uint32_t exceptions = 0;

	if (dinit->key.length != 32 && dinit->key.length != 16)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dinit->key.length == 32)
		key_len = XSECURE_AES_KEY_SIZE_256;

	if (c->key)
		goto init_op;

	exceptions = cpu_spin_lock_xsave(&key_list_lock);
	if (SLIST_EMPTY(&key_list)) {
		cpu_spin_unlock_xrestore(&key_list_lock, exceptions);
		return TEE_ERROR_BUSY;
	}
	c->key = SLIST_FIRST(&key_list);
	SLIST_REMOVE_HEAD(&key_list, link);
	cpu_spin_unlock_xrestore(&key_list_lock, exceptions);

	/* initialize the AES engine */
	if (versal_crypto_request(AES_INIT, &arg)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	/* write the key */
	versal_mbox_alloc(dinit->key.length, dinit->key.data, &p);

	arg.data[0] = key_len;
	arg.data[1] = c->key->id;
	arg.dlen = 2;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (versal_crypto_request(AES_WRITE_KEY, &arg)) {
		EMSG("AES_WRITE_KEY error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(&arg, 0, sizeof(arg));
	free(p.buf);
init_op:
	/* send the initialization structure */
	versal_mbox_alloc(sizeof(*init), NULL, &init_buf);
	versal_mbox_alloc(dinit->nonce.length, dinit->nonce.data, &p);

	init = init_buf.buf;
	init->iv_addr = virt_to_phys(p.buf);
	init->operation = dinit->encrypt ? XSECURE_ENCRYPT : XSECURE_DECRYPT;
	init->key_src = c->key->id;
	init->key_len = key_len;

	arg.ibuf[0].buf = init_buf.buf;
	arg.ibuf[0].len = init_buf.alloc_len;
	arg.ibuf[1].buf = p.buf;
	arg.ibuf[1].len = p.alloc_len;
	arg.ibuf[1].only_cache = true;

	if (versal_crypto_request(AES_OP_INIT, &arg)) {
		EMSG("AES_OP_INIT error");
		ret = TEE_ERROR_GENERIC;
	}
out:
	free(p.buf);
	free(init);

	return ret;
}

static TEE_Result do_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	versal_mbox_alloc(dupdate->aad.length, dupdate->aad.data, &p);

	arg.data[0] = (dupdate->aad.length % 16) ? p.alloc_len : p.len;
	arg.dlen = 1;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (versal_crypto_request(AES_UPDATE_AAD, &arg)) {
		EMSG("AES_UPDATE_AAD error");
		ret = TEE_ERROR_GENERIC;
	}

	free(p.buf);

	return ret;
}

static TEE_Result update_payload(struct drvcrypt_authenc_update_payload
				 *dupdate, bool is_last)
{
	enum versal_crypto_api id = AES_DECRYPT_UPDATE;
	struct versal_aes_input_param *input = NULL;
	struct versal_mbox_mem input_cmd = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem q = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	versal_mbox_alloc(dupdate->src.length, dupdate->src.data, &p);
	versal_mbox_alloc(dupdate->dst.length, NULL, &q);
	versal_mbox_alloc(sizeof(*input), NULL, &input_cmd);

	input = input_cmd.buf;
	input->input_addr = virt_to_phys(p.buf);
	input->input_len = dupdate->src.length;
	input->is_last = is_last;

	arg.ibuf[0].buf = input;
	arg.ibuf[0].len = input_cmd.alloc_len;
	arg.ibuf[1].buf = q.buf;
	arg.ibuf[1].len = q.alloc_len;
	arg.ibuf[2].buf = p.buf;
	arg.ibuf[2].len = p.alloc_len;

	if (dupdate->encrypt)
		id = AES_ENCRYPT_UPDATE;

	if (versal_crypto_request(id, &arg)) {
		EMSG("AES_UPDATE_PAYLOAD error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dupdate->dst.data, q.buf, dupdate->dst.length);
out:
	free(p.buf);
	free(q.buf);
	free(input);

	return ret;
}

static TEE_Result do_update_payload(struct drvcrypt_authenc_update_payload *p)
{
	return update_payload(p, false);
}

static TEE_Result do_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	last.ctx = dfinal->ctx;
	last.dst = dfinal->dst;
	last.encrypt = true;
	last.src = dfinal->src;

	ret = update_payload(&last, true);
	if (ret)
		return ret;

	memcpy(dfinal->dst.data, last.dst.data, dfinal->dst.length);

	versal_mbox_alloc(GCM_TAG_LEN, NULL, &p);

	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;
	if (versal_crypto_request(AES_ENCRYPT_FINAL, &arg)) {
		EMSG("AES_ENCRYPT_FINAL error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dfinal->tag.data, p.buf, GCM_TAG_LEN);
	dfinal->tag.length = GCM_TAG_LEN;
out:
	free(p.buf);

	return ret;
}

static TEE_Result do_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	last.ctx = dfinal->ctx;
	last.dst = dfinal->dst;
	last.encrypt = false;
	last.src = dfinal->src;

	ret = update_payload(&last, true);
	if (ret)
		return ret;

	versal_mbox_alloc(dfinal->tag.length, dfinal->tag.data, &p);
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (versal_crypto_request(AES_DECRYPT_FINAL, &arg)) {
		EMSG("AES_DECRYPT_FINAL error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dfinal->dst.data, last.dst.data, dfinal->dst.length);
	memcpy(dfinal->tag.data, p.buf, GCM_TAG_LEN);
	dfinal->tag.length = GCM_TAG_LEN;
out:
	free(p.buf);

	return ret;
}

static void do_final(void *ctx)
{
}

static void do_free(void *ctx)
{
	struct versal_ae_ctx *c = to_versal_ctx(ctx);
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&key_list_lock);

	if (refcount_dec(&c->key->refc)) {
		refcount_set(&c->key->refc, 1);
		SLIST_INSERT_HEAD(&key_list, c->key, link);
	}

	cpu_spin_unlock_xrestore(&key_list_lock, exceptions);

	free(c);
}

static void do_copy_state(void *dst_ctx, void *src_ctx)
{
	struct versal_ae_ctx *src = to_versal_ctx(src_ctx);
	struct versal_ae_ctx *dst = to_versal_ctx(dst_ctx);

	memcpy(dst, src, sizeof(*dst));
	refcount_inc(&src->key->refc);
}

static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	struct versal_ae_ctx *c = NULL;

	if (algo != TEE_ALG_AES_GCM)
		return TEE_ERROR_NOT_IMPLEMENTED;

	c = calloc(1, sizeof(*c));
	if (!c)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx = &c->a_ctx;

	return TEE_SUCCESS;
}

static struct drvcrypt_authenc versal_authenc = {
	.update_payload = do_update_payload,
	.update_aad = do_update_aad,
	.copy_state = do_copy_state,
	.alloc_ctx = do_allocate,
	.enc_final = do_enc_final,
	.dec_final = do_dec_final,
	.free_ctx = do_free,
	.final = do_final,
	.init = do_init,
};

/*
 * This driver reserves all AE_USER_KEYS for its operation - perhaps use a
 * CFG_ so the user can specify a range
 */
static const char *const dt_ctrl_match_table[] = {
	"xlnx,versal-sec-cfg",
};

static TEE_Result enable_secure_status(void)
{
	unsigned int i = 0;
	void *fdt = NULL;
	int node = -1;

	fdt = get_external_dt();
	if (!fdt)
		return TEE_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(dt_ctrl_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
						     dt_ctrl_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0)
		return TEE_SUCCESS;

	if (_fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return TEE_SUCCESS;

	if (dt_enable_secure_status(fdt, node)) {
		EMSG("Not able to set the AES-GCM DTB entry secure");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result versal_register_authenc(void)
{
	const uint32_t user_keys[] = {
		XSECURE_AES_USER_KEY_0, XSECURE_AES_USER_KEY_1,
		XSECURE_AES_USER_KEY_2, XSECURE_AES_USER_KEY_3,
		XSECURE_AES_USER_KEY_4, XSECURE_AES_USER_KEY_5,
		XSECURE_AES_USER_KEY_6, XSECURE_AES_USER_KEY_7,
	};
	struct versal_aes_key *key = NULL;
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	ret = drvcrypt_register_authenc(&versal_authenc);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(user_keys); i++) {
		key = calloc(1, sizeof (*key));
		if (!key)
			return TEE_ERROR_OUT_OF_MEMORY;

		key->id = user_keys[i];
		refcount_set(&key->refc, 1);
		SLIST_INSERT_HEAD(&key_list, key, link);
	}


	return enable_secure_status();
}

driver_init_late(versal_register_authenc);
