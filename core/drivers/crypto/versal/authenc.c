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

struct versal_payload {
	struct versal_mbox_mem input_cmd;
	struct versal_mbox_mem src;
	struct versal_mbox_mem dst;
	bool encrypt;
};

struct versal_aad {
	struct versal_mbox_mem mem;
};

struct versal_node {
	struct versal_payload payload;
	struct versal_aad aad;
	bool is_aad;
	STAILQ_ENTRY(versal_node) link;
};

struct versal_init {
	uint32_t key_len;
	uint32_t operation;
	struct versal_mbox_mem key;
	struct versal_mbox_mem nonce;
	struct versal_mbox_mem init_buf;
} ;

struct versal_ae_ctx {
	struct crypto_authenc_ctx a_ctx;
};

enum engine_state {
	READY = 1, INIT = 2, FINALIZED = 3,
};

static struct versal_engine {
	enum aes_key_src key_src;
	enum engine_state state;
	struct versal_init init;
	struct refcount refc;
	STAILQ_HEAD(authenc_replay_list, versal_node) replay_list;
} engine = {
	.key_src = XSECURE_AES_USER_KEY_0,
};

static struct versal_ae_ctx *to_versal_ctx(struct crypto_authenc_ctx *ctx)
{
	assert(ctx);
	return container_of(ctx, struct versal_ae_ctx, a_ctx);
}

static TEE_Result replay_init(void)
{
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	if (versal_crypto_request(AES_INIT, &arg)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	arg.data[0] = engine.init.key_len;
	arg.data[1] = engine.key_src;
	arg.dlen = 2;
	arg.ibuf[0].buf = engine.init.key.buf;
	arg.ibuf[0].len = engine.init.key.alloc_len;

	if (versal_crypto_request(AES_WRITE_KEY, &arg)) {
		EMSG("AES_WRITE_KEY error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(&arg, 0, sizeof(arg));

	arg.ibuf[0].buf = engine.init.init_buf.buf;
	arg.ibuf[0].len = engine.init.init_buf.alloc_len;
	arg.ibuf[1].buf = engine.init.nonce.buf;
	arg.ibuf[1].len = engine.init.nonce.alloc_len;
	arg.ibuf[1].only_cache = true;

	if (versal_crypto_request(AES_OP_INIT, &arg)) {
		EMSG("AES_OP_INIT error");
		ret = TEE_ERROR_GENERIC;
	}
out:
	return ret;
}

static TEE_Result replay_aad(struct versal_aad *p)
{
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	arg.data[0] = (p->mem.len % 16) ? p->mem.alloc_len : p->mem.len;
	arg.dlen = 1;
	arg.ibuf[0].buf = p->mem.buf;
	arg.ibuf[0].len = p->mem.alloc_len;

	if (versal_crypto_request(AES_UPDATE_AAD, &arg)) {
		EMSG("AES_UPDATE_AAD error");
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

static TEE_Result replay_payload(struct versal_payload *p)
{
	enum versal_crypto_api id = AES_DECRYPT_UPDATE;
	struct versal_aes_input_param *input = NULL;
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	input = p->input_cmd.buf;
	input->input_addr = virt_to_phys(p->src.buf);
	input->input_len = p->src.len;
	input->is_last = 0;

	arg.ibuf[0].buf = p->input_cmd.buf;
	arg.ibuf[0].len = p->input_cmd.alloc_len;
	arg.ibuf[1].buf = p->dst.buf;
	arg.ibuf[1].len = p->dst.alloc_len;
	arg.ibuf[2].buf = p->src.buf;
	arg.ibuf[2].len = p->src.alloc_len;

	if (p->encrypt)
		id = AES_ENCRYPT_UPDATE;

	if (versal_crypto_request(id, &arg)) {
		EMSG("AES_UPDATE_PAYLOAD error");
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

static TEE_Result do_replay(void)
{
	struct versal_node *node = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = replay_init();
	if (ret)
		return ret;

	STAILQ_FOREACH(node, &engine.replay_list, link) {
		if (node->is_aad) {
			ret = replay_aad(&node->aad);
			if (ret)
				return ret;
		} else {
			ret = replay_payload(&node->payload);
			if (ret)
				return ret;
		}
	}

	/* engine has been init */
	engine.state = INIT;

	return ret;
}

static TEE_Result do_init(struct drvcrypt_authenc_init *dinit)
{
	uint32_t key_len = XSECURE_AES_KEY_SIZE_128;
	struct versal_aes_init *init = NULL;
	struct versal_mbox_mem init_buf = { };
	struct versal_mbox_mem key = { };
	struct versal_mbox_mem nonce = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	if (dinit->key.length != 32 && dinit->key.length != 16)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dinit->key.length == 32)
		key_len = XSECURE_AES_KEY_SIZE_256;

	if (engine.state != READY)
		return TEE_ERROR_BAD_STATE;

	/* initialize the AES engine */
	if (versal_crypto_request(AES_INIT, &arg)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	/* write the key */
	versal_mbox_alloc(dinit->key.length, dinit->key.data, &key);

	arg.data[0] = key_len;
	arg.data[1] = engine.key_src;
	arg.dlen = 2;
	arg.ibuf[0].buf = key.buf;
	arg.ibuf[0].len = key.alloc_len;

	if (versal_crypto_request(AES_WRITE_KEY, &arg)) {
		EMSG("AES_WRITE_KEY error");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memset(&arg, 0, sizeof(arg));

	/* send the initialization structure */
	versal_mbox_alloc(sizeof(*init), NULL, &init_buf);
	versal_mbox_alloc(dinit->nonce.length, dinit->nonce.data, &nonce);

	init = init_buf.buf;
	init->iv_addr = virt_to_phys(nonce.buf);
	init->operation = dinit->encrypt ? XSECURE_ENCRYPT : XSECURE_DECRYPT;
	init->key_src = engine.key_src;
	init->key_len = key_len;

	arg.ibuf[0].buf = init_buf.buf;
	arg.ibuf[0].len = init_buf.alloc_len;
	arg.ibuf[1].buf = nonce.buf;
	arg.ibuf[1].len = nonce.alloc_len;
	arg.ibuf[1].only_cache = true;

	if (versal_crypto_request(AES_OP_INIT, &arg)) {
		EMSG("AES_OP_INIT error");
		ret = TEE_ERROR_GENERIC;
	}
out:
	/* save key context */
	engine.init.operation = dinit->encrypt ? XSECURE_ENCRYPT : XSECURE_DECRYPT;
	engine.init.key_len = key_len;
	engine.init.init_buf = init_buf;
	engine.init.nonce = nonce;
	engine.init.key = key;

	/* engine has been init*/
	engine.state = INIT;

	return ret;
}

static TEE_Result do_update_aad(struct drvcrypt_authenc_update_aad *dupdate)
{
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	struct versal_node *node = NULL;

	/* if there is a copy, we dont allow updates, only finalize */
	if (refcount_val(&engine.refc) > 1)
		return TEE_ERROR_BUSY;

	/* if there was a copy and it was finalized, we need to replay */
	if (engine.state == FINALIZED)
		do_replay();

	versal_mbox_alloc(dupdate->aad.length, dupdate->aad.data, &p);

	arg.data[0] = (p.len % 16) ? p.alloc_len : p.len;
	arg.dlen = 1;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (versal_crypto_request(AES_UPDATE_AAD, &arg)) {
		EMSG("AES_UPDATE_AAD error (len = %ld)", dupdate->aad.length);
		ret = TEE_ERROR_GENERIC;
	}

	node = calloc(1, sizeof(*node));
	if (!node)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* save the context */
	node->aad.mem = p;
	node->is_aad = true;
	STAILQ_INSERT_TAIL(&engine.replay_list, node, link);

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
	struct versal_node *node = NULL;

	versal_mbox_alloc(dupdate->src.length, dupdate->src.data, &p);
	versal_mbox_alloc(dupdate->dst.length, NULL, &q);
	versal_mbox_alloc(sizeof(*input), NULL, &input_cmd);

	input = input_cmd.buf;
	input->input_addr = virt_to_phys(p.buf);
	input->input_len = (p.len % 4) ? ROUNDUP(p.len, 4) : p.len;
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
		EMSG("AES_UPDATE_PLD error (len = %ld)", dupdate->src.length);
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(dupdate->dst.data, q.buf, dupdate->dst.length);

	/* save the context */
	if (!is_last) {
		node = calloc(1, sizeof(*node));
		if (!node)
			return TEE_ERROR_OUT_OF_MEMORY;

		node->is_aad = false;
		node->payload.dst = q;
		node->payload.src = p;
		node->payload.input_cmd = input_cmd;
		node->payload.encrypt = dupdate->encrypt;
		STAILQ_INSERT_TAIL(&engine.replay_list, node, link);
	} else {
		free(p.buf);
		free(q.buf);
		free(input_cmd.buf);
	}
out:
	return ret;
}

static TEE_Result do_update_payload(struct drvcrypt_authenc_update_payload *p)
{
	TEE_Result ret = TEE_SUCCESS;
	/* If there is a copy, we dont allow updates until one of the copies
	 * has been deleted
	 */
	if (refcount_val(&engine.refc) > 1)
		return TEE_ERROR_BUSY;

	/* if there was a copy and it was finalized, we need to replay before
	 * we can update; do not clear the list so the state can be copied
	 */
	if (engine.state == FINALIZED) {
		ret = do_replay();
		if (ret)
			return ret;
	}

	return update_payload(p, false);
}

static TEE_Result do_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	if (engine.state == FINALIZED) {
		DMSG("Operation was already finalized");
		ret = do_replay();
		if (ret)
			return ret;
	}

	if (engine.state != INIT)
		panic();

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

	if (refcount_val(&engine.refc) > 1)
		engine.state = FINALIZED;
	else
		engine.state = READY;

	return ret;
}

static TEE_Result do_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	struct drvcrypt_authenc_update_payload last = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };

	if (engine.state == FINALIZED) {
		DMSG("Operation was already finalized");
		ret = do_replay();
		if (ret)
			return ret;
	}

	if (engine.state != INIT)
		panic();

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

	if (refcount_val(&engine.refc) > 1)
		engine.state = FINALIZED;
	else
		engine.state = READY;

	return ret;
}

static void do_final(void *ctx)
{
}

static void do_free(void *ctx)
{
	struct versal_ae_ctx *c = to_versal_ctx(ctx);
	struct versal_node *node = NULL;

	if (refcount_dec(&engine.refc)) {
		refcount_set(&engine.refc, 1);
		engine.state = READY;
		free(engine.init.init_buf.buf);
		free(engine.init.nonce.buf);
		free(engine.init.key.buf);
		memset(&engine.init, 0, sizeof(engine.init));
		STAILQ_FOREACH(node, &engine.replay_list, link) {
			STAILQ_REMOVE(&engine.replay_list, node, versal_node, link);
			if (node->is_aad) {
				free(node->aad.mem.buf);
			} else {
				free(node->payload.dst.buf);
				free(node->payload.src.buf);
				free(node->payload.input_cmd.buf);
			}
			free(node);
		}
	}

	free(c);
}

static void do_copy_state(void *dst_ctx, void *src_ctx)
{
	refcount_inc(&engine.refc);
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
	TEE_Result ret = TEE_SUCCESS;

	ret = drvcrypt_register_authenc(&versal_authenc);
	if (ret)
		return ret;

	if (engine.key_src < XSECURE_AES_USER_KEY_0 ||
	    engine.key_src > XSECURE_AES_USER_KEY_7)
		return TEE_ERROR_GENERIC;

	engine.state = READY;
	STAILQ_INIT(&engine.replay_list);
	refcount_set(&engine.refc, 1);

	return enable_secure_status();
}

driver_init_late(versal_register_authenc);
