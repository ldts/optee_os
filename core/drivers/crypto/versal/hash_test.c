// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <string.h>

#include "ipi.h"

#define __STR(X) #X
#define STR(X) __STR(X)

#define SHA3_HASH_LEN		48
#define SHA3_INPUT_DATA_LEN	6

static const uint8_t data[SHA3_INPUT_DATA_LEN + 1] = "XILINX";

static uint8_t expected[SHA3_HASH_LEN] = {
	0x70, 0x69, 0x77, 0x35, 0x0b, 0x93,
	0x92, 0xa0, 0x48, 0x2c, 0xd8, 0x23,
	0x38, 0x47, 0xd2, 0xd9, 0x2d, 0x1a,
	0x95, 0x0c, 0xad, 0xa8, 0x60, 0xc0,
	0x9b, 0x70, 0xc6, 0xad, 0x6e, 0xf1,
	0x5d, 0x49, 0x68, 0xa3, 0x50, 0x75,
	0x06, 0xbb, 0x0b, 0x9b, 0x03, 0x7d,
	0xd5, 0x93, 0x76, 0x50, 0xdb, 0xd4
};
static uint8_t out[SHA3_HASH_LEN];

static TEE_Result test_sha3(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA384);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_init(ctx);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_final(ctx, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	/* release the SHA3 engine */
	crypto_hash_free_ctx(ctx);

	return TEE_SUCCESS;
}

static TEE_Result test_sha3_0(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx1;
	void *ctx2;
	void *ctx3;

	crypto_hash_alloc_ctx(&ctx1, TEE_ALG_SHA384);
	crypto_hash_alloc_ctx(&ctx2, TEE_ALG_SHA384);
	crypto_hash_alloc_ctx(&ctx3, TEE_ALG_SHA384);

	crypto_hash_init(ctx1);
	crypto_hash_init(ctx2);
	crypto_hash_init(ctx3);

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx2, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx3, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx1, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx2, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx3, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	crypto_hash_free_ctx(ctx1);
	crypto_hash_free_ctx(ctx2);
	crypto_hash_free_ctx(ctx3);

	/* check that the engine remains accessible */
	return test_sha3();
}

static TEE_Result test_sha3_1(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx1;
	void *ctx2;

	crypto_hash_alloc_ctx(&ctx1, TEE_ALG_SHA384);
	crypto_hash_alloc_ctx(&ctx2, TEE_ALG_SHA384);

	crypto_hash_init(ctx1);

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	crypto_hash_copy_state(ctx2, ctx1);

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx2, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx1, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	crypto_hash_free_ctx(ctx1);
	crypto_hash_free_ctx(ctx2);

	return test_sha3();
}

static TEE_Result test_sha3_2(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx1;
	void *ctx2;

	crypto_hash_alloc_ctx(&ctx1, TEE_ALG_SHA384);
	crypto_hash_alloc_ctx(&ctx2, TEE_ALG_SHA384);

	crypto_hash_init(ctx1);

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	crypto_hash_copy_state(ctx2, ctx1);
	crypto_hash_free_ctx(ctx1);

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx2, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, expected, sizeof(expected))) {
		EMSG("%s %d", __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	crypto_hash_free_ctx(ctx2);

	return test_sha3();
}

static TEE_Result test_sha3_3(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx1;
	uint8_t result[] = {
		0xe4, 0x11, 0x98, 0x30, 0x6d, 0xad, 0xed, 0x1a,
		0x4a, 0x5f, 0x61, 0xe1, 0x76, 0x1e, 0xac, 0x09,
		0x4a, 0x88, 0xb1, 0xad, 0xb8, 0x08, 0xbf, 0xff,
		0xe9, 0x51, 0xe8, 0x9a, 0xfe, 0x22, 0x8e, 0x43,
		0x27, 0xeb, 0x46, 0x55, 0x62, 0xe7, 0x50, 0x28,
		0xcd, 0xed, 0x13, 0x1c, 0x6d, 0x33, 0xc1, 0xc7,
	};

	crypto_hash_alloc_ctx(&ctx1, TEE_ALG_SHA384);

	crypto_hash_init(ctx1);

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;

	}
	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx1, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, result, sizeof(result))) {
		EMSG("%s %d", __func__, __LINE__);
		DHEXDUMP(out, sizeof(out));
		return TEE_ERROR_GENERIC;
	}

	crypto_hash_free_ctx(ctx1);

	return test_sha3();
}

static TEE_Result test_sha3_4(void)
{
	TEE_Result res = TEE_SUCCESS;
	void *ctx1;
	void *ctx2;
	uint8_t result[] = {
		0xe4, 0x11, 0x98, 0x30, 0x6d, 0xad, 0xed, 0x1a,
		0x4a, 0x5f, 0x61, 0xe1, 0x76, 0x1e, 0xac, 0x09,
		0x4a, 0x88, 0xb1, 0xad, 0xb8, 0x08, 0xbf, 0xff,
		0xe9, 0x51, 0xe8, 0x9a, 0xfe, 0x22, 0x8e, 0x43,
		0x27, 0xeb, 0x46, 0x55, 0x62, 0xe7, 0x50, 0x28,
		0xcd, 0xed, 0x13, 0x1c, 0x6d, 0x33, 0xc1, 0xc7,
	};

	crypto_hash_alloc_ctx(&ctx1, TEE_ALG_SHA384);
	crypto_hash_alloc_ctx(&ctx2, TEE_ALG_SHA384);

	crypto_hash_init(ctx1);

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;

	}
	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	res = crypto_hash_update(ctx1, data, SHA3_INPUT_DATA_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	crypto_hash_copy_state(ctx2, ctx1);
	crypto_hash_free_ctx(ctx1);

	memset(out, 0, sizeof(out));
	res = crypto_hash_final(ctx2, out, SHA3_HASH_LEN);
	if (res != TEE_SUCCESS) {
		EMSG("%s %d", __func__, __LINE__);
		return res;
	}

	if (memcmp(out, result, sizeof(result))) {
		EMSG("%s %d", __func__, __LINE__);
		DHEXDUMP(out, sizeof(out));
		return TEE_ERROR_GENERIC;
	}

	crypto_hash_free_ctx(ctx2);

	return test_sha3();

}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_sha3,    .name = STR(hash sha384), },
	{ .f = test_sha3_0, .name = STR(hash 0) , },
	{ .f = test_sha3_1, .name = STR(hash 1), },
	{ .f = test_sha3_2, .name = STR(hash 2), },
	{ .f = test_sha3_3, .name = STR(hash 3), },
	{ .f = test_sha3_4, .name = STR(hash 4), },
};

static TEE_Result versal_sha3_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(test); i++) {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = true;
	}

	IMSG("Versal: Test HASH");
	for (i = 0; i < ARRAY_SIZE(test); i++) {
		IMSG("---- %s:\t\t\t\t\t [%s]",
		     test[i].name,
		     test[i].failed ? "KO" : "OK");
	}

	return TEE_SUCCESS;;
}

boot_final(versal_sha3_test);
