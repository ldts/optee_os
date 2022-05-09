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

	return TEE_SUCCESS;
}


static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_sha3, .name = STR(hash sha384), },
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
