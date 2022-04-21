// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_nvm.h"

#define __STR(X) #X
#define STR(X) __STR(X)

static TEE_Result test_read_ppk(void)
{
	uint32_t hash[8] = { 0xff };

	if (versal_read_efuse_ppk(hash, sizeof(hash), EFUSE_PPK1))
		return TEE_ERROR_GENERIC;

	DMSG("PPK1 hash:");
	DHEXDUMP((void *)hash, sizeof(hash));

	return TEE_SUCCESS;
}

static TEE_Result test_read_iv(void)
{
	uint32_t iv[3] = { 0xff };

	if (versal_read_efuse_iv(iv, sizeof(iv), EFUSE_PLM_IV_RANGE))
		return TEE_ERROR_GENERIC;

	DMSG("EFUSE_PLM_IV_RANGE eFuse:");
	DHEXDUMP((void *)iv, sizeof(iv));

	return TEE_SUCCESS;
}

static TEE_Result test_read_dna(void)
{
	uint32_t dna[4];

	if (versal_read_efuse_dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

	DMSG("DNA eFuse");
	DHEXDUMP((void *)dna, sizeof(dna));

	return TEE_SUCCESS;
}

static TEE_Result test_read_user_fuses(void)
{
	uint32_t fuses[64] = { 0xff };

	if (versal_read_efuse_user(fuses, sizeof(fuses), 2, 10))
		return TEE_ERROR_GENERIC;

	DMSG("User eFuse(s)");
	DHEXDUMP((void *)fuses, sizeof(fuses));

	return TEE_SUCCESS;
}

static TEE_Result test_write_user_fuses(void)
{
	/* the length of the source buffer must be cacheline aligned */
	uint32_t fuses[4] = { 0xab123456, 0xbc123456, 0xcd123456, 0xde123456 };

	if (versal_write_efuse_user(fuses, sizeof(fuses), 3 ,4))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_write_user_fuses, .name = STR(write_user_fuses),},
	{ .f = test_read_user_fuses, .name = STR(read_user_fuses),},
	{ .f = test_read_dna, .name = STR(read_dna_fuse),},
	{ .f = test_read_ppk, .name = STR(read_ppk_fuse),},
	{ .f = test_read_iv, .name = STR(read_iv_fuse),},
	{ .f = NULL, .name = "" },
};

static TEE_Result versal_nvm_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	do {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = true;
		i++;

	} while (test[i].f);

	for (i = 0; i < ARRAY_SIZE(test) - 1; i++)
		IMSG("TEST %s:\t\t [%s]",
		     test[i].name, test[i].failed ? "KO" : "OK");

	return TEE_SUCCESS;;
}
driver_init(versal_nvm_test);

