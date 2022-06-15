// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * The proper way to run this test would be to write the eFuses using some
 * Xilinx tool and then just memcmp the read results.
 *
 * For writing would be the inverse test.
 *
 * Foundries has validated this manually and through visual inspection of the
 * output.
 *
 */

#include <arm.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_puf.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#define __STR(X) #X
#define STR(X) __STR(X)

static TEE_Result test_puf_check_api(void)
{
	enum versal_puf_api api[] = {
		PUF_REGISTRATION,
		PUF_REGENERATION,
		PUF_CLEAR_PUF_ID,
	};
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(api); i++) {
		ret = versal_puf_check_api(api[i]);
		if (ret)
			return ret;
	}

	return TEE_SUCCESS;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_puf_check_api,       .name = STR(api    ),},
	{ .f = NULL,                     .name = STR(foo), },
};

static TEE_Result versal_puf_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	do {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = true;
		i++;

	} while (test[i].f);

	IMSG("Versal: Test PUF");

	for (i = 0; i < ARRAY_SIZE(test) - 1; i++)
		IMSG("---- %s:\t\t\t\t\t [%s]",
		     test[i].name, test[i].failed ? "KO" : "OK");

	return TEE_SUCCESS;;
}
driver_init(versal_puf_test);

