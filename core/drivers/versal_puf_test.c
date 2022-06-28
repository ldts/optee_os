// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
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

static struct versal_puf_data buf = { };
static struct versal_puf_cfg cfg  = { };

static TEE_Result test_puf_register(void)
{
	cfg.global_var_filter = XPUF_GLBL_VAR_FLTR_OPTION;
	cfg.shutter_value = XPUF_SHUTTER_VALUE;
	cfg.puf_operation = XPUF_REGISTRATION;
	cfg.reg_mode = XPUF_SYNDROME_MODE_4K;

	if (versal_puf_register(&buf, &cfg))
		return TEE_ERROR_GENERIC;
#if 0
	IMSG("Shutter Value : 0x%08x", cfg.shutter_value);
	IMSG("Syndrome data");
	for (size_t i = 0; i < XPUF_4K_PUF_SYN_LEN_IN_WORDS; i++) {
		IMSG("syndrome[%d] = 0x%x", i, buf.syndrome_data[i]);
		buf.syndrome_data[i] = buf.syndrome_data[i];
	}

	IMSG("CHASH         : 0x%08x", buf.chash);
	IMSG("AUX           : 0x%08x", buf.aux);
	IMSG("Unique ID     : 0x%x.0x%x.0x%x.0x%x.0x%x.0x%x.0x%x.0x%x",
	     buf.puf_id[0], buf.puf_id[1], buf.puf_id[2], buf.puf_id[3],
	     buf.puf_id[4], buf.puf_id[5], buf.puf_id[6], buf.puf_id[7]);
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_puf_regenerate(void)
{
	cfg.puf_operation = XPUF_REGEN_ON_DEMAND;
	cfg.read_option = XPUF_READ_FROM_RAM;

	if (versal_puf_regenerate(&buf, &cfg))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_puf_register,        .name = STR(register   )},
	{ .f = test_puf_regenerate,      .name = STR(regenerate )},
	{ .f = test_puf_check_api,       .name = STR(all api    )},
	{ .f = NULL,                     .name = STR(foo)},
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

