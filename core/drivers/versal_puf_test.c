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

#define XPUF_REGISTRATION		(0x0U)
#define XPUF_REGEN_ID_ONLY		(0x2U)
#define XPUF_SHUTTER_VALUE		(0x81000100U)
#define XPUF_SYNDROME_MODE_4K		(0x0U)
#define XPUF_GLBL_VAR_FLTR_OPTION	(1)
#define XPUF_READ_FROM_RAM              (0)

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

static TEE_Result test_puf_register(void)
{
	struct versal_puf_data buf = { };
	struct versal_puf_cfg cfg = { };

	cfg.global_var_filter = XPUF_GLBL_VAR_FLTR_OPTION;
	cfg.shutter_value = XPUF_SHUTTER_VALUE;
	cfg.puf_operation = XPUF_REGISTRATION;
	cfg.reg_mode = XPUF_SYNDROME_MODE_4K;

	if (versal_puf_register(&buf, &cfg))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_puf_regenerate(void)
{
	struct versal_puf_data buf = { };
	struct versal_puf_cfg cfg = { };

	cfg.global_var_filter = XPUF_GLBL_VAR_FLTR_OPTION;
	cfg.shutter_value = XPUF_SHUTTER_VALUE;
	cfg.puf_operation = XPUF_REGEN_ID_ONLY;
	cfg.read_option = XPUF_READ_FROM_RAM;
	cfg.reg_mode = XPUF_SYNDROME_MODE_4K;

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

