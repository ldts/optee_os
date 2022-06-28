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
#include <drivers/versal_gpio.h>
#include <gpio.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#define __STR(X) #X
#define STR(X) __STR(X)

static TEE_Result test_gpio_poll_out(void)
{
	struct versal_gpio_chip gpio = { };
	unsigned int pin = 37;

	if (versal_gpio_pmc_init(&gpio))
		return TEE_ERROR_GENERIC;

	gpio.chip.ops->set_direction(&gpio.chip, pin, GPIO_DIR_OUT);

	gpio.chip.ops->set_value(&gpio.chip, pin, GPIO_LEVEL_LOW);
	if (gpio.chip.ops->get_value(&gpio.chip, pin) != GPIO_LEVEL_LOW)
		return TEE_ERROR_GENERIC;

	gpio.chip.ops->set_value(&gpio.chip, pin, GPIO_LEVEL_HIGH);
	if (gpio.chip.ops->get_value(&gpio.chip, pin) != GPIO_LEVEL_HIGH)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_gpio_poll_inp(void)
{
	struct versal_gpio_chip gpio = { };
	unsigned int pin = 37;

	if (versal_gpio_ps_init(&gpio))
		return TEE_ERROR_GENERIC;

	gpio.chip.ops->set_direction(&gpio.chip, pin, GPIO_DIR_IN);
	gpio.chip.ops->get_value(&gpio.chip, pin);

	return TEE_SUCCESS;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_gpio_poll_out,   .name = STR(poll out),},
	{ .f = test_gpio_poll_inp,   .name = STR(poll inp), },
	{ .f = NULL,                 .name = STR(foo ), },
};

static TEE_Result versal_gpio_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	do {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = true;
		i++;

	} while (test[i].f);

	IMSG("Versal: Test GPIO");
	for (i = 0; i < ARRAY_SIZE(test) - 1; i++)
		IMSG("---- %s:\t\t\t\t\t [%s]",
		     test[i].name, test[i].failed ? "KO" : "OK");

	return TEE_SUCCESS;;
}
driver_init(versal_gpio_test);

