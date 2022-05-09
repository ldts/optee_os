/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_ZYNQ_GPIO_H
#define __DRIVERS_ZYNQ_GPIO_H

#include <gpio.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <util.h>

#define ZYNQMP_GPIO_MAX_BANK	6

struct zynq_platform_data {
	const char *label;
	uint16_t ngpio;
	uint32_t max_bank;
	uint32_t bank_min[ZYNQMP_GPIO_MAX_BANK];
	uint32_t bank_max[ZYNQMP_GPIO_MAX_BANK];
};

struct zynq_gpio_platdata {
	paddr_t base;
	const struct zynq_platform_data *p_data;
};

struct zynq_gpio_chip {
	struct gpio_chip chip;
	struct zynq_gpio_platdata plat;
	vaddr_t base;
};

TEE_Result zynq_gpio_pmc_init(struct zynq_gpio_chip *chip);
TEE_Result zynq_gpio_init(struct zynq_gpio_chip *chip);

#endif /* __DRIVERS_ZYNQ_GPIO_H */
