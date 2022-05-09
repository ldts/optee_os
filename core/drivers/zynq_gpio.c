// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015 DAVE Embedded Systems <devel@dave.eu>
 * Most of code taken from linux kernel driver (linux/drivers/gpio/gpio-zynq.c)
 *
 * OP-TEE integration: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */
#include <arm.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

#include "drivers/zynq_gpio.h"

#define ZYNQ_GPIO_LEN  0x10000

#define ZYNQ_GPIO_MAX_BANK	4

#define ZYNQ_GPIO_BANK0_NGPIO	32
#define ZYNQ_GPIO_BANK1_NGPIO	22
#define ZYNQ_GPIO_BANK2_NGPIO	32
#define ZYNQ_GPIO_BANK3_NGPIO	32

#define ZYNQ_GPIO_NR_GPIOS	(ZYNQ_GPIO_BANK0_NGPIO + \
				 ZYNQ_GPIO_BANK1_NGPIO + \
				 ZYNQ_GPIO_BANK2_NGPIO + \
				 ZYNQ_GPIO_BANK3_NGPIO)

#define ZYNQMP_GPIO_MAX_BANK	6

#define ZYNQMP_GPIO_BANK0_NGPIO	26
#define ZYNQMP_GPIO_BANK1_NGPIO	26
#define ZYNQMP_GPIO_BANK2_NGPIO	26
#define ZYNQMP_GPIO_BANK3_NGPIO	32
#define ZYNQMP_GPIO_BANK4_NGPIO	32
#define ZYNQMP_GPIO_BANK5_NGPIO	32

#define ZYNQMP_GPIO_NR_GPIOS	174

#define ZYNQ_GPIO_BANK0_PIN_MIN(str)	0
#define ZYNQ_GPIO_BANK0_PIN_MAX(str)	(ZYNQ_GPIO_BANK0_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK0_NGPIO - 1)
#define ZYNQ_GPIO_BANK1_PIN_MIN(str)	(ZYNQ_GPIO_BANK0_PIN_MAX(str) + 1)
#define ZYNQ_GPIO_BANK1_PIN_MAX(str)	(ZYNQ_GPIO_BANK1_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK1_NGPIO - 1)
#define ZYNQ_GPIO_BANK2_PIN_MIN(str)	(ZYNQ_GPIO_BANK1_PIN_MAX(str) + 1)
#define ZYNQ_GPIO_BANK2_PIN_MAX(str)	(ZYNQ_GPIO_BANK2_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK2_NGPIO - 1)
#define ZYNQ_GPIO_BANK3_PIN_MIN(str)	(ZYNQ_GPIO_BANK2_PIN_MAX(str) + 1)
#define ZYNQ_GPIO_BANK3_PIN_MAX(str)	(ZYNQ_GPIO_BANK3_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK3_NGPIO - 1)
#define ZYNQ_GPIO_BANK4_PIN_MIN(str)	(ZYNQ_GPIO_BANK3_PIN_MAX(str) + 1)
#define ZYNQ_GPIO_BANK4_PIN_MAX(str)	(ZYNQ_GPIO_BANK4_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK4_NGPIO - 1)
#define ZYNQ_GPIO_BANK5_PIN_MIN(str)	(ZYNQ_GPIO_BANK4_PIN_MAX(str) + 1)
#define ZYNQ_GPIO_BANK5_PIN_MAX(str)	(ZYNQ_GPIO_BANK5_PIN_MIN(str) + \
					ZYNQ##str##_GPIO_BANK5_NGPIO - 1)


#define ZYNQ_GPIO_DATA_LSW_OFFSET(BANK)	(0x000 + (8 * BANK))
#define ZYNQ_GPIO_DATA_MSW_OFFSET(BANK)	(0x004 + (8 * BANK))
#define ZYNQ_GPIO_DATA_RO_OFFSET(BANK)	(0x060 + (4 * BANK))
#define ZYNQ_GPIO_DIRM_OFFSET(BANK)	(0x204 + (0x40 * BANK))
#define ZYNQ_GPIO_OUTEN_OFFSET(BANK)	(0x208 + (0x40 * BANK))
#define ZYNQ_GPIO_INTMASK_OFFSET(BANK)	(0x20C + (0x40 * BANK))
#define ZYNQ_GPIO_INTEN_OFFSET(BANK)	(0x210 + (0x40 * BANK))
#define ZYNQ_GPIO_INTDIS_OFFSET(BANK)	(0x214 + (0x40 * BANK))
#define ZYNQ_GPIO_INTSTS_OFFSET(BANK)	(0x218 + (0x40 * BANK))
#define ZYNQ_GPIO_INTTYPE_OFFSET(BANK)	(0x21C + (0x40 * BANK))
#define ZYNQ_GPIO_INTPOL_OFFSET(BANK)	(0x220 + (0x40 * BANK))
#define ZYNQ_GPIO_INTANY_OFFSET(BANK)	(0x224 + (0x40 * BANK))

/* Disable all interrupts mask */
#define ZYNQ_GPIO_IXR_DISABLE_ALL	0xFFFFFFFF

/* Mid pin number of a bank */
#define ZYNQ_GPIO_MID_PIN_NUM 16

/* GPIO upper 16 bit mask */
#define ZYNQ_GPIO_UPPER_MASK 0xFFFF0000

static inline void zynq_gpio_get_bank_pin(unsigned int pin_num,
					  unsigned int *bank_num,
					  unsigned int *bank_pin_num,
					  struct zynq_gpio_chip *chip)
{
	struct zynq_gpio_platdata *platdata = &chip->plat;
	uint32_t bank = 0;

	for (bank = 0; bank < platdata->p_data->max_bank; bank++) {
		if (pin_num >= platdata->p_data->bank_min[bank] &&
			pin_num <= platdata->p_data->bank_max[bank]) {
			*bank_num = bank;
			*bank_pin_num = pin_num -
					platdata->p_data->bank_min[bank];
			return;
		}
	}

	if (bank >= platdata->p_data->max_bank) {
		EMSG("Invalid bank and pin num");
		*bank_pin_num = 0;
		*bank_num = 0;
	}
}

static int gpio_is_valid(unsigned gpio, struct zynq_gpio_chip *chip)
{
	struct zynq_gpio_platdata *platdata = &chip->plat;
	return gpio < platdata->p_data->ngpio;
}

static void check_gpio(unsigned gpio, struct zynq_gpio_chip *chip)
{
	if (!gpio_is_valid(gpio, chip))
		panic();
}

static enum gpio_level gpio_get_value(struct zynq_gpio_chip *chip,
				      unsigned int gpio)
{
	uint32_t data = 0;
	unsigned int bank_num = 0;
	unsigned int bank_pin_num = 0;

	check_gpio(gpio, chip);
	zynq_gpio_get_bank_pin(gpio, &bank_num, &bank_pin_num, chip);
	data = io_read32(chip->base + ZYNQ_GPIO_DATA_RO_OFFSET(bank_num));

	return (data >> bank_pin_num) & 1;
}

static void gpio_set_value(struct zynq_gpio_chip *chip, unsigned int gpio,
			   enum gpio_level val)
{
	unsigned int bank_num = 0;
	unsigned int reg_offset = 0;
	unsigned int bank_pin_num = 0;

	check_gpio(gpio, chip);
	zynq_gpio_get_bank_pin(gpio, &bank_num,& bank_pin_num, chip);

	if (bank_pin_num >= ZYNQ_GPIO_MID_PIN_NUM) {
		/* only 16 data bits in bit maskable reg */
		bank_pin_num -= ZYNQ_GPIO_MID_PIN_NUM;
		reg_offset = ZYNQ_GPIO_DATA_MSW_OFFSET(bank_num);
	} else {
		reg_offset = ZYNQ_GPIO_DATA_LSW_OFFSET(bank_num);
	}

	/*
	 * get the 32 bit value to be written to the mask/data register where
	 * the upper 16 bits is the mask and lower 16 bits is the data
	 */
	val = !!val;
	val = ~(1 <<(bank_pin_num + ZYNQ_GPIO_MID_PIN_NUM)) &
		((val << bank_pin_num)| ZYNQ_GPIO_UPPER_MASK);

	io_write32(chip->base + reg_offset, val);
}

static void gpio_set_direction(struct zynq_gpio_chip *chip,
			       unsigned int gpio,
			       enum gpio_dir direction)
{
	uint32_t reg = 0;
	unsigned int bank_num = 0;
	unsigned int bank_pin_num = 0;

	check_gpio(gpio, chip);

	if (direction == GPIO_DIR_OUT) {
		zynq_gpio_get_bank_pin(gpio, &bank_num, &bank_pin_num, chip);

		/* set the GPIO pin as output */
		reg = io_read32(chip->base + ZYNQ_GPIO_DIRM_OFFSET(bank_num));
		reg |= BIT(bank_pin_num);
		io_write32(chip->base + ZYNQ_GPIO_DIRM_OFFSET(bank_num), reg);

		/* configure the output enable reg for the pin */
		reg = io_read32(chip->base + ZYNQ_GPIO_OUTEN_OFFSET(bank_num));

		reg |= BIT(bank_pin_num);
		io_write32(chip->base + ZYNQ_GPIO_OUTEN_OFFSET(bank_num), reg);

		/* set the state of the pin */
		gpio_set_value(chip, gpio, GPIO_LEVEL_LOW);
	} else {
		zynq_gpio_get_bank_pin(gpio, &bank_num, &bank_pin_num, chip);

		/* bank 0 pins 7 and 8 are special and cannot be used as inputs */
		if (bank_num == 0 && (bank_pin_num == 7 || bank_pin_num == 8))
			panic();

		/* clear the bit in direction mode reg to set the pin as input */
		reg = io_read32(chip->base + ZYNQ_GPIO_DIRM_OFFSET(bank_num));
		reg &= ~BIT(bank_pin_num);
		io_write32(chip->base + ZYNQ_GPIO_DIRM_OFFSET(bank_num), reg);
	}
}

static enum gpio_dir gpio_get_direction(struct zynq_gpio_chip *chip,
					unsigned int gpio)
{
	uint32_t reg = 0;
	unsigned int bank_num = 0;
	unsigned int bank_pin_num = 0;

	check_gpio(gpio, chip);
	zynq_gpio_get_bank_pin(gpio, &bank_num, &bank_pin_num, chip);

	reg = io_read32(chip->base + ZYNQ_GPIO_DIRM_OFFSET(bank_num));
	reg &= BIT(bank_pin_num);
	if (reg)
		return GPIO_DIR_OUT;
	else
		return GPIO_DIR_IN;
}

static enum gpio_level do_get_value(struct gpio_chip *chip, unsigned int gpio)
{
	struct zynq_gpio_chip *p = container_of(chip,
						struct zynq_gpio_chip, chip);
	return gpio_get_value(p, gpio);
}

static void do_set_value(struct gpio_chip *chip, unsigned int gpio,
			 enum gpio_level val)
{
	struct zynq_gpio_chip *p = container_of(chip,
						struct zynq_gpio_chip, chip);
	return gpio_set_value(p, gpio, val);
}

static void do_set_dir(struct gpio_chip *chip, unsigned int gpio,
		       enum gpio_dir direction)
{
	struct zynq_gpio_chip *p = container_of(chip,
						struct zynq_gpio_chip, chip);
	return gpio_set_direction(p, gpio, direction);
}

static enum gpio_dir do_get_dir(struct gpio_chip *chip, unsigned int gpio)
{
	struct zynq_gpio_chip *p = container_of(chip,
						struct zynq_gpio_chip, chip);
	return gpio_get_direction(p, gpio);
}

static const struct gpio_ops zynq_gpio_ops = {
	.get_direction = do_get_dir,
	.set_direction = do_set_dir,
	.get_value = do_get_value,
	.set_value = do_set_value,
	.get_interrupt = NULL,
	.set_interrupt = NULL,
};

#define PMC_GPIO_NR_GPIOS	116
#define PMC_GPIO_MAX_BANK	5
#define PMC_GPIO_BASE           0xf1020000

static const struct zynq_platform_data pmc_gpio_def = {
	.label = "pmc_gpio",
	.ngpio = PMC_GPIO_NR_GPIOS,
	.max_bank = PMC_GPIO_MAX_BANK,
	.bank_min[0] = 0,
	.bank_max[0] = 25,
	.bank_min[1] = 26,
	.bank_max[1] = 51,
	.bank_min[3] = 52,
	.bank_max[3] = 83,
	.bank_min[4] = 84,
	.bank_max[4] = 115,
};

#define VERSAL_GPIO_NR_GPIOS	58
#define VERSAL_GPIO_MAX_BANK	4
#define VERSAL_GPIO_BASE        0xff0b0000

static const struct zynq_platform_data versal_gpio_def = {
	.label = "versal_gpio",
	.ngpio = VERSAL_GPIO_NR_GPIOS,
	.max_bank = VERSAL_GPIO_MAX_BANK,
	.bank_min[0] = 0,
	.bank_max[0] = 25,
	.bank_min[3] = 26,
	.bank_max[3] = 57,
};

TEE_Result zynq_gpio_pmc_init(struct zynq_gpio_chip *chip)
{
	if (chip->base)
		return TEE_SUCCESS;

	chip->chip.ops = &zynq_gpio_ops;
	chip->plat.p_data = &pmc_gpio_def;
	chip->plat.base = PMC_GPIO_BASE;

	chip->base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						   PMC_GPIO_BASE,
						   ZYNQ_GPIO_LEN);
	if (!chip->base) {
		EMSG("Failed to map gpio");
		chip->chip.ops = NULL;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result zynq_gpio_init(struct zynq_gpio_chip *chip)
{
	if (chip->base)
		return TEE_SUCCESS;

	chip->chip.ops = &zynq_gpio_ops;
	chip->plat.p_data = &versal_gpio_def;
	chip->plat.base = VERSAL_GPIO_BASE;

	chip->base = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						  VERSAL_GPIO_BASE,
						  ZYNQ_GPIO_LEN);
	if (!chip->base) {
		EMSG("Failed to map gpio");
		chip->chip.ops = NULL;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
