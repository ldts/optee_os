// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <mm/core_mmu.h>
#include <stdint.h>

#include "lpass.h"

#define QDSP6V67SS_PUB_REG	0x00400000
#define QDSP6SS_CORE_CBCR	(QDSP6V67SS_PUB_REG + 0x20)
#define QDSP6SS_XO_CBCR		(QDSP6V67SS_PUB_REG + 0x38)
#define QDSP6SS_SLEEP_CBCR	(QDSP6V67SS_PUB_REG + 0x3c)
#define CORE_START_REG		(QDSP6V67SS_PUB_REG + 0x400)
#define BOOT_CMD_REG		(QDSP6V67SS_PUB_REG + 0x404)
#define BOOT_STATUS_REG		(QDSP6V67SS_PUB_REG + 0x408)

#define QDSP6SS_RST_EVB		(QDSP6V67SS_PUB_REG + 0x10)
#define QDSP6SS_RST_EVB_SHFT	4
#define QDSP6SS_RST_EVB_BMSK	0xffffff0

#define MCC_REG			0x00950000
#define EFUSE_Q6SS_EVB_SEL	(MCC_REG + 0xb000)
#define EFUSE_Q6SS_EVB_SEL_SHFT	0
#define EFUSE_Q6SS_EVB_SEL_BMSK	0x1

#define BOOT_CORE_START			BIT(0)
#define BOOT_CMD_START			BIT(0)
#define BOOT_FSM_TIMEOUT		10000

TEE_Result lpass_start(struct qcom_lpass_data *data)
{
	vaddr_t base = io_pa_or_va(&data->base, data->size);
	uint64_t timer;
	uint32_t val;

	io_write32(base + QDSP6SS_XO_CBCR, 1);
	io_write32(base + QDSP6SS_SLEEP_CBCR, 1);
	io_write32(base + QDSP6SS_CORE_CBCR, 1);

	io_write32(base + QDSP6SS_RST_EVB, data->fw_base >> 4);
	io_write32(base + EFUSE_Q6SS_EVB_SEL, 0);

	/* Wait for addresses to be programmed before starting Q6 */
	dsb();

	io_write32(base + CORE_START_REG, BOOT_CORE_START);
	io_write32(base + BOOT_CMD_REG, BOOT_CMD_START);

	timer = timeout_init_us(BOOT_FSM_TIMEOUT);
	do {
		val = io_read32(base + BOOT_STATUS_REG);
		if (val & BIT(0))
			break;
		if (timeout_elapsed(timer))
			break;
		udelay(10);
	} while (1);

	if ((val & BIT(0)) == 0) {
		EMSG("Timed out waiting for DSP to boot :(");
		return TEE_ERROR_TIMEOUT;
	}

	return TEE_SUCCESS;
}

TEE_Result lpass_shutdown(struct qcom_lpass_data *data __unused)
{
	/* todo */
	return TEE_SUCCESS;
}
