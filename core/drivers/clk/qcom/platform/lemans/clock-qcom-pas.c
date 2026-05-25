// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clock_group_qcom.h"

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);

static TEE_Result cdsp0_enable(void)
{
	struct io_pa_va turing_cc_io = {
		.pa = TURING_0_BASE + TURINGNSP_0_CC_OFFSET
	};
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io, 0x50000);
	uint64_t timeout = timeout_init_us(10000);
	TEE_Result res = TEE_SUCCESS;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_0_Q6SS_AHBS_AON);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_0_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;

	io_clrbits32(cc_base + TURINGNSP_0_Q6SS_ALT_RESET_CTL,
		     CBCR_BRANCH_ENABLE_BIT);
	io_clrbits32(cc_base + TURINGNSP_0_Q6SS_AHBS_AON,
		     CBCR_BRANCH_ENABLE_BIT);
	io_setbits32(cc_base + TURINGNSP_0_NSPNOC,
		     CBCR_BRANCH_ENABLE_BIT);

	io_clrbits32(cc_base + TURINGNSP_0_VAPSS_GDSCR, 0x1);

	while (!timeout_elapsed(timeout)) {
		if (io_read32(cc_base + TURINGNSP_0_VAPSS_GDSCR) & 0x80000000)
			goto out;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
out:
	io_setbits32(cc_base + TURINGNSP_0_VAPSS_GDSCR, 0x801);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
#if 0
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
#endif
	TEE_Result res = 0;

	switch (group) {
	case QCOM_CLKS_TURING:
#if 0
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_0_CFG_AHB_CLK);
		if (res)
			goto timeout;
#endif
		res = cdsp0_enable();
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
timeout:
	EMSG("Timeout trying to enable clock group %d\n", group);
	return TEE_ERROR_TIMEOUT;
}
