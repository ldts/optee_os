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

static TEE_Result cdsp_enable(paddr_t turing_base)
{
	struct io_pa_va turing_cc_io = {
		.pa = turing_base + TURINGNSP_CC_OFFSET
	};
	vaddr_t cc_base = io_pa_or_va(&turing_cc_io, 0x50000);
	uint64_t timeout = timeout_init_us(10000);
	TEE_Result res = TEE_SUCCESS;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_AHBS_AON);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_enable_cbc(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON);
	if (res != TEE_SUCCESS)
		return res;

	io_clrbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_CTL,
		     CBCR_BRANCH_ENABLE_BIT);
	io_clrbits32(cc_base + TURINGNSP_Q6SS_ALT_RESET_AON,
		     CBCR_BRANCH_ENABLE_BIT);

	io_setbits32(cc_base + TURINGNSP_NSPNOC,
		     CBCR_BRANCH_ENABLE_BIT);

	/* Retention flop */
	io_clrbits32(cc_base + TURINGNSP_VAPSS_GDSCR, 0x1);
	while (!timeout_elapsed(timeout)) {
		if (io_read32(cc_base + TURINGNSP_VAPSS_GDSCR) & 0x80000000)
			goto out;

		udelay(10);
	}

	return TEE_ERROR_TIMEOUT;
out:
	io_setbits32(cc_base + TURINGNSP_VAPSS_GDSCR, 0x801);

	return TEE_SUCCESS;
}

static const struct qcom_lucidevo_pll_config q6_pll_cfg = {
	.l_val = TURINGNSP_Q6_PLL_L_VAL,
	.cal_l_val = TURINGNSP_Q6_PLL_CAL_L_VAL,
	.pre_div = 1,
	.config_ctl = TURINGNSP_Q6_PLL_CONFIG_CTL,
	.config_ctl_u = TURINGNSP_Q6_PLL_CONFIG_CTL_U,
	.config_ctl_u1 = TURINGNSP_Q6_PLL_CONFIG_CTL_U1,
	.user_ctl = TURINGNSP_Q6_PLL_USER_CTL,
	.user_ctl_u = TURINGNSP_Q6_PLL_USER_CTL_U,
	/* alpha (default) fractional mode */
};

/*
 * Bring the QDSP6 out of reset once the boot FSM has completed: configure and
 * lock the Q6 PLL, switch the core RCG onto it, then release the core. This
 * mirrors the CLOCK_PROCESSOR_TURING case of Clock_EnableProcessorEx in the
 * reference ClockPIL driver. The Q6 PLL register space must not be accessed
 * until the boot FSM is done, so this runs after cdspN_fw_start().
 */
static TEE_Result cdsp_enable_processor(paddr_t turing_base)
{
	struct io_pa_va proc_io = {
		.pa = turing_base + TURINGNSP_BOOT_OFFSET
	};
	vaddr_t boot_base = io_pa_or_va(&proc_io, TURINGNSP_PROC_WINDOW_SIZE);
	vaddr_t pll_base = boot_base - TURINGNSP_BOOT_OFFSET +
			   TURINGNSP_Q6_PLL_OFFSET;
	vaddr_t core_cc = boot_base - TURINGNSP_BOOT_OFFSET +
			  TURINGNSP_CORE_CC_OFFSET;
	TEE_Result res = TEE_SUCCESS;

	res = qcom_clock_lucidevo_pll_enable(pll_base, &q6_pll_cfg);
	if (res != TEE_SUCCESS)
		return res;

	res = qcom_clock_set_rate(core_cc + QDSP6SS_CORE_CFG_RCGR,
				  core_cc + QDSP6SS_CORE_CMD_RCGR,
				  Q6RCG_CFG_VALUE);
	if (res != TEE_SUCCESS)
		return res;

	/* Release the core only after the PLL has been initialised. */
	io_setbits32(boot_base + QDSP6SS_BOOT_CORE_START, BIT(0));

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
		return cdsp_enable_processor(TURING_0_BASE);
	case QCOM_CLKS_TURING1:
		return cdsp_enable_processor(TURING_1_BASE);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	struct io_pa_va base = { .pa = GCC_BASE };
	vaddr_t gcc_base = io_pa_or_va(&base, GCC_SIZE);
	TEE_Result res = 0;

	switch (group) {
	case QCOM_CLKS_TURING:
		/* Turing bus clock branch connected to the NIU socket */
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_0_CFG_AHB_CLK);
		if (res)
			goto timeout;

		res = cdsp_enable(TURING_0_BASE);
		if (res != TEE_SUCCESS)
			goto timeout;
		break;
	case QCOM_CLKS_TURING1:
		/* Turing bus clock branch connected to the NIU socket */
		res = qcom_clock_enable_cbc(gcc_base +
					    GCC_TURING_1_CFG_AHB_CLK);
		if (res)
			goto timeout;

		res = cdsp_enable(TURING_1_BASE);
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
