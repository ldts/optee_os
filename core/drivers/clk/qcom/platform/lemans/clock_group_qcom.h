/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef _CLOCK_GROUP_QCOM_H_
#define _CLOCK_GROUP_QCOM_H_

#define GCC_SEC_CTRL_CFG_RCGR			0x39038
#define GCC_SEC_CTRL_CMD_RCGR			0x39034
#define QFPROM_CLOCK_DIVIDE			0x7

#define GCC_TURING_0_CFG_AHB_CLK		0x41028
#define GCC_TURING_1_CFG_AHB_CLK		0x12028

/*
 * Turing/NSP clock-controller register offsets. They are identical for both
 * NSP instances; only the subsystem base address differs (TURING_0_BASE vs
 * TURING_1_BASE).
 */
#define TURINGNSP_CC_OFFSET			0x02008000
#define TURINGNSP_Q6SS_ALT_RESET_AON		0x418
#define TURINGNSP_Q6SS_AHBS_AON			0x414
#define TURINGNSP_Q6SS_ALT_RESET_CTL		0x10034
#define TURINGNSP_NSPNOC			0x22c
#define TURINGNSP_VAPSS_GDSCR			0x80

/*
 * QDSP6 boot / PLL / core clock-controller blocks, relative to the subsystem
 * base. The "enable processor" sequence maps a single window starting at
 * TURINGNSP_BOOT_OFFSET (0x50000 covers all three blocks below).
 */
#define TURINGNSP_BOOT_OFFSET			0x02300000
#define TURINGNSP_PROC_WINDOW_SIZE		0x50000
#define TURINGNSP_Q6_PLL_OFFSET			0x02340000
#define TURINGNSP_CORE_CC_OFFSET		0x02348000

/* Offsets within the boot block (TURINGNSP_BOOT_OFFSET). */
#define QDSP6SS_BOOT_CORE_START			0x400

/* Offsets within the core clock-controller block (TURINGNSP_CORE_CC_OFFSET). */
#define QDSP6SS_CORE_CMD_RCGR			0x20
#define QDSP6SS_CORE_CFG_RCGR			0x24

/*
 * Q6 core RCG: source select = Q6 PLL, source divider = 1. CFG_RCGR holds
 * SRC_SEL at bits [10:8] and SRC_DIV at bits [4:0].
 */
#define Q6RCG_SRC_SEL				0x2
#define Q6RCG_SRC_SEL_SHIFT			8
#define Q6RCG_SRC_DIV				0x1
#define Q6RCG_CFG_VALUE				(((Q6RCG_SRC_SEL) << \
						  (Q6RCG_SRC_SEL_SHIFT)) | \
						 (Q6RCG_SRC_DIV))

/*
 * Q6 Lucid-EVO PLL settings (identical for both NSP instances), taken from the
 * reference clock driver HALclkPLLSettings.h (TURING_Q6_CC_x_TURING_Q6_CC_PLL).
 */
#define TURINGNSP_Q6_PLL_L_VAL			0x32
#define TURINGNSP_Q6_PLL_CAL_L_VAL		0x44
#define TURINGNSP_Q6_PLL_CONFIG_CTL		0x20485699
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U		0x00182261
#define TURINGNSP_Q6_PLL_CONFIG_CTL_U1		0x32AA299C
#define TURINGNSP_Q6_PLL_USER_CTL		0x00000000
#define TURINGNSP_Q6_PLL_USER_CTL_U		0x00400805

#endif /* _CLOCK_GROUP_QCOM_H_ */
