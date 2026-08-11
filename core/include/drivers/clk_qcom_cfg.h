/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Data contract for a platform's clock domains, consumed by the generic clock
 * provider in clk-qcom.c.
 */

#ifndef _CLK_QCOM_CFG_H_
#define _CLK_QCOM_CFG_H_

#include <mm/core_memprot.h>
#include <stdint.h>
#include <types_ext.h>

/*
 * One frequency configuration row for an RCG.
 *
 * @div2x    Twice the half-integer source divider; SRC_DIV is encoded as
 *           (div2x - 1). 0 means no divide.
 * @m, @n    MND fractional divider; used only when (m != 0 && m < n).
 * @dfs_idx  DFS performance-state index, or QCOM_DFS_NA.
 * @cx_level Raw rail_voltage_level this rate requires (e.g. MIN_SVS 0x30),
 *           voted around the mux program. 0 means no vote.
 */
struct qcom_clk_mux_config {
	uint32_t freq_hz;
	uint32_t mux_sel;
	uint16_t div2x;
	uint32_t m;
	uint32_t n;
	uint8_t  dfs_idx;
	uint16_t cx_level;
};

#define QCOM_DFS_NA		0xFF

/*
 * One register block a domain's registers live in, e.g. one GCC instance. A
 * target may split domains across per-quadrant controllers alongside the
 * central GCC, so each domain names its own block rather than assuming one
 * global base.
 *
 * @io.va is filled in and cached by io_pa_or_va() on first resolve. @size also
 * bounds-checks each domain's offsets.
 */
struct qcom_clk_regmap {
	struct io_pa_va io;
	size_t size;
};

/*
 * A clock domain: a gated branch, optionally with an RCG and frequency plan.
 *
 * Register locations are full physical addresses matching the HWIO_<reg>_ADDR
 * values in the reference driver's header, so a row can be read against the
 * hardware documentation without resolving which base it is relative to.
 *
 * @cmd_rcgr_addr  CFG/M/N/D and the DFS banks sit at fixed offsets from it.
 *                 0 marks a branch-only domain: enable/disable only, set_rate
 *                 and DFS are rejected.
 * @cbcr_addr      Never derived -- its distance from @cmd_rcgr_addr varies by
 *                 target and even by wrapper. CLK_OFF is always polled here.
 * @vote_reg_addr  Shared vote register this branch enable is gated through.
 *                 Nonzero on every supported target.
 * @vote_bit       Bit position within @vote_reg_addr; per-target, so supplied
 *                 rather than derived.
 * @dfs_states     DFS performance states the RCG supports; 0 means no DFS.
 * @n_configs      Rows in @configs; the array is not sentinel-terminated.
 */
struct qcom_clk_domain {
	const char *name;
	struct qcom_clk_regmap *regmap;
	paddr_t cmd_rcgr_addr;
	paddr_t cbcr_addr;
	paddr_t vote_reg_addr;
	uint8_t vote_bit;
	uint16_t dfs_states;
	const struct qcom_clk_mux_config *configs;
	uint32_t n_configs;
};

/*
 * Vote entry for one RCG source (upstream PLL). RCGs here have no parent clk,
 * so before switching onto a PLL source the walker places a branch vote to hold
 * the already-configured PLL on. Direct register write, not RPMh.
 *
 * A source needing no vote (e.g. XO) has no entry and voting is skipped.
 *
 * @regmap  Part of the lookup key: each controller has its own GPLL0 and its
 *          own PLL vote register.
 */
struct qcom_clk_src_vote {
	struct qcom_clk_regmap *regmap;
	uint32_t mux_sel;
	paddr_t vote_reg_addr;
	uint8_t vote_bit;
};

/*
 * Per-target config, provided by the target's translation unit. @src_votes may
 * be NULL/0 on a target needing no source voting.
 */
struct qcom_clk_cfg {
	const struct qcom_clk_domain *domains;
	uint32_t n_domains;
	const struct qcom_clk_src_vote *src_votes;
	uint32_t n_src_votes;
};

const struct qcom_clk_cfg *qcom_clk_cfg_get(void);

#endif /* _CLK_QCOM_CFG_H_ */
