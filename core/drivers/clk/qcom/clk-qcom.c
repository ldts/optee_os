// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Ltd
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <io.h>
#include <mm/core_mmu.h>

register_phys_mem(MEM_AREA_IO_NSEC, GCC_BASE, GCC_SIZE);

#ifdef CFG_QCOM_CLK_CFG
#include <config.h>
#include <drivers/clk_qcom_cfg.h>
#include <initcall.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>

#include "clk_qcom_volt.h"
#include "clock_group_qcom.h"
#endif

#define CBCR_BRANCH_ENABLE_BIT		BIT(0)
#define CBCR_HW_CTL_ENABLE_BIT		BIT(1)
#define CBCR_BRANCH_OFF_BIT		BIT(31)

/* Lucid-EVO PLL register offsets, relative to the PLL register block base. */
#define PLL_MODE			0x0
#define PLL_OPMODE			0x4
#define PLL_L_VAL			0x10
#define PLL_ALPHA_VAL			0x14
#define PLL_USER_CTL			0x18
#define PLL_USER_CTL_U			0x1c
#define PLL_CONFIG_CTL			0x20
#define PLL_CONFIG_CTL_U		0x24
#define PLL_CONFIG_CTL_U1		0x28

/* PLL_MODE fields */
#define PLL_MODE_OUTCTRL		BIT(0)
#define PLL_MODE_RESET_N		BIT(2)
#define PLL_MODE_LOCK_DET		BIT(31)

/* PLL_OPMODE values */
#define PLL_OPMODE_RUN			0x1

/* PLL_L_VAL fields */
#define PLL_L_VAL_L_MASK		0x0000ffff
#define PLL_L_VAL_CAL_L_SHIFT		16
#define PLL_L_VAL_CAL_L_MASK		0xffff0000

/* PLL_USER_CTL fields */
#define PLL_USER_CTL_PLLOUT_MAIN_EN	BIT(0)
#define PLL_USER_CTL_PRE_DIV_SHIFT	22
#define PLL_USER_CTL_PRE_DIV_MASK	0x01c00000
#define PLL_USER_CTL_POST_DIV_ODD_MASK	0x0003c000
#define PLL_USER_CTL_POST_DIV_EVEN_MASK	0x00003c00
#define PLL_USER_CTL_FRAC_FORMAT_SEL	BIT(28)

/* PLL_USER_CTL_U fields */
#define PLL_USER_CTL_U_FINE_LOCK_DET	BIT(0)

static inline bool cbcr_branch_on(uint32_t val)
{
	return !(val & CBCR_BRANCH_OFF_BIT);
}

TEE_Result qcom_clock_enable_cbc(vaddr_t cbcr)
{
	int ret = 0;

	io_setbits32(cbcr, CBCR_BRANCH_ENABLE_BIT);

	/*
	 * In hardware clock-control mode (HW_CTL set) CLK_OFF is driven by HW,
	 * not the software CLK_ENABLE write, so skip the poll to avoid
	 * spinning.
	 */
	if (io_read32(cbcr) & CBCR_HW_CTL_ENABLE_BIT)
		return TEE_SUCCESS;

	REG_POLL_TIMEOUT(cbcr, 10 * 1000, 10, &ret, cbcr_branch_on);

	if (ret < 0)
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

static inline bool pll_locked(uint32_t val)
{
	return val & PLL_MODE_LOCK_DET;
}

TEE_Result qcom_lucidevo_pll_enable(vaddr_t pll_base,
				    const struct qcom_lucidevo_pll_config *cfg)
{
	uint32_t user_val = 0;
	int ret = 0;

	/* Reg settings: program the static PLL trim/config registers. */
	io_write32(pll_base + PLL_CONFIG_CTL, cfg->config_ctl);
	io_write32(pll_base + PLL_CONFIG_CTL_U, cfg->config_ctl_u);
	io_write32(pll_base + PLL_CONFIG_CTL_U1, cfg->config_ctl_u1);
	io_write32(pll_base + PLL_USER_CTL, cfg->user_ctl);
	io_write32(pll_base + PLL_USER_CTL_U, cfg->user_ctl_u);

	/* ConfigPLL: program L value and fractional value. */
	io_mask32(pll_base + PLL_L_VAL, cfg->l_val, PLL_L_VAL_L_MASK);
	io_write32(pll_base + PLL_ALPHA_VAL, cfg->alpha_val);

	/* Select fractional format and program the pre-/post-div ratios. */
	user_val = io_read32(pll_base + PLL_USER_CTL);
	if (cfg->frac_mode_mn)
		user_val |= PLL_USER_CTL_FRAC_FORMAT_SEL;
	else
		user_val &= ~PLL_USER_CTL_FRAC_FORMAT_SEL;

	user_val &= ~(PLL_USER_CTL_PRE_DIV_MASK |
		      PLL_USER_CTL_POST_DIV_ODD_MASK |
		      PLL_USER_CTL_POST_DIV_EVEN_MASK);
	if (cfg->pre_div >= 1 && cfg->pre_div <= 8)
		user_val |= SHIFT_U32(cfg->pre_div - 1,
				      PLL_USER_CTL_PRE_DIV_SHIFT) &
			    PLL_USER_CTL_PRE_DIV_MASK;
	io_write32(pll_base + PLL_USER_CTL, user_val);

	/* Always use fine-grained lock detection. */
	io_setbits32(pll_base + PLL_USER_CTL_U, PLL_USER_CTL_U_FINE_LOCK_DET);

	/* SetCalConfig: program the calibration L value. */
	io_mask32(pll_base + PLL_L_VAL,
		  SHIFT_U32(cfg->cal_l_val, PLL_L_VAL_CAL_L_SHIFT),
		  PLL_L_VAL_CAL_L_MASK);

	/* Enable: select RUN opmode and take the PLL out of reset. */
	io_write32(pll_base + PLL_OPMODE, PLL_OPMODE_RUN);
	io_setbits32(pll_base + PLL_MODE, PLL_MODE_RESET_N);

	/* Wait for the PLL to lock. */
	REG_POLL_TIMEOUT(pll_base + PLL_MODE, 10 * 1000, 10, &ret, pll_locked);
	if (ret < 0)
		return TEE_ERROR_TIMEOUT;

	/* Enable PLL outputs and the main output. */
	io_setbits32(pll_base + PLL_MODE, PLL_MODE_OUTCTRL);
	io_setbits32(pll_base + PLL_USER_CTL, PLL_USER_CTL_PLLOUT_MAIN_EN);

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_set_rate(vaddr_t cfg_rcgr, vaddr_t cmd_rcgr,
			       uint32_t cfg_value)
{
	uint32_t val = 0;

	io_write32(cfg_rcgr, cfg_value);
	io_write32(cmd_rcgr, CMD_RCGR_UPDATE_BIT);

	if (IO_READ32_POLL_TIMEOUT(cmd_rcgr, val, !(val & CMD_RCGR_UPDATE_BIT),
				   1, 10 * 1000))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_TURING:
	case QCOM_CLKS_TURING1:
	case QCOM_CLKS_LPASS:
	case QCOM_CLKS_WPSS:
	case QCOM_CLKS_GPDSP0:
	case QCOM_CLKS_GPDSP1:
		return qcom_clock_enable_pas(group);
	default:
		EMSG("Unsupported clock group %d\n", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

#ifdef CFG_QCOM_CLK_CFG
/*
 * Largest offset from CMD_RCGR the walker touches. Claiming the DFS extent on a
 * domain without DFS would falsely reject an RCG near the top of its regmap.
 */
static uint32_t qcom_rcg_span(uint16_t dfs_states)
{
	if (!dfs_states)
		return QCOM_RCG_D_REG_OFFSET;

	return QCOM_RCG_PERF_D_DFSR_REG_OFFSET + 0x4 * (dfs_states - 1);
}

/*
 * io_pa_or_va() validates the regmap base, not the per-register offset added on
 * top: an offset past @regmap->size would resolve outside the mapped block.
 */
static TEE_Result qcom_clk_regmap_va(struct qcom_clk_regmap *regmap,
				     paddr_t pa, size_t span, vaddr_t *va)
{
	if (pa < regmap->io.pa || pa - regmap->io.pa + span > regmap->size)
		return TEE_ERROR_BAD_PARAMETERS;

	*va = io_pa_or_va(&regmap->io, regmap->size) + (pa - regmap->io.pa);

	return TEE_SUCCESS;
}

static void qcom_config_mux_offs(vaddr_t cgr,
				 const struct qcom_clk_mux_config *cfg,
				 uint32_t cfg_off, uint32_t m_off,
				 uint32_t n_off, uint32_t d_off)
{
	uint32_t half_div = cfg->div2x ? cfg->div2x - 1 : 0;
	uint32_t val = io_read32(cgr + cfg_off);

	val &= ~(QCOM_RCG_CFG_SRC_SEL_FMSK | QCOM_RCG_CFG_SRC_DIV_FMSK |
		 QCOM_RCG_CFG_MODE_FMSK | QCOM_RCG_CFG_HW_CLK_CONTROL_FMSK);

	val |= SHIFT_U32(cfg->mux_sel, QCOM_RCG_CFG_SRC_SEL_SHFT) &
	       QCOM_RCG_CFG_SRC_SEL_FMSK;
	val |= SHIFT_U32(half_div, QCOM_RCG_CFG_SRC_DIV_SHFT) &
	       QCOM_RCG_CFG_SRC_DIV_FMSK;

	if (cfg->m != 0 && cfg->m < cfg->n) {
		io_write32(cgr + m_off, cfg->m);
		io_write32(cgr + n_off, ~(cfg->n - cfg->m));
		io_write32(cgr + d_off, ~cfg->n);

		val |= SHIFT_U32(QCOM_RCG_CFG_DUAL_EDGE_MODE_VAL,
				 QCOM_RCG_CFG_MODE_SHFT) &
		       QCOM_RCG_CFG_MODE_FMSK;
	}

	io_write32(cgr + cfg_off, val);
}

/* Lowest plan rate >= @freq_hz, or NULL if the plan's top rate is lower. */
static const struct qcom_clk_mux_config *
qcom_find_config(const struct qcom_clk_domain *domain, uint32_t freq_hz)
{
	const struct qcom_clk_mux_config *at_least = NULL;
	uint32_t at_least_hz = UINT32_MAX;
	uint32_t i = 0;

	for (i = 0; i < domain->n_configs; i++) {
		const struct qcom_clk_mux_config *c = &domain->configs[i];

		if (c->freq_hz == freq_hz)
			return c;

		if (c->freq_hz > freq_hz && c->freq_hz < at_least_hz) {
			at_least_hz = c->freq_hz;
			at_least = c;
		}
	}

	return at_least;
}

/*
 * Per-domain state behind a parentless struct clk. VAs are resolved once at
 * registration; cmd_rcgr_va stays 0 for a branch-only domain.
 */
struct qcom_clk_priv {
	const struct qcom_clk_domain *domain;
	struct clk *clk;
	vaddr_t cbcr_va;
	vaddr_t vote_va;
	vaddr_t cmd_rcgr_va;
	uint16_t corner;	/* corner voted for this domain */
	uint32_t rate;		/* last resolved output rate, 0 until set */
	bool dfs_on;		/* hardware DFS already handed the RCG */
};

static struct qcom_clk_priv *qcom_clk_privs;

/*
 * Entries fully resolved and registered; lookups bound on this rather than
 * cfg->n_domains because a driver_init failure is logged, not fatal.
 */
static uint32_t qcom_clk_priv_count;

/* Parallel to qcom_clk_cfg_get()->src_votes. */
static vaddr_t *qcom_src_vote_va;

/*
 * Hold the RCG's upcoming PLL source on before switching the mux onto it; the
 * PLL itself is already configured by an earlier boot image. XO needs no vote
 * and has no entry. The vote is left in place afterwards.
 */
static void qcom_clk_src_vote(struct qcom_clk_regmap *regmap, uint32_t mux_sel)
{
	const struct qcom_clk_cfg *cfg = qcom_clk_cfg_get();
	uint32_t i = 0;

	for (i = 0; i < cfg->n_src_votes; i++) {
		const struct qcom_clk_src_vote *sv = &cfg->src_votes[i];

		/* Each controller has its own GPLL0 at this mux index. */
		if (sv->mux_sel != mux_sel || sv->regmap != regmap)
			continue;

		io_setbits32(qcom_src_vote_va[i], BIT(sv->vote_bit));
		return;
	}
}

/*
 * Rail raised before speeding up and lowered after slowing down, so a rate is
 * never programmed under-volted.
 */
static TEE_Result qcom_domain_set_rate(struct qcom_clk_priv *priv,
				       uint32_t freq_hz, uint32_t *res_hz)
{
	const struct qcom_clk_domain *domain = priv->domain;
	const struct qcom_clk_mux_config *cfg = NULL;
	uint32_t val = 0;
	uint16_t prev = priv->corner;
	uint16_t next = prev;
	TEE_Result res = TEE_SUCCESS;

	if (!priv->cmd_rcgr_va)
		return TEE_ERROR_BAD_PARAMETERS;

	cfg = qcom_find_config(domain, freq_hz);
	if (!cfg)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* cx_level 0 means no vote, so this releases any corner still held. */
	next = cfg->cx_level;

	if (next > prev) {
		res = qcom_clk_volt_vote(prev, next);
		if (res)
			return res;
		priv->corner = next;
	}

	qcom_clk_src_vote(domain->regmap, cfg->mux_sel);

	qcom_config_mux_offs(priv->cmd_rcgr_va, cfg, QCOM_RCG_CFG_REG_OFFSET,
			     QCOM_RCG_M_REG_OFFSET, QCOM_RCG_N_REG_OFFSET,
			     QCOM_RCG_D_REG_OFFSET);

	io_setbits32(priv->cmd_rcgr_va, QCOM_RCG_CMD_CFG_UPDATE_FMSK);

	if (IO_READ32_POLL_TIMEOUT(priv->cmd_rcgr_va, val,
				   !(val & QCOM_RCG_CMD_CFG_UPDATE_FMSK),
				   1, 10 * 1000))
		return TEE_ERROR_TIMEOUT;

	/* Best-effort: a failed step down just leaves the rail safe-high. */
	if (next < prev && !qcom_clk_volt_vote(prev, next))
		priv->corner = next;

	if (res_hz)
		*res_hz = cfg->freq_hz;

	return TEE_SUCCESS;
}

static TEE_Result qcom_clock_domain_enable_dfs(struct qcom_clk_priv *priv)
{
	const struct qcom_clk_domain *domain = priv->domain;
	uint32_t i = 0;

	if (!domain->dfs_states || !priv->cmd_rcgr_va)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Rewriting the banks under a running DFS machine would corrupt it. */
	if (priv->dfs_on)
		return TEE_SUCCESS;

	for (i = 0; i < domain->n_configs; i++) {
		const struct qcom_clk_mux_config *c = &domain->configs[i];
		uint32_t perf = 0;

		if (c->dfs_idx == QCOM_DFS_NA ||
		    c->dfs_idx >= domain->dfs_states)
			continue;

		perf = 0x4 * c->dfs_idx;
		qcom_config_mux_offs(priv->cmd_rcgr_va, c,
				     QCOM_RCG_PERF_DFSR_REG_OFFSET + perf,
				     QCOM_RCG_PERF_M_DFSR_REG_OFFSET + perf,
				     QCOM_RCG_PERF_N_DFSR_REG_OFFSET + perf,
				     QCOM_RCG_PERF_D_DFSR_REG_OFFSET + perf);
	}

	io_write32(priv->cmd_rcgr_va + QCOM_RCG_CMD_DFSR_REG_OFFSET,
		   QCOM_RCG_CMD_DFSR_HW_CLK_CONTROL_FMSK |
		   QCOM_RCG_CMD_DFSR_DFS_EN_FMSK);

	priv->dfs_on = true;

	return TEE_SUCCESS;
}

static TEE_Result qcom_clk_priv_set_rate(struct clk *clk, unsigned long rate,
					 unsigned long parent_rate __unused)
{
	struct qcom_clk_priv *priv = clk->priv;
	uint32_t res_hz = 0;
	TEE_Result res = TEE_SUCCESS;

	/*
	 * Reject rather than truncate to uint32_t Hz: a wrapped rate would
	 * silently match some unrelated low plan row.
	 */
	if (rate > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_domain_set_rate(priv, rate, &res_hz);
	if (res)
		return res;

	priv->rate = res_hz;
	return TEE_SUCCESS;
}

/*
 * Last rate this driver programmed. After qcom_clk_enable_dfs() the hardware
 * picks the rate, so this is the last software vote, not the live rate.
 */
static unsigned long qcom_clk_priv_get_rate(struct clk *clk,
					    unsigned long parent_rate __unused)
{
	struct qcom_clk_priv *priv = clk->priv;

	return priv->rate;
}

static inline bool cbcr_branch_off(uint32_t val)
{
	return val & CBCR_BRANCH_OFF_BIT;
}

/*
 * Every domain gates through a shared vote register rather than its own CBCR
 * CLK_ENABLE bit. CLK_OFF is still polled on the CBCR, which has the only
 * status bit.
 *
 * The clk core serialises these ops under one mutex, so the read-modify-write
 * cannot race another TEE clk. It can still race Linux writing the same
 * NS-mapped word; only not sharing a vote register would fix that.
 */
static TEE_Result qcom_clk_priv_enable(struct clk *clk)
{
	struct qcom_clk_priv *priv = clk->priv;
	int ret = 0;

	io_setbits32(priv->vote_va, BIT(priv->domain->vote_bit));

	if (io_read32(priv->cbcr_va) & CBCR_HW_CTL_ENABLE_BIT)
		return TEE_SUCCESS;

	REG_POLL_TIMEOUT(priv->cbcr_va, 10 * 1000, 10, &ret, cbcr_branch_on);

	return ret < 0 ? TEE_ERROR_TIMEOUT : TEE_SUCCESS;
}

static void qcom_clk_priv_disable(struct clk *clk)
{
	struct qcom_clk_priv *priv = clk->priv;
	int ret = 0;

	io_clrbits32(priv->vote_va, BIT(priv->domain->vote_bit));

	/* HW_CTL drives the off-state; polling CLK_OFF would spin. */
	if (io_read32(priv->cbcr_va) & CBCR_HW_CTL_ENABLE_BIT)
		return;

	REG_POLL_TIMEOUT(priv->cbcr_va, 10 * 1000, 10, &ret, cbcr_branch_off);
}

static const struct clk_ops qcom_clk_priv_ops = {
	.enable = qcom_clk_priv_enable,
	.disable = qcom_clk_priv_disable,
	.set_rate = qcom_clk_priv_set_rate,
	.get_rate = qcom_clk_priv_get_rate,
};

static TEE_Result qcom_clk_priv_resolve(struct qcom_clk_priv *priv)
{
	const struct qcom_clk_domain *domain = priv->domain;
	TEE_Result res = TEE_SUCCESS;

	res = qcom_clk_regmap_va(domain->regmap, domain->cbcr_addr,
				 sizeof(uint32_t), &priv->cbcr_va);
	if (res)
		return res;

	res = qcom_clk_regmap_va(domain->regmap, domain->vote_reg_addr,
				 sizeof(uint32_t), &priv->vote_va);
	if (res)
		return res;

	if (!domain->cmd_rcgr_addr)
		return TEE_SUCCESS;

	/* The DFS banks extend past CMD_RCGR, so span covers the whole set. */
	return qcom_clk_regmap_va(domain->regmap, domain->cmd_rcgr_addr,
				  qcom_rcg_span(domain->dfs_states) +
				  sizeof(uint32_t), &priv->cmd_rcgr_va);
}

static TEE_Result qcom_clk_src_votes_resolve(const struct qcom_clk_cfg *cfg)
{
	uint32_t i = 0;

	if (!cfg->n_src_votes)
		return TEE_SUCCESS;

	qcom_src_vote_va = calloc(cfg->n_src_votes, sizeof(*qcom_src_vote_va));
	if (!qcom_src_vote_va)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < cfg->n_src_votes; i++) {
		const struct qcom_clk_src_vote *sv = &cfg->src_votes[i];
		TEE_Result res = qcom_clk_regmap_va(sv->regmap,
						    sv->vote_reg_addr,
						    sizeof(uint32_t),
						    &qcom_src_vote_va[i]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result qcom_clocks_register(void)
{
	const struct qcom_clk_cfg *cfg = qcom_clk_cfg_get();
	uint32_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (qcom_clk_privs)
		return TEE_SUCCESS;

	if (!cfg || !cfg->n_domains)
		return TEE_ERROR_BAD_STATE;

	res = qcom_clk_src_votes_resolve(cfg);
	if (res)
		return res;

	qcom_clk_privs = calloc(cfg->n_domains, sizeof(*qcom_clk_privs));
	if (!qcom_clk_privs)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < cfg->n_domains; i++) {
		struct qcom_clk_priv *priv = &qcom_clk_privs[i];
		struct clk *clk = NULL;

		priv->domain = &cfg->domains[i];

		res = qcom_clk_priv_resolve(priv);
		if (res) {
			EMSG("%s: bad register address", priv->domain->name);
			return res;
		}

		clk = clk_alloc(cfg->domains[i].name, &qcom_clk_priv_ops,
				NULL, 0);
		if (!clk)
			return TEE_ERROR_OUT_OF_MEMORY;

		priv->clk = clk;
		clk->priv = priv;

		res = clk_register(clk);
		if (res) {
			clk_free(clk);
			priv->clk = NULL;
			return res;
		}

		qcom_clk_priv_count = i + 1;
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_clk_get_by_name(const char *name, struct clk **out)
{
	uint32_t i = 0;

	if (!name || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!qcom_clk_priv_count)
		return TEE_ERROR_BAD_STATE;

	for (i = 0; i < qcom_clk_priv_count; i++) {
		if (!strcmp(qcom_clk_privs[i].domain->name, name)) {
			*out = qcom_clk_privs[i].clk;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result qcom_clk_enable_dfs(struct clk *clk)
{
	struct qcom_clk_priv *priv = NULL;

	if (!clk || clk->ops != &qcom_clk_priv_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	priv = clk->priv;
	return qcom_clock_domain_enable_dfs(priv);
}

const struct qcom_clk_domain *qcom_clk_get_domain(struct clk *clk)
{
	struct qcom_clk_priv *priv = NULL;

	if (!clk || clk->ops != &qcom_clk_priv_ops)
		return NULL;

	priv = clk->priv;
	return priv->domain;
}

driver_init(qcom_clocks_register);
#endif /* CFG_QCOM_CLK_CFG */
