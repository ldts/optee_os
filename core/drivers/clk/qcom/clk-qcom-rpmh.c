// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * RPMh CX/MX rail voting for clock rate changes. Kept separate from the RCG
 * walker (clk-qcom.c) so a non-RPMh target can supply its own rail-vote
 * backend behind the same qcom_clk_volt_vote() contract.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <kernel/mutex.h>
#include <tee_api_types.h>

#include "clk_qcom_volt.h"

/*
 * A rate is never programmed under-volted: the corner is voted before the rate
 * is raised and released only after it is lowered.
 *
 * Domains share one aggregate vote. Each holds a reference count per corner
 * (votes[]) and the rails sit at the highest corner with a nonzero count, so
 * one domain lowering its need never drops the rails below what another needs.
 */

#define QCOM_CLK_VLVL_MAX	32

/* CX plus, where the target has it, MX. */
#define QCOM_CLK_RAIL_MAX	2

/* A partial vote left the rails disagreeing; no real corner compares equal. */
#define QCOM_CLK_CORNER_UNKNOWN	0xFFFF

struct qcom_clk_volt {
	struct mutex lock;	/* serialises the vote + tracking state */
	struct rpmh_client *rpmh;
	bool ready;
	uint32_t rails[QCOM_CLK_RAIL_MAX];
	uint32_t n_rails;
	uint16_t vlvls[QCOM_CLK_VLVL_MAX];	/* ascending */
	uint32_t n_vlvls;
	uint16_t votes[QCOM_CLK_VLVL_MAX];	/* reference count per corner */
	uint16_t voted;		/* corner on the rails; 0 means nothing voted */
};

static struct qcom_clk_volt qcom_clk_volt = {
	.lock = MUTEX_INITIALIZER,
};

static TEE_Result qcom_clk_volt_init(void)
{
	struct qcom_clk_volt *v = &qcom_clk_volt;
	size_t len = sizeof(v->vlvls);
	TEE_Result res = TEE_SUCCESS;
	uint32_t addr = 0;

	if (v->ready)
		return TEE_SUCCESS;

	if (!v->rpmh) {
		v->rpmh = rpmh_create_handle(RSC_DRV_SECURE, "clk");
		if (!v->rpmh)
			return TEE_ERROR_GENERIC;
	}

	/* Rebuilt from scratch, so a retry after a partial init cannot grow. */
	v->n_rails = 0;

	res = cmd_db_get_addr("cx.lvl", &addr);
	if (res)
		return res;
	v->rails[v->n_rails++] = addr;

	/* Short-buffer error rather than a list missing its top corners. */
	res = cmd_db_get_aux("cx.lvl", (uint8_t *)v->vlvls, &len);
	if (res)
		return res;
	v->n_vlvls = len / sizeof(v->vlvls[0]);

	/* Only trailing zeros are padding: index 0 is a real corner (OFF). */
	while (v->n_vlvls > 1 && v->vlvls[v->n_vlvls - 1] == 0)
		v->n_vlvls--;

	if (!v->n_vlvls)
		return TEE_ERROR_BAD_STATE;

	/* MX tracks CX on this target; vote it too when the rail exists. */
	if (!cmd_db_get_addr("mx.lvl", &addr))
		v->rails[v->n_rails++] = addr;

	v->ready = true;

	return TEE_SUCCESS;
}

/* RPMh takes an ordinal into the rail's corner list, not the raw corner. */
static TEE_Result qcom_corner_to_hlvl(uint16_t corner, uint32_t *hlvl)
{
	uint32_t i = 0;

	for (i = 0; i < qcom_clk_volt.n_vlvls; i++) {
		if (qcom_clk_volt.vlvls[i] >= corner) {
			*hlvl = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/* Caller holds v->lock. */
static TEE_Result qcom_clk_volt_apply(uint16_t corner)
{
	struct qcom_clk_volt *v = &qcom_clk_volt;
	uint32_t hlvl = 0;
	uint32_t req_id = 0;
	uint32_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (corner == v->voted)
		return TEE_SUCCESS;

	/* Resolved first, so an unsupported corner strands no state below. */
	res = qcom_corner_to_hlvl(corner, &hlvl);
	if (res)
		return res;

	/* UNKNOWN until every rail lands, so a partial vote re-votes. */
	v->voted = QCOM_CLK_CORNER_UNKNOWN;

	for (i = 0; i < v->n_rails; i++) {
		res = rpmh_send_command(v->rpmh, RPMH_SET_ACTIVE, true,
					v->rails[i], hlvl, &req_id);
		if (res)
			return res;
		rpmh_barrier_single(v->rpmh, req_id);
	}

	v->voted = corner;

	return TEE_SUCCESS;
}

/*
 * Highest corner with a nonzero count, or 0 for none. Returns a corner and not
 * an index: 0 is not a legal corner, so it doubles as "nothing voted".
 */
static uint16_t qcom_clk_volt_peak(void)
{
	struct qcom_clk_volt *v = &qcom_clk_volt;
	uint16_t peak = 0;
	uint32_t i = 0;

	for (i = 0; i < v->n_vlvls; i++)
		if (v->votes[i])
			peak = v->vlvls[i];

	return peak;
}

/* Move one domain's vote between corners; 0 means no vote. Holds v->lock. */
static TEE_Result qcom_clk_volt_move(uint16_t old_corner, uint16_t new_corner)
{
	struct qcom_clk_volt *v = &qcom_clk_volt;
	uint32_t old_idx = 0;
	uint32_t new_idx = 0;
	TEE_Result res = TEE_SUCCESS;

	if (new_corner) {
		res = qcom_corner_to_hlvl(new_corner, &new_idx);
		if (res)
			return res;
	}

	if (old_corner) {
		res = qcom_corner_to_hlvl(old_corner, &old_idx);
		if (res)
			return res;

		/* Caller-tracked state: a stale corner would pin the rails. */
		if (!v->votes[old_idx])
			return TEE_ERROR_BAD_STATE;
	}

	if (new_corner)
		v->votes[new_idx]++;
	if (old_corner)
		v->votes[old_idx]--;

	res = qcom_clk_volt_apply(qcom_clk_volt_peak());
	if (res) {
		if (new_corner)
			v->votes[new_idx]--;
		if (old_corner)
			v->votes[old_idx]++;
	}

	return res;
}

TEE_Result qcom_clk_volt_vote(uint16_t old_corner, uint16_t new_corner)
{
	struct qcom_clk_volt *v = &qcom_clk_volt;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&v->lock);
	res = qcom_clk_volt_init();
	if (!res)
		res = qcom_clk_volt_move(old_corner, new_corner);
	mutex_unlock(&v->lock);

	return res;
}
