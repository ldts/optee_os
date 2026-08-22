// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Aggregate RPMh voting for the shared CX/MX rails. Any consumer that must
 * raise a rail corner before an operation (and release it after) votes here;
 * the helper keeps the rails at the highest corner still needed across all of
 * them. Not tied to any one subsystem.
 *
 * Callers speak in raw corners (rail_voltage_level). RPMh, though, takes an
 * ordinal into the rail's corner list (hlvl), so a corner is resolved to an
 * hlvl once, at the vote boundary; the reference counts and the aggregate are
 * then tracked purely in hlvl space.
 *
 * This helper does not serialise its own state: its one consumer, the clock
 * driver, reaches it only from the set-rate path, which already runs under the
 * clock framework lock. A consumer not already serialised against that path
 * would have to add its own serialisation.
 */

#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <tee_api_types.h>

#include "rpmh_rail.h"

#define RPMH_RAIL_HLVL_MAX	32

/* CX plus, where the target has it, MX. */
#define RPMH_RAIL_MAX		2

/* A partial vote left the rails disagreeing; no real hlvl compares equal. */
#define RPMH_RAIL_HLVL_INVALID	0xFFFFFFFF

struct rpmh_rail {
	struct rpmh_client *rpmh;
	bool ready;
	uint32_t rails[RPMH_RAIL_MAX];
	size_t num_rails;
	uint16_t corners[RPMH_RAIL_HLVL_MAX];	/* corner per hlvl, ascending */
	size_t num_hlvls;
	uint16_t votes[RPMH_RAIL_HLVL_MAX];	/* reference count per hlvl */
	uint32_t voted;		/* hlvl on the rails; INVALID if partial */
};

static struct rpmh_rail rpmh_rail;

static TEE_Result rpmh_rail_init(void)
{
	struct rpmh_rail *r = &rpmh_rail;
	size_t len = sizeof(r->corners);
	TEE_Result res = TEE_SUCCESS;
	uint32_t addr = 0;

	if (r->ready)
		return TEE_SUCCESS;

	if (!r->rpmh) {
		r->rpmh = rpmh_create_handle(RSC_DRV_SECURE, "rail");
		if (!r->rpmh)
			return TEE_ERROR_GENERIC;
	}

	/* Rebuilt from scratch, so a retry after a partial init cannot grow. */
	r->num_rails = 0;

	res = cmd_db_get_addr("cx.lvl", &addr);
	if (res)
		return res;
	r->rails[r->num_rails++] = addr;

	/* Short-buffer error rather than a list missing its top corners. */
	res = cmd_db_get_aux("cx.lvl", (uint8_t *)r->corners, &len);
	if (res)
		return res;
	r->num_hlvls = len / sizeof(r->corners[0]);

	/* Only trailing zeros are padding: hlvl 0 is a real corner (OFF). */
	while (r->num_hlvls > 1 && r->corners[r->num_hlvls - 1] == 0)
		r->num_hlvls--;

	if (!r->num_hlvls)
		return TEE_ERROR_BAD_STATE;

	/* MX tracks CX on this target; vote it too when the rail exists. */
	if (!cmd_db_get_addr("mx.lvl", &addr))
		r->rails[r->num_rails++] = addr;

	r->ready = true;

	return TEE_SUCCESS;
}

/* Resolve a raw corner to the rail's hlvl ordinal (smallest that satisfies). */
static TEE_Result rpmh_rail_corner_to_hlvl(uint16_t corner, uint32_t *hlvl)
{
	size_t i = 0;

	for (i = 0; i < rpmh_rail.num_hlvls; i++) {
		if (rpmh_rail.corners[i] >= corner) {
			*hlvl = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/* Drive every rail to @hlvl. */
static TEE_Result rpmh_rail_apply(uint32_t hlvl)
{
	struct rpmh_rail *r = &rpmh_rail;
	uint32_t req_id = 0;
	size_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (hlvl == r->voted)
		return TEE_SUCCESS;

	/* INVALID until every rail lands, so a partial vote re-votes. */
	r->voted = RPMH_RAIL_HLVL_INVALID;

	for (i = 0; i < r->num_rails; i++) {
		res = rpmh_send_command(r->rpmh, RPMH_SET_ACTIVE, true,
					r->rails[i], hlvl, &req_id);
		if (res)
			return res;
		rpmh_barrier_single(r->rpmh, req_id);
	}

	r->voted = hlvl;

	return TEE_SUCCESS;
}

/* Highest hlvl any consumer still holds, or hlvl 0 (lowest corner) if none. */
static uint32_t rpmh_rail_peak(void)
{
	struct rpmh_rail *r = &rpmh_rail;
	uint32_t peak = 0;
	size_t i = 0;

	for (i = 0; i < r->num_hlvls; i++)
		if (r->votes[i])
			peak = i;

	return peak;
}

/* Move one consumer's vote between corners; 0 means no vote. */
static TEE_Result rpmh_rail_move(uint16_t old_corner, uint16_t new_corner)
{
	struct rpmh_rail *r = &rpmh_rail;
	uint32_t old_hlvl = 0;
	uint32_t new_hlvl = 0;
	TEE_Result res = TEE_SUCCESS;

	if (new_corner) {
		res = rpmh_rail_corner_to_hlvl(new_corner, &new_hlvl);
		if (res)
			return res;
	}

	if (old_corner) {
		res = rpmh_rail_corner_to_hlvl(old_corner, &old_hlvl);
		if (res)
			return res;

		/* Caller-tracked state: a stale corner would pin the rails. */
		if (!r->votes[old_hlvl])
			return TEE_ERROR_BAD_STATE;
	}

	if (new_corner)
		r->votes[new_hlvl]++;
	if (old_corner)
		r->votes[old_hlvl]--;

	res = rpmh_rail_apply(rpmh_rail_peak());
	if (res) {
		if (new_corner)
			r->votes[new_hlvl]--;
		if (old_corner)
			r->votes[old_hlvl]++;
	}

	return res;
}

TEE_Result rpmh_rail_vote(uint16_t old_corner, uint16_t new_corner)
{
	TEE_Result res = TEE_SUCCESS;

	res = rpmh_rail_init();
	if (!res)
		res = rpmh_rail_move(old_corner, new_corner);

	return res;
}
