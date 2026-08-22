/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _RPMH_RAIL_H_
#define _RPMH_RAIL_H_

#include <stdint.h>
#include <tee_api_types.h>

/*
 * Aggregate RPMh voting for the shared CX (and, where present, MX) rails.
 *
 * CX/MX are SoC-wide rails, so all consumers share one aggregate vote: the
 * rails sit at the highest corner any consumer still needs. Each consumer
 * tracks the corner it holds and moves it with rpmh_rail_vote(); the helper
 * reference-counts corners so one consumer lowering its need never drops the
 * rails below what another still requires.
 *
 * Move this consumer's vote from @old_corner to @new_corner (raw
 * rail_voltage_level; 0 means "no vote"). Vote up before an operation needs
 * the higher corner and down after it no longer does, so the rails are never
 * left below what is in use.
 *
 * Not internally serialised: callers must be serialised against each other
 * (the clock driver, its only consumer, calls this under the clock framework
 * lock).
 */
TEE_Result rpmh_rail_vote(uint16_t old_corner, uint16_t new_corner);

#endif /* _RPMH_RAIL_H_ */
