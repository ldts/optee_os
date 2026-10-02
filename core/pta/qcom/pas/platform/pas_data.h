/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_DATA_H_
#define _PAS_DATA_H_

#include <drivers/clk_qcom.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>

struct qcom_pas_data {
	uint32_t pas_id;
	/*
	 * 0-terminated list of PAS_IDs this subsystem depends on: each must
	 * be loaded before this one's fw_start() runs and must stay loaded
	 * until after this one shuts down. NULL if this subsystem has no
	 * dependencies.
	 */
	const uint32_t *depends_on;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	/* Set once fw_start() succeeds; cleared once fw_shutdown() succeeds. */
	bool loaded;
	enum qcom_clk_group clk_group;
	/* Map the controller window MEM_AREA_IO_SEC, e.g. when XPU-gated. */
	bool map_secure;
};

#endif /* _PAS_DATA_H_ */
