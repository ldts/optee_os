/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef LPASS_H
#define LPASS_H

#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <drivers/clk_qcom.h>

struct qcom_lpass_data {
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	enum qcom_clk_group clk_group;
};

TEE_Result lpass_start(struct qcom_lpass_data *data);
TEE_Result lpass_shutdown(struct qcom_lpass_data *data);

#endif /* LPASS_H */
