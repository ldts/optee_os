/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 */

#ifndef _Q6DSP_H_
#define _Q6DSP_H_

#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <drivers/clk_qcom.h>

struct qcom_q6dsp_data {
	uint32_t pas_id;
	struct io_pa_va base;
	struct io_pa_va lpass_efuse_base;
	paddr_t firmware_base;
	enum qcom_clk_group clk_group;
};

TEE_Result wpss_dsp_start(struct qcom_q6dsp_data *data);

#endif /* _Q6DSP_H_ */
