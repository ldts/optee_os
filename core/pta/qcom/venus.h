/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026,
 */

#ifndef VENUS_H
#define VENUS_H

#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <drivers/clk_qcom.h>

struct qcom_venus_data {
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
};

TEE_Result venus_fw_start(struct qcom_venus_data *data);
void venus_fw_shutdown(struct qcom_venus_data *data);

#endif /* VENUS_H */
