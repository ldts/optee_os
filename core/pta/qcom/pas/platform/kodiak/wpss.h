/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _WPSS_H_
#define _WPSS_H_

#include "pas_data.h"

TEE_Result wpss_get_resource_table(struct resource_table *rt, size_t *rt_size);
struct qcom_pas_data *wpss_get_pas_data(void);
TEE_Result wpss_fw_shutdown(void);
TEE_Result wpss_fw_start(void);

#endif /* _WPSS_H_ */
