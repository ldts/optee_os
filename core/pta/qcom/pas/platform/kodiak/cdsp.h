/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CDSP_H_
#define _CDSP_H_

#include "pas_data.h"

TEE_Result cdsp_get_resource_table(struct resource_table *rt, size_t *size);
struct qcom_pas_data *cdsp_get_pas_data(void);
TEE_Result cdsp_fw_shutdown(void);
TEE_Result cdsp_fw_start(void);

#endif /* _CDSP_H_ */
