/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _VENUS_H_
#define _VENUS_H_

#include "pas_data.h"

#define IRIS_WRAPPER_TOP_TZ_REG_BASE	0x000c0000
#define IRIS_WRAPPER_TOP_REG_BASE	0x000b0000

struct qcom_pas_data *venus_get_pas_data(void);
TEE_Result venus_fw_set_state(bool power_on);
TEE_Result venus_fw_shutdown(void);
TEE_Result venus_fw_start(void);

#endif /* _VENUS_H_ */
