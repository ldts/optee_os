/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __QCOM_SMEM_H__
#define __QCOM_SMEM_H__

#include <types_ext.h>
#include <stdbool.h>

#define QCOM_SMEM_HOST_ANY -1

bool qcom_smem_is_available(void);

int qcom_smem_alloc(unsigned int host, unsigned int item, size_t size);

void *qcom_smem_get(unsigned int host, unsigned int item, size_t *size);

int qcom_smem_get_free_space(unsigned int host);

#endif
