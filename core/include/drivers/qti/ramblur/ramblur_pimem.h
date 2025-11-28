/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef RAMBLUR_PIMEM_H
#define RAMBLUR_PIMEM_H

#define RAMBLUR_PIMEM_REG_SIZE 0x4000

void qti_ramblur_pimem_get_version(uint32_t *major, uint32_t *minor,
				   uint32_t *step);

#endif
