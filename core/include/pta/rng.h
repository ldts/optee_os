/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021, Foundries Limited
 */

#ifndef ___RNG_H
#define ___RNG_H

#include <kernel/pseudo_ta.h>

TEE_Result rng_get_entropy(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result rng_get_info(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);

#endif
