/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Foundries.io Ltd
 */

#ifndef __RNG_PTA__H
#define __RNG_PTA__H

#define PTA_RNG_UUID { 0xab7a617c, 0xb8e7, 0x4d8f, { \
		       0x83, 0x01, 0xd0, 0x9b, 0x61, 0x03, 0x6b, 0x64 } }

/*
 * [in/out]	memref[0]	entropy buffer
 */
#define PTA_CMD_GET_ENTROPY		0

/*
 * [out]	value[0].a	RNG data-rate in bytes per second
 * [out]	value[0].b	quality/entropy per 1024 bit of data
 */
#define PTA_CMD_GET_RNG_INFO		1

#endif /* __RNG_PTA__H */
