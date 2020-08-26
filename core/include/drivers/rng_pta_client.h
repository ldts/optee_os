/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, Linaro Limited
 */

#ifndef __RNG_PTA_CLIENT_H
#define __RNG_PTA_CLIENT_H

#define PTA_RNG_UUID { 0x035a4479, 0xc369, 0x47f4, \
		{ 0x94, 0x51, 0xc6, 0xfd, 0xff, 0x28, 0xad, 0x65 } }

/*
 * PTA_CMD_GET_ENTROPY - Get Entropy from RNG using crypto_rng_read()
 *
 * param[0] (inout memref) - Entropy buffer memory reference
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_NOT_SUPPORTED - Requested entropy size greater than size of pool
 * TEE_ERROR_HEALTH_TEST_FAIL - Continuous health testing failed
 */
#define PTA_CMD_GET_ENTROPY		0x0

/*
 * PTA_CMD_GET_RNG_INFO - Get RNG information
 *
 * param[0] (out value) - value.a: RNG data-rate in bytes per second
 *                        value.b: Quality/Entropy per 1024 bit of data
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_GET_RNG_INFO		0x1

#endif /* __RNG_PTA_CLIENT_H */
