// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020, Foundries Limited
 */

#include <crypto/crypto.h>
#include <drivers/rng_pta_client.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <string.h>

#define PTA_NAME "rng.pta"

static TEE_Result rng_get_entropy(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *e = NULL;
	uint32_t rq_size = 0;
	uint32_t exceptions = 0;
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rq_size = params[0].memref.size;
	e = (uint8_t *)params[0].memref.buffer;
	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	res = crypto_rng_read(e, rq_size);
	thread_set_exceptions(exceptions);

	return res;
}

static TEE_Result rng_get_info(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * value.a is data rate: calls to crypto rng will always generate
	 * the requested number of bytes from the RNG device therefore there
	 * is no need to artificially wait for it to generate additional data.
	 */
	params[0].value.a = 0;

	/*
	 * value.b is quality: 0 (unknown), 1 (lowest) and 1024(highest)
	 * HW dependent true entropy estimation set this to 1024.
	 */
	params[0].value.b = 1024;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t cmd, uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (cmd) {
	case PTA_CMD_GET_ENTROPY:
		return rng_get_entropy(types, params);
	case PTA_CMD_GET_RNG_INFO:
		return rng_get_info(types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_RNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
