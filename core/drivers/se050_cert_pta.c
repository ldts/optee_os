// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <drivers/se050_cert_pta_client.h>

#define PTA_NAME "se050_cert.pta"

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_VALUE_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	IMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.a = params[0].memref.size;

	switch (nCommandID) {
	case PTA_CMD_SE050_CERT_GET:
		return crypto_cert_get(params[0].memref.buffer,
				       &params[1].value.a,
				       params[1].value.b);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SE050_CERT_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
