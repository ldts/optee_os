// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>
#include <string.h>

TEE_Result crypto_cert_get(uint8_t *cert, uint32_t *len, uint32_t id)
{
	sss_status_t status = kStatus_SSS_Success;
	sss_se05x_object_t k_object = { 0 };
	size_t bits = (*len) * 8;

	status = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	status = sss_se05x_key_object_get_handle(&k_object, id);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	status = sss_se05x_key_store_get_key(se050_kstore, &k_object,
					     cert, len, &bits);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}
