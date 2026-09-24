// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom_geni_i2c.h>
#include <i2c_native.h>
#include <phNxpEsePal_i2c.h>

static struct qup_i2c_data qi;
static struct i2c_dev dev;

TEE_Result native_i2c_transfer(struct rpc_i2c_request *req, size_t *bytes)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (req->mode == RPC_I2C_MODE_READ)
		ret = i2c_read(&dev, req->buffer, req->buffer_len);
	else
		ret = i2c_write(&dev, req->buffer, req->buffer_len);

	if (!ret)
		*bytes = req->buffer_len;

	return ret;
}

int native_i2c_init(void)
{
	if (qup_i2c_init(&qi, CFG_CORE_SE05X_I2C_BUS))
		return -1;

	/* GENI supports only 100k/400k/1M, set a valid default */
	qi.speed_hz = CFG_CORE_SE05X_BAUDRATE;

	if (qup_i2c_dev_init(&qi, &dev, SMCOM_I2C_ADDRESS >> 1))
		return -1;

	return 0;
}
