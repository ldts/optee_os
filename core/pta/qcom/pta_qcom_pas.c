// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <platform_config.h>
#include <pta_qcom_pas.h>
#include <string.h>

#include "q6dsp.h"
#include "venus.h"
#include "lpass.h"

#define PTA_NAME	"pta.qcom.pas"

static struct qcom_q6dsp_data wpss_dsp_data = {
	.pas_id = PAS_ID_WPSS,
	.base.pa = WPSS_BASE,
	.clk_group = QCOM_CLKS_WPSS,
};

static struct qcom_venus_data venus_fw_data = {
	.base.pa = IRIS_BASE,
	.size = IRIS_SIZE,
};

static struct qcom_lpass_data lpass_data = {
	.base.pa = LPASS_BASE,
	.size = LPASS_SIZE,
	.clk_group = QCOM_CLKS_LPASS,
};

static TEE_Result qcom_pas_is_supported(uint32_t pt,
				TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.a != PAS_ID_WPSS &&
	    params[0].value.a != PAS_ID_VENUS &&
	    params[0].value.a != PAS_ID_QDSP6)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

static TEE_Result qcom_pas_init_image(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.a == PAS_ID_WPSS ||
	    params[0].value.a == PAS_ID_VENUS ||
	    params[0].value.a == PAS_ID_QDSP6)
		return TEE_SUCCESS;

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result qcom_pas_mem_setup(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS]__unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case PAS_ID_WPSS:
		wpss_dsp_data.firmware_base = params[0].value.b;
		break;
	case PAS_ID_VENUS:
		venus_fw_data.fw_base = params[1].value.a;
		venus_fw_data.fw_size = params[1].value.b;
		break;
	case PAS_ID_QDSP6:
		lpass_data.fw_base = params[1].value.a;
		lpass_data.fw_size = params[1].value.b;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result qcom_pas_auth_and_reset(uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS]__unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_SUCCESS;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case PAS_ID_WPSS:
		if (!wpss_dsp_data.firmware_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(wpss_dsp_data.clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		wpss_dsp_start(&wpss_dsp_data);
		break;
	case PAS_ID_VENUS:
		if (!venus_fw_data.fw_base)
			return TEE_ERROR_NO_DATA;

		venus_fw_start(&venus_fw_data);
		break;
	case PAS_ID_QDSP6:
		if (!lpass_data.fw_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(lpass_data.clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		lpass_start(&lpass_data);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;

	}

	return TEE_SUCCESS;
}

static TEE_Result qcom_pas_shutdown(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case PAS_ID_VENUS:
		venus_fw_shutdown(&venus_fw_data);
		ret = TEE_SUCCESS;
		break;
	case PAS_ID_QDSP6:
		lpass_shutdown(&lpass_data);
		ret = TEE_SUCCESS;
		break;
	default:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	return ret;
}

static TEE_Result pta_qcom_pas_invoke_command(void *session __unused,
					      uint32_t cmd_id,
					      uint32_t param_types,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_QCOM_PAS_IS_SUPPORTED:
		return qcom_pas_is_supported(param_types, params);
	case PTA_QCOM_PAS_INIT_IMAGE:
		return qcom_pas_init_image(param_types, params);
	case PTA_QCOM_PAS_MEM_SETUP:
		return qcom_pas_mem_setup(param_types, params);
	case PTA_QCOM_PAS_AUTH_AND_RESET:
		return qcom_pas_auth_and_reset(param_types, params);
	case PTA_QCOM_PAS_SHUTDOWN:
		return qcom_pas_shutdown(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Pseudo Trusted Application entry points
 */
static TEE_Result pta_qcom_pas_open_session(uint32_t pt __unused,
					    TEE_Param params[TEE_NUM_PARAMS] __unused,
					    void **sess_ctx __unused)
{
	uint32_t login = to_ta_session(ts_get_current_session())->clnt_id.login;

	if (login == TEE_LOGIN_REE_KERNEL)
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

pseudo_ta_register(.uuid = PTA_QCOM_PAS_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = pta_qcom_pas_invoke_command,
		   .open_session_entry_point = pta_qcom_pas_open_session);
