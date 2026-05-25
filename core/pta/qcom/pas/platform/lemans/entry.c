// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <mm/core_memprot.h>
#include <platform_pas.h>
#include <pta_qcom_pas.h>
#include <string.h>

#include "cdsp0.h"

TEE_Result pas_platform_is_supported(uint32_t pas_id)
{
	if (pas_id != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result pas_platform_capabilities(uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}

TEE_Result pas_platform_init_image(uint32_t pas_id)
{
	if (pas_id != PAS_ID_TURING)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result pas_platform_mem_setup(uint32_t pas_id , uint32_t fw_size,
				  uint32_t fw_base_low, uint32_t fw_base_high)
{
	struct qcom_pas_data *data = NULL;

	switch (pas_id) {
	case PAS_ID_TURING:
		data = cdsp0_get_pas_data();
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	data->fw_size = fw_size;
	data->fw_base = fw_base_low;
	data->fw_base |= SHIFT_U64(fw_base_high, 32);

	/* Map the controller */
	if (!data->base.va) {
		data->base.va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_NSEC,
							      data->base.pa,
							      data->size);
		if (!data->base.va)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_platform_get_resource_table(uint32_t pas_id,
					   struct resource_table *rt,
					   size_t *size)
{

	switch (pas_id) {
	case PAS_ID_TURING:
		return cdsp0_get_resource_table(rt, size);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result pas_platform_set_remote_state(uint32_t pas_id __unused,
					 uint32_t state __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result pas_platform_auth_and_reset(uint32_t pas_id)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct qcom_pas_data *data = NULL;

	switch (pas_id) {
	case PAS_ID_TURING:
		data = cdsp0_get_pas_data();
		if (!data->fw_base)
			return TEE_ERROR_NO_DATA;

		res = qcom_clock_enable(data->clk_group);
		if (res != TEE_SUCCESS)
			return res;

		return cdsp0_fw_start();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result pas_platform_shutdown(uint32_t pas_id)
{
	switch (pas_id) {
	case PAS_ID_TURING:
		return cdsp0_fw_shutdown();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
