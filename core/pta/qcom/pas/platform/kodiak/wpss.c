// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <resource_table.h>
#include <stdint.h>
#include <string.h>

#include "dsp_fw.h"
#include "wpss.h"

#define WPSS_QDSP6V67SS_PUB_REG	0x00000000

static const struct fw_rsc_devmem wpss_mem_res[] = {
	{ .name = "wlan_fw_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x80c00000, .pa = 0x80c00000, .len = 0xc00000, },
	{ .name = "wlan_ce_mem", .flags = IOMMU_READ | IOMMU_WRITE,
		.da = 0x004cd000, .pa = 0x004cd000, .len = 0x1000, },
};

DEFINE_RESOURCE_TABLE(WPSS, ARRAY_SIZE(wpss_mem_res));

TEE_Result wpss_fw_start(void)
{
	static const struct dsp_fw_start_regs regs = {
		.boot_status = WPSS_QDSP6V67SS_PUB_REG + 0x408,
		.core_start = WPSS_QDSP6V67SS_PUB_REG + 0x400,
		.sleep_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x3c,
		.core_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x20,
		.boot_cmd = WPSS_QDSP6V67SS_PUB_REG + 0x404,
		.rst_evb = WPSS_QDSP6V67SS_PUB_REG + 0x10,
		.xo_cbcr = WPSS_QDSP6V67SS_PUB_REG + 0x38,
	};
	struct qcom_pas_data *data = wpss_get_pas_data();

	return dsp_fw_start(data, &regs);
}

TEE_Result wpss_fw_shutdown(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result wpss_get_resource_table(struct resource_table *rt, size_t *rt_size)
{
	const struct fw_rsc_hdr header = {
		.type = RSC_DEVMEM,
	};
	static struct resource_table table = {
		.ver = 1,
		.num = WPSS_NUM_MEM_RESOURCES,
		.offset[WPSS_NUM_MEM_RESOURCES - 1] = 0,
	};

	return get_mem_rsc(rt, rt_size, &table, &header,
			   wpss_mem_res,
			   WPSS_RESOURCE_TABLE_HEADER_SIZE,
			   WPSS_RESOURCE_TABLE_SIZE);
}

struct qcom_pas_data *wpss_get_pas_data(void)
{
	static struct qcom_pas_data pas_data = {
		.clk_group = QCOM_CLKS_WPSS,
		.pas_id = PAS_ID_WPSS,
		.base.pa = WPSS_BASE,
		.size = WPSS_SIZE,
	};

	return &pas_data;
}
