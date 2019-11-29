// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <io.h>
#include <drivers/imx_snvs.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdint.h>
#include <types_ext.h>
#include <trace.h>

#define SNVS_HPSR	0x14

#define HPSR_SSM_ST_MASK			GENMASK_32(11, 8)
#define HPSR_SSM_ST_SHIFT			8
#define HPSR_SYS_SECURITY_CFG_MASK		GENMASK_32(14, 12)
#define HPSR_SYS_SECURITY_CFG_SHIFT		12

enum snvs_security_cfg snvs_get_security_cfg(void)
{
	vaddr_t snvs = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);
	uint32_t val = 0;

	val = io_read32(snvs + SNVS_HPSR);
	val &= HPSR_SYS_SECURITY_CFG_MASK;
	val = val >> HPSR_SYS_SECURITY_CFG_SHIFT;
	DMSG("Security CFG: 0x%01x", val);
	if (val == 0)
		return SNVS_SECURITY_CFG_FAB;
	else if (val == 1)
		return SNVS_SECURITY_CFG_OPEN;
	else if (val > 1 && val < 4)
		return SNVS_SECURITY_CFG_CLOSED;
	else if (val > 4 && val < 8)
		return SNVS_SECURITY_CFG_FIELD_RETURN;
	return SNVS_SECURITY_CFG_OPEN;
}

enum snvs_ssm_mode snvs_get_ssm_mode(void)
{
	vaddr_t snvs = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);
	uint32_t val = 0;

	val = io_read32(snvs + SNVS_HPSR);
	val &= HPSR_SSM_ST_MASK;
	val = val >> HPSR_SSM_ST_SHIFT;
	DMSG("SSM ST Mode: 0x%01x", val);
	return val;
}
