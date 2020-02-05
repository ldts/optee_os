// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_ctrl.h>
#include <caam_io.h>
#include <registers/ctrl_regs.h>
#include <kernel/generic_boot.h>
#include <registers/version_regs.h>
#include <caam_hal_cfg.h>
#include <mm/core_memprot.h>

uint8_t caam_hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val = 0;

	val = io_caam_read32(baseaddr + CHANUM_MS);

	return GET_CHANUM_MS_JRNUM(val);
}

uint8_t caam_hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val = 0;

	/* Read the number of instance */
	val = io_caam_read32(baseaddr + CHANUM_LS);

	if (GET_CHANUM_LS_MDNUM(val)) {
		/* Hashing is supported */
		val = io_caam_read32(baseaddr + CHAVID_LS);
		val &= BM_CHAVID_LS_MDVID;
		if (val == CHAVID_LS_MDVID_LP256)
			return TEE_MAIN_ALGO_SHA256;

		return TEE_MAIN_ALGO_SHA512;
	}

	return UINT8_MAX;
}

void caam_hal_ctrl_inc_priblob(void){
	vaddr_t ctrl_base = 0;
	void *fdt = NULL;

	fdt = get_dt();
	if (fdt)
		caam_hal_cfg_get_ctrl_dt(fdt, &ctrl_base);
	if (!ctrl_base)
		ctrl_base = (vaddr_t)phys_to_virt(CAAM_BASE, MEM_AREA_IO_SEC);

	io_setbits32(ctrl_base + SCFGR, 0x3);
}
