// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <imx_pm.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>

paddr_t iram_tbl_phys_addr = -1UL;
void *iram_tbl_virt_addr;

static uint32_t imx7ulp_mmdc_io_lpddr3_offset[] = {
	0x128, 0xf8, 0xd8, 0x108,
	0x104, 0x124, 0x80, 0x84,
	0x88, 0x8c, 0x120, 0x10c,
	0x110, 0x114, 0x118, 0x90,
	0x94, 0x98, 0x9c, 0xe0,
	0xe4,
};

static uint32_t imx7ulp_mmdc_lpddr3_offset[] = {
	0x01c, 0x800, 0x85c, 0x890,
	0x848, 0x850, 0x81c, 0x820,
	0x824, 0x828, 0x82c, 0x830,
	0x834, 0x838, 0x8c0, 0x8b8,
	0x004, 0x00c, 0x010, 0x038,
	0x014, 0x018, 0x02c, 0x030,
	0x040, 0x000, 0x01c, 0x01c,
	0x01c, 0x01c, 0x01c, 0x01c,
	0x01c, 0x01c, 0x01c, 0x01c,
	0x01c, 0x01c, 0x83c, 0x020,
	0x800, 0x004, 0x404, 0x01c,
};

static const uint32_t imx7ulp_lpddr3_script[] = {
	0x00008000, 0xA1390003, 0x0D3900A0, 0x00400000,
	0x40404040, 0x40404040, 0x33333333, 0x33333333,
	0x33333333, 0x33333333, 0xf3333333, 0xf3333333,
	0xf3333333, 0xf3333333, 0x24922492, 0x00000800,
	0x00020052, 0x292C42F3, 0x00100A22, 0x00120556,
	0x00C700DB, 0x00211718, 0x0F9F26D2, 0x009F0E10,
	0x0000003F, 0xC3190000, 0x00008050, 0x00008058,
	0x003F8030, 0x003F8038, 0xFF0A8030, 0xFF0A8038,
	0x04028030, 0x04028038, 0x83018030, 0x83018038,
	0x01038030, 0x01038038, 0x20000000, 0x00001800,
	0xA1310000, 0x00020052, 0x00011006, 0x00000000,
};

static struct imx7ulp_pm_data imx7ulp_lpddr3_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx7ulp_mmdc_io_lpddr3_offset),
	.mmdc_io_offset = imx7ulp_mmdc_io_lpddr3_offset,
	.mmdc_num = ARRAY_SIZE(imx7ulp_mmdc_lpddr3_offset),
	.mmdc_offset = imx7ulp_mmdc_lpddr3_offset,
};

struct imx7ulp_pm_info *pm_info;

paddr_t phys_addr[] = {
	AIPS0_BASE, AIPS1_BASE, 0
};

static int pm_imx7ulp_iram_tbl_init(void)
{
	uint32_t i;
	struct tee_mmap_region map;

	/* iram mmu translation table already initialized */
	if (iram_tbl_phys_addr != (-1UL))
		return 0;

	iram_tbl_phys_addr = LP_OCRAM_START;
	iram_tbl_virt_addr = phys_to_virt(iram_tbl_phys_addr,
					  MEM_AREA_TEE_COHERENT,
					  16 * 1024);

	/* 16KB */
	memset(iram_tbl_virt_addr, 0, 16 * 1024);

	for (i = 0; i < ARRAY_SIZE(phys_addr); i++) {
		map.pa = phys_addr[i];
		map.va = (vaddr_t)phys_to_virt(phys_addr[i], MEM_AREA_IO_SEC,
						CORE_MMU_PGDIR_SIZE);
		map.region_size = CORE_MMU_PGDIR_SIZE;
		map.size = AIPS1_SIZE; /* 4M for AIPS1/2/3 */
		map.type = MEM_AREA_IO_SEC;
		map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
			   TEE_MATTR_SECURE |
			   (TEE_MATTR_MEM_TYPE_DEV << TEE_MATTR_MEM_TYPE_SHIFT);
		map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);
	}

	map.pa = M4_AIPS_BASE;
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_IO_SEC, 0x100000);
	map.region_size = 0x100000;
	map.size = 0x100000;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				 TEE_MATTR_SECURE;
	map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);

	map.pa = ROUNDDOWN(IRAM_BASE, 0x100000);
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_TEE_COHERENT, 0x100000);
	map.region_size = 0x100000;
	map.size = 0x100000;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				TEE_MATTR_SECURE | TEE_MATTR_PX;
	map_memarea_sections(&map, (uint32_t *)iram_tbl_virt_addr);

	/*
	 * We no need to give GIC a standalone entry, because AIPS0 has
	 * already included GIC space. If not, map_memarea will
	 * panic.
	 *
	 * Note: No map DRAM space, DRAM is in auto-selfrefresh,
	 * If map DRAM in to MMU, mmu will access DRAM which
	 * hang system.
	 */
	return 0;
}

int imx7ulp_suspend_init(void)
{
	uint32_t i;
	uint32_t suspend_ocram_base = (uint32_t)core_mmu_get_va(
			(paddr_t)LP_OCRAM_START +
			SUSPEND_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT,
			SUSPEND_OCRAM_SIZE);
	struct imx7ulp_pm_info *p =
			(struct imx7ulp_pm_info *)suspend_ocram_base;
	struct imx7ulp_pm_data *pm_data;
	uint32_t *mmdc_io_offset_array, *mmdc_offset_array;

	pm_info = p;

	pm_imx7ulp_iram_tbl_init();

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	DMSG("ocram_base %x, pm_info size%x\n", suspend_ocram_base, sizeof(*p));

	p->pbase = LP_OCRAM_START + SUSPEND_OCRAM_OFFSET;
	p->resume_addr = (paddr_t)virt_to_phys(
				(void *)(vaddr_t)imx7ulp_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->scg1_base = core_mmu_get_va(SCG1_BASE, MEM_AREA_IO_SEC, SCG1_SIZE);
	p->smc1_base = core_mmu_get_va(SMC1_BASE, MEM_AREA_IO_SEC, SMC1_SIZE);
	p->mmdc_base = core_mmu_get_va(MMDC_BASE, MEM_AREA_IO_SEC, MMDC_SIZE);
	p->mmdc_io_base = core_mmu_get_va(MMDC_IO_BASE, MEM_AREA_IO_SEC,
					  MMDC_IO_SIZE);
	p->sim_base = core_mmu_get_va(SIM_BASE, MEM_AREA_IO_SEC, SIM_SIZE);

	pm_data = &imx7ulp_lpddr3_pm_data;
	p->mmdc_io_num = pm_data->mmdc_io_num;
	mmdc_io_offset_array = pm_data->mmdc_io_offset;
	p->mmdc_num = pm_data->mmdc_num;
	mmdc_offset_array = pm_data->mmdc_offset;

	for (i = 0; i < p->mmdc_io_num; i++) {
		p->mmdc_io_val[i][0] = mmdc_io_offset_array[i];
		p->mmdc_io_val[i][1] = io_read32(p->mmdc_io_base +
					      mmdc_io_offset_array[i]);
	}

	/* initialize MMDC settings */
	for (i = 0; i < p->mmdc_num; i++)
		p->mmdc_val[i][0] = mmdc_offset_array[i];

	for (i = 0; i < p->mmdc_num; i++)
		p->mmdc_val[i][1] = imx7ulp_lpddr3_script[i];

	memcpy((void *)(suspend_ocram_base + sizeof(*p)),
			(void *)(vaddr_t)imx7ulp_suspend,
			SUSPEND_OCRAM_SIZE - sizeof(*p));

	dcache_clean_range((void *)suspend_ocram_base, SUSPEND_OCRAM_SIZE);
	/* Note that IRAM IOSEC map,
	 * if changed to MEM map, need to flush cache
	 */
	icache_inv_all();

	DMSG("%s resume address = %x\n", __func__, (uint32_t)(p->resume_addr));

	return 0;
}
