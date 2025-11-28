// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Qualcomm Technologies Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <ramblur_pimem.h>
#include <ramblur_pimem_hwio.h>
#include <string.h>

#define ANTIROLLBACK	(UINT32_C(1) << \
	RAMBLUR_PIMEM_WIN0_ALGORITHM_CONFIG_WIN_ANTIROLLBACK_ENABLE_SHFT)
#define INTEGRITY	(UINT32_C(1) << \
	RAMBLUR_PIMEM_WIN0_ALGORITHM_CONFIG_WIN_INTEGRITY_ENABLE_SHFT)
#define CONFIDENTIALITY	(UINT32_C(1) << \
	RAMBLUR_PIMEM_WIN0_ALGORITHM_CONFIG_WIN_CONFIDENTIALITY_ENABLE_SHFT)

static vaddr_t ramblur_va;

static inline uint16_t in_word(vaddr_t addr)
{
	return io_read16(addr + ramblur_va);
}

static inline uint32_t in_dword(vaddr_t addr)
{
	return io_read32(addr + ramblur_va);
}

static inline uint32_t in_dword_masked(vaddr_t addr, uint32_t mask)
{
	uint32_t val = in_dword(addr);

	return val & mask;
}

static inline void out_dword(vaddr_t port, uint32_t val)
{
	io_write32(port + ramblur_va, val);
	dsb();
}

static inline void out_dword_masked_ns(vaddr_t io, uint32_t mask, uint32_t val,
				       uint32_t current_reg_content)
{
	uint32_t new_val;

	new_val = (current_reg_content & (uint32_t)~mask) |
		((uint32_t)val & (uint32_t)mask);
	out_dword(io, new_val);
}

static void enable_window(int window)
{
	uint32_t mask = 0;
	uint32_t reg = 0;
	uint32_t val = 0;

	mask = RAMBLUR_PIMEM_WINn_CTL_WIN_ENABLE_REQ_BMSK;
	reg = RAMBLUR_PIMEM_WINn_CTL_ADDR(window);
	val = BIT(RAMBLUR_PIMEM_WINn_CTL_WIN_ENABLE_REQ_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_PIMEM_WINn_CTL_INI(window));

	reg = RAMBLUR_PIMEM_WINn_STATUS_ADDR(window);
	mask = RAMBLUR_PIMEM_WINn_STATUS_WIN_ENABLE_STATUS_BMSK;

	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_PIMEM_WINn_STATUS_WIN_ENABLE_STATUS_SHFT;
	} while (val != 1U);
}

static void disable_sw_init_mode(int window)
{
	uint32_t mask = 0;
	uint32_t reg = 0;
	uint32_t val = 0;

	mask = RAMBLUR_PIMEM_WINn_CTL_SW_INIT_MODE_BMSK;
	reg = RAMBLUR_PIMEM_WINn_CTL_ADDR(window);
	val = 0U;

	out_dword_masked_ns(reg, mask, val, RAMBLUR_PIMEM_WINn_CTL_INI(window));
}

static void disable_window(int window)
{
	uint32_t mask = 0;
	uint32_t reg = 0;
	uint32_t val = 0;

	mask = RAMBLUR_PIMEM_WINn_CTL_WIN_DISABLE_REQ_BMSK;
	reg = RAMBLUR_PIMEM_WINn_CTL_ADDR(window);
	val = BIT(RAMBLUR_PIMEM_WINn_CTL_WIN_DISABLE_REQ_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_PIMEM_WINn_CTL_INI(window));

	mask = RAMBLUR_PIMEM_WINn_STATUS_WIN_ENABLE_STATUS_BMSK;
	reg = RAMBLUR_PIMEM_WINn_STATUS_ADDR(window);

	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_PIMEM_WINn_STATUS_WIN_ENABLE_STATUS_SHFT;
	} while (val != 0U);
}

static void prepare_hardware(int window, uint32_t offset)
{
	uint32_t mask = 0;
	uint32_t reg = 0;
	uint32_t val = 0;
	uint32_t cur = 0;

	mask = RAMBLUR_PIMEM_WINn_HW_INIT_START_OFFSET_INIT_START_OFFSET_BMSK;
	reg = RAMBLUR_PIMEM_WINn_HW_INIT_START_OFFSET_ADDR(window);
	cur = RAMBLUR_PIMEM_WINn_HW_INIT_START_OFFSET_INI(window);
	val = offset;

	out_dword_masked_ns(reg, mask, val, cur);
}

static int init_hardware(int window)
{
	uint32_t mask = 0;
	uint32_t reg = 0;
	uint32_t val = 0;

	mask = RAMBLUR_PIMEM_WINn_CTL_START_HW_INIT_BMSK;
	reg = RAMBLUR_PIMEM_WINn_CTL_ADDR(window);
	val = BIT(RAMBLUR_PIMEM_WINn_CTL_START_HW_INIT_SHFT);

	out_dword_masked_ns(reg, mask, val, RAMBLUR_PIMEM_WINn_CTL_INI(window));

	mask = RAMBLUR_PIMEM_WINn_STATUS_HW_INIT_DONE_BMSK;
	reg = RAMBLUR_PIMEM_WINn_STATUS_ADDR(window);

	do {
		val = in_dword_masked(reg, mask) >>
			RAMBLUR_PIMEM_WINn_STATUS_HW_INIT_DONE_SHFT;
	} while (val != 1U);

	return 0;
}

static int init_window(int window)
{
	const uint32_t offset = 0U;

	disable_sw_init_mode(window);
	disable_window(window);
	prepare_hardware(window, offset);

	return init_hardware(window);
}

static void set_algorithm(int window, uint32_t algo)
{
	uint32_t reg = RAMBLUR_PIMEM_WINn_ALGORITHM_CONFIG_ADDR(window);

	out_dword(reg, algo);
}

static uint32_t get_window_size(int window)
{
	uint32_t reg = RAMBLUR_PIMEM_WINn_SIZE_ADDR(window);

	return in_dword_masked(reg, RAMBLUR_PIMEM_WINn_SIZE_RMSK);
}

static void resize_window(int window, size_t size)
{
	uint32_t reg = RAMBLUR_PIMEM_WINn_SIZE_ADDR(window);

	out_dword(reg, (uint32_t)size);
}

static void configure_data_vault(int window, uintptr_t addr)
{
	uint32_t hi = (uint32_t)(addr >> 32);
	uint32_t lo = (uint32_t)addr;
	uint32_t reg = 0;

	hi &= RAMBLUR_PIMEM_WINn_DATA_VAULT_START_ADDR_HI_RMSK;
	reg = RAMBLUR_PIMEM_WINn_DATA_VAULT_START_ADDR_HI_ADDR(window);
	out_dword(reg, hi);

	lo &= RAMBLUR_PIMEM_WINn_DATA_VAULT_START_ADDR_LOW_RMSK;
	reg = RAMBLUR_PIMEM_WINn_DATA_VAULT_START_ADDR_LOW_ADDR(window);
	out_dword(reg, lo);
}

static TEE_Result initialize_window(int window, size_t size, uintptr_t vault)
{
	uint32_t win_size = 0;
	int rc = 0;

	configure_data_vault(window, vault);

	win_size = get_window_size(window);
	if (win_size) {
		/* We can't resize in this code path */
		return TEE_SUCCESS;
	}

	resize_window(window, size);

	set_algorithm(window, ANTIROLLBACK | INTEGRITY | CONFIDENTIALITY);

	rc = init_window(window);
	if (rc)
		return TEE_ERROR_ACCESS_DENIED;

	enable_window(window);

	return TEE_SUCCESS;
}

void qti_ramblur_pimem_get_version(uint32_t *major, uint32_t *minor,
				   uint32_t *step)
{
	uint32_t val = in_dword(RAMBLUR_PIMEM_VERSION_ADDR);

	if (major) {
		*major = (val & RAMBLUR_PIMEM_VERSION_MAJOR_VERSION_BMSK) >>
			 RAMBLUR_PIMEM_VERSION_MAJOR_VERSION_SHFT;
	}

	if (minor) {
		*minor = (val & RAMBLUR_PIMEM_VERSION_MINOR_VERSION_BMSK) >>
			 RAMBLUR_PIMEM_VERSION_MINOR_VERSION_SHFT;
	}

	if (step) {
		*step = (val & RAMBLUR_PIMEM_VERSION_STEP_VERSION_BMSK) >>
			RAMBLUR_PIMEM_VERSION_STEP_VERSION_SHFT;
	}
}

static TEE_Result qti_ramblur_pimem_init(void)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, RAMBLUR_PIMEM_REG_BASE,
				  RAMBLUR_PIMEM_REG_SIZE))
		panic("Can't add Ramblur pIMEM");

	ramblur_va = (vaddr_t)phys_to_virt(RAMBLUR_PIMEM_REG_BASE,
					   MEM_AREA_IO_SEC,
					   RAMBLUR_PIMEM_REG_SIZE);
	if (!ramblur_va)
		panic("Can't get Ramblur virtual");

	return initialize_window(TA_WINDOW_ID, TA_WINDOW_SIZE, TA_VAULT_BASE);
}

early_init(qti_ramblur_pimem_init);

