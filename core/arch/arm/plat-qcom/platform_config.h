/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#if defined(PLATFORM_FLAVOR_kodiak)
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x100000000)
#define DRAM1_SIZE			ULL(0x100000000)

/* DDR reserved regions */
#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xc1800000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01c00000)
#define SMEM_BASE			ULL(0x80900000)
#define SMEM_SIZE			ULL(0x200000)

#define IRIS_BASE			UL(0x0aa00000)
#define IRIS_SIZE			ULL(0x00200000)

#define GENI_UART_REG_BASE		UL(0x994000)
#define RAMBLUR_PIMEM_REG_BASE		UL(0x610000)

/* GIC related constants */
#define GICD_BASE			UL(0x17a00000)
#define GICR_BASE			UL(0x17a60000)

#define GCC_BASE			UL(0x100000)
#define WPSS_BASE			UL(0x8a00000)
#define PAS_ID_WPSS			0x6
#define PAS_ID_VENUS			9
#endif

#endif /*PLATFORM_CONFIG_H*/
