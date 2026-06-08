/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GCC_BASE			UL(0x110000)
#define GCC_SIZE			UL(0x100000)

#define CFG_SEC_ELF_DDR_ADDR		UL(0x908FF000)
#define CFG_SEC_ELF_DDR_SIZE		UL(0x1000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x380000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x800000000)

#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xd1900000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01c00000)

#define GENI_UART_REG_BASE		UL(0xa8c000)

#define IMEM_BASE			UL(0x14680000)
#define IMEM_SIZE			UL(0x32000)

#define TURING_0_BASE			UL(0x24000000)
#define TURING_0_SIZE			UL(0x03000000)

#define TURING_1_BASE			UL(0x28000000)
#define TURING_1_SIZE			UL(0x03000000)

#define PAS_ID_TURING			18
#define PAS_ID_TURING1			30

/*
 * CDSP (CDSP0 / TURING) content-protection shared channel in the static TZ DDR
 * region. TZ zeroes this on CDSP0 bring-up (ACResetSharedChannel,
 * AC_VM_CP_CDSP); there is no equivalent CDSP1 channel. Address mirrors the TZ
 * DDR layout: TZBSP_EBI1_SECCHANNEL_CDSP (TZ_TZ_STAT_BASE_ADDR 0xDB100000 +
 * 0xc0000 + TZBSP_TZ_DDR_SECCHANNEL_SIZE 0x1c000), size 0x2000.
 */
#define CDSP_SECCHANNEL_BASE		UL(0xdb1dc000)
#define CDSP_SECCHANNEL_SIZE		UL(0x2000)

#endif /* TARGET_CONFIG_H */
