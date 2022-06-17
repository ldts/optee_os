PLATFORM_FLAVOR ?= generic

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
$(call force,CFG_GIC,y)

# Disable core ASLR for two reasons:
# 1. There is no source for ALSR seed, as TF-a does not provide a
#    DTB to OP-TEE. Hardware RNG is also not currently supported.
# 2. Xilinx's bootgen can't find the OP-TEE entry point from the TEE.elf file
#    used to generate boot.bin. Enabling ASLR requires an update to TF-A.
$(call force,CFG_CORE_ASLR,n)

CFG_CRYPTO_WITH_CE ?= y
CFG_CORE_DYN_SHM   ?= y
CFG_WITH_STATS     ?= y
CFG_ARM64_core     ?= y

CFG_TZDRAM_START   ?= 0x60000000
CFG_TZDRAM_SIZE    ?= 0x10000000
CFG_SHMEM_START    ?= 0x70000000
CFG_SHMEM_SIZE     ?= 0x10000000

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_CORE_ARM64_PA_BITS,43)
else
$(call force,CFG_ARM32_core,y)
endif

$(call force, CFG_VERSAL_RNG_DRV, y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)
$(call force, CFG_VERSAL_PM, y)
$(call force, CFG_VERSAL_MBOX, y)
$(call force, CFG_VERSAL_NVM, y)

# TRNG configuration
CFG_VERSAL_TRNG_SEED_LIFE ?= 3
CFG_VERSAL_TRNG_DF_MUL    ?= 7

# MBOX configuration
CFG_VERSAL_MBOX_IPI_ID    ?= 3

# Crypto
CFG_VERSAL_CRYPTO_DRIVER  ?= n

# FPGA
CFG_VERSAL_FPGA_INIT      ?= n
CFG_VERSAL_FPGA_DDR_ADDR  ?= 0x80000

# PUF
CFG_VERSAL_PUF            ?= y

# GPIO
CFG_ZYNQ_GPIO             ?= y

# HUK AES-GCM key selection:
# To secure the system the key must be one of the eFUSEd keys
#    4  : EFUSE AES
#    6  : EFUSE USR 0
#    7  : EFUSE USR 1
#    12 : AES development key
CFG_VERSAL_HUK_KEY        ?= 12
CFG_VERSAL_HUK            ?= y

# XSECURE_AES_USER_KEY_0 (12) to XSECURE_AES_USER_KEY_7 (19)
CFG_VERSAL_AES_GCM_KEY    =? 12

# AES GCM replay feature requires extra heap allocations
CFG_CORE_HEAP_SIZE ?= 524288
