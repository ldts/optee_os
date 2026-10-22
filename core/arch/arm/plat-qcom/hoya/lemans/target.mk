CFG_TA_RAM_VA_SIZE ?= 0x1c00000

CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_TLMM ?= y

CFG_QCOM_DIAG_LOG ?= $(CFG_TEE_CORE_DEBUG)
CFG_QCOM_GENI_SPI ?= y

# Discrete TPM (dTPM) on QUP2 SE2, driven over SPI using the TCG PTP SPI
# (TIS) protocol. The TCG PCR provider / event-log replay is not wired here
# (this platform has no firmware TPM event log at a fixed address); the chip
# is used directly. Enable CFG_CORE_TPM_EVENT_LOG separately if that changes.
CFG_DRIVERS_TPM2 ?= y
CFG_DRIVERS_TPM2_SPI ?= y
ifeq ($(CFG_DRIVERS_TPM2_SPI),y)
$(call force,CFG_QCOM_GENI_SPI,y)
$(call force,CFG_DRIVERS_TPM2,y)
endif
# Expose the dTPM to the normal world (Linux TEE-backed TPM driver). Needs
# the device-enumeration PTA so Linux can discover it by UUID.
CFG_TPM_PASSTHROUGH_PTA ?= y
ifeq ($(CFG_TPM_PASSTHROUGH_PTA),y)
$(call force,CFG_DEVICE_ENUM_PTA,y)
endif
# SPI serial engine and chip-select the dTPM is wired to (QUP2_SE2_SPI_ID),
# and the SPI bus clock to run it at.
CFG_TPM2_SPI_SE_ID ?= 15
CFG_TPM2_SPI_CS ?= 0
CFG_TPM2_SPI_SPEED_HZ ?= 20000000

ifneq ($(CFG_INSECURE),y)
CFG_QCOM_QFPROM_FUSEPROV ?= y
endif

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
# PAS subsystems map their controller windows at runtime from the reserved VA
# pool (never released). The six DSP windows total ~146.5 MB; the 60 MB default
# fits only one, so reserve 256 MB with headroom.
CFG_RESERVED_VASPACE_SIZE ?= (256 * 1024 * 1024)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
CFG_QCOM_PAS_AUTH ?= y
endif

CFG_QCOM_HWKM ?= y

ifeq ($(CFG_QCOM_PAS_AUTH),y)
$(call force,CFG_QCOM_FUSE_PTA,y)
CFG_PAS_MD_SLOTS = 8
# This chip's OEM_CONFIG2 fuse row has a per-root-cert hash function
# select bit; targets without it always use SHA-384.
$(call force,CFG_QCOM_SEGMENT_HASH_SELECT,y)
endif

ifneq ($(filter y,$(CFG_QCOM_QFPROM_FUSEPROV) $(CFG_QCOM_FUSE_PTA)),)
$(call force,CFG_QCOM_QFPROM,y)
endif

ifeq ($(CFG_QCOM_QFPROM),y)
# Fuse blowing needs the smpa4 supply rail the SoC requires for
# programming, voted over RPMH.
$(call force,CFG_QCOM_RPMH_CLIENT,y)
$(call force,CFG_QCOM_CMD_DB,y)
endif

# QUPv3 serial-engine clock set-rate/DFS support. Set-rate votes CX/MX via
# RPMh, so pull cmd_db/RPMh client in whenever the clock config path is built.
CFG_QCOM_CLK_CFG ?= y
ifeq ($(CFG_QCOM_CLK_CFG),y)
$(call force,CFG_QCOM_CMD_DB,y)
$(call force,CFG_QCOM_RPMH_CLIENT,y)
endif
