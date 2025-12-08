# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
#

incdirs-$(CFG_QCOM_RAMBLUR_PIMEM_V3) += ../../include/drivers/qcom/ramblur/v3/
srcs-$(CFG_QCOM_RAMBLUR_PIMEM_V3) += ramblur/ramblur_pimem_v3.c

incdirs-$(CFG_QCOM_SMEM) += ../../include/drivers/qcom/smem/
srcs-$(CFG_QCOM_SMEM) += smem/smem.c

incdirs-$(CFG_QCOM_SOCINFO) += ../../include/drivers/qcom/socinfo/
srcs-$(CFG_QCOM_SOCINFO) += socinfo/socinfo.c

