# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025, Qualcomm Technologies, Inc. and/or its subsidiaries.
#
#

incdirs-$(CFG_QTI_RAMBLUR_PIMEM) += ../../include/drivers/qti/ramblur/$(PLATFORM_FLAVOR)/
incdirs-$(CFG_QTI_RAMBLUR_PIMEM) += ../../include/drivers/qti/ramblur/

srcs-$(CFG_QTI_RAMBLUR_PIMEM) += ramblur/ramblur_pimem.c
