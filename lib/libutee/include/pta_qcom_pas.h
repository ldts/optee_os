/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PTA_QCOM_REMOTEPROC_H
#define __PTA_QCOM_REMOTEPROC_H

#include <stdint.h>
#include <util.h>

/*
 * Interface to the pseudo TA which provides platform implementation
 * of the remote processor management
 */

#define PTA_QCOM_PAS_UUID { 0xcff7d191, 0x7ca0, 0x4784, \
		{ 0xaf, 0x13, 0x48, 0x22, 0x3b, 0x9a, 0x4f, 0xbe} }

/*
 * Peripheral Authentication Service (PAS) supported.
 *
 * Get PAS support status.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].value.a:	Firmware format (PTA_RPROC_HWCAP_FMT_*)
 * [out] params[2].value.a:	Image protection method (PTA_RPROC_HWCAP_PROT_*)
 */
#define PTA_QCOM_PAS_IS_SUPPORTED		1

/*
 * PAS capabilities.
 *
 * Get PAS capabilities.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].value.a:	Firmware format (PTA_RPROC_HWCAP_FMT_*)
 * [out] params[2].value.a:	Image protection method (PTA_RPROC_HWCAP_PROT_*)
 */
#define PTA_QCOM_PAS_CAPABILITIES		2

/*
 * PAS image initialization.
 *
 * Perform PAS image initialization.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].memref:	Loadable firmware image
 */
#define PTA_QCOM_PAS_INIT_IMAGE			3

/*
 * PAS memory setup.
 *
 * Perform PAS memory setup.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].memref:	Section data to load
 * [in]  params[2].value.a:	32bit LSB load device segment address
 * [in]  params[2].value.b:	32bit MSB load device segment address
 * [in]  params[3].memref:	Expected hash (SHA256) of the payload
 */
#define PTA_QCOM_PAS_MEM_SETUP			4

/*
 * PAS image authentication and co-processor reset.
 *
 * Perform PAS image authentication and co-processor reset.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].value.a:	32bit LSB device memory address
 * [in]  params[1].value.b:	32bit MSB device memory address
 * [in]  params[2].value.a:	32bit LSB device memory size
 * [in]  params[2].value.b:	32bit MSB device memory size
 * [in]  params[3].value.a:	Byte value to be set
 */
#define PTA_QCOM_PAS_AUTH_AND_RESET		5

/*
 * PAS co-processor shutdown.
 *
 * Perform PAS co-processor shutdown.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define PTA_QCOM_PAS_SHUTDOWN			6

#endif /* __PTA_QCOM_REMOTEPROC_H */
