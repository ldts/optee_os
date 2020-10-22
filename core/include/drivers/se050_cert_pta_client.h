/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2020, Foundries Limited
 */

#ifndef __SE050_CERT_PTA_CLIENT_H
#define __SE050_CERT_PTA_CLIENT_H

#define PTA_SE050_CERT_UUID { 0xd63a9c0b, 0xad3e, 0x4c8e, \
		{ 0x8f, 0xd0, 0x0e, 0x78, 0x18, 0xb0, 0x4c, 0x52 } }
/*
 * Get a certificate from the SE050
 *
 * out  params[0].memref = buffer
 * out  params[1].value.a = buffer len
 * in   params[1].value.b = certificate id
 */
#define PTA_CMD_SE050_CERT_GET		0

#endif /* __SE050_CERT_PTA_CLIENT_H */
