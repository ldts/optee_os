/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_SSS_APIS_H_
#define SE050_SSS_APIS_H_

#include <fsl_sss_se05x_types.h>
#include <nxScp03_Types.h>

extern sss_policy_t se050_asym_policy;
struct se050_scp_key;
/*
 * Context management
 */
typedef struct {
	SE_Connect_Ctx_t open_ctx;
	sss_se05x_session_t session;
	sss_se05x_key_store_t ks;

	/* scp support*/
	struct se050_auth_ctx {
		NXSCP03_StaticCtx_t static_ctx;
		NXSCP03_DynCtx_t dynamic_ctx;
	} se05x_auth;
	sss_user_impl_session_t host_session;
	sss_key_store_t host_ks;
} sss_se05x_ctx_t;

sss_status_t se050_key_store_and_object_init(sss_se05x_ctx_t *ctx);
void se050_delete_persistent_key(uint8_t *data, size_t len);
sss_status_t se050_enable_scp03(sss_se05x_session_t *session);
sss_status_t se050_rotate_scp03_keys(sss_se05x_ctx_t *ctx);
sss_status_t se050_session_open(sss_se05x_ctx_t *ctx,
				struct se050_scp_key *key);
#endif /* SE050_SSS_APIS_H_ */
