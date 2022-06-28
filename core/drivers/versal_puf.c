// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_puf.h"

/* Protocol API with the remote processor */
#define PUF_MODULE_SHIFT	8
#define PUF_MODULE		12
#define PUF_API_ID(_id) ((PUF_MODULE << PUF_MODULE_SHIFT) | (_id))

TEE_Result versal_puf_register(struct versal_puf_data *buf,
			       struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf  = { };
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem syndrome_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd arg = { };

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].buf = &req;
	arg.ibuf[0].len = sizeof(req);
	arg.ibuf[1].buf = syndrome_data_addr.buf;
	arg.ibuf[1].len = syndrome_data_addr.alloc_len;
	arg.ibuf[2].buf = hash_addr.buf;
	arg.ibuf[2].len = hash_addr.alloc_len;
	arg.ibuf[3].buf = aux_addr.buf;
	arg.ibuf[3].len = aux_addr.alloc_len;
	arg.ibuf[4].buf = puf_id_addr.buf;
	arg.ibuf[4].len = puf_id_addr.alloc_len;
	arg.ibuf[5].buf = efuse_syn_data_addr.buf;
	arg.ibuf[5].len = efuse_syn_data_addr.alloc_len;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_data_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(PUF_REGISTRATION);
	arg.data[1] = virt_to_phys(arg.ibuf[0].buf);
	arg.data[2] = virt_to_phys(arg.ibuf[0].buf)>> 32;

	if (versal_mbox_notify(&arg, NULL, NULL)) {
		EMSG("Failed to register the PUF");
		ret = TEE_ERROR_GENERIC;
	}

	/* return the generated data */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));
	memcpy(&buf->chash, hash_addr.buf, sizeof(buf->chash));
	memcpy(&buf->aux, aux_addr.buf, sizeof(buf->aux));
	memcpy(buf->efuse_syn_data, efuse_syn_data_addr.buf,
	       sizeof(buf->efuse_syn_data));
	memcpy(buf->syndrome_data, syndrome_data_addr.buf,
	       sizeof(buf->syndrome_data));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(syndrome_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

TEE_Result versal_puf_regenerate(struct versal_puf_data *buf,
				 struct versal_puf_cfg *cfg)
{
	struct versal_puf_data_req req __aligned_puf  = { };
	struct versal_mbox_mem efuse_syn_data_addr = { };
	struct versal_mbox_mem syndrome_data_addr = { };
	struct versal_mbox_mem syndrome_addr = { };
	struct versal_mbox_mem puf_id_addr = { };
	struct versal_mbox_mem hash_addr = { };
	struct versal_mbox_mem aux_addr = { };
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd arg = { };

	versal_mbox_alloc(sizeof(buf->puf_id), buf->puf_id, &puf_id_addr);
	versal_mbox_alloc(sizeof(buf->chash), &buf->chash, &hash_addr);
	versal_mbox_alloc(sizeof(buf->aux), &buf->aux, &aux_addr);
	versal_mbox_alloc(sizeof(buf->efuse_syn_data), buf->efuse_syn_data,
			  &efuse_syn_data_addr);
	versal_mbox_alloc(sizeof(buf->syndrome_data), buf->syndrome_data,
			  &syndrome_data_addr);

	arg.ibuf[0].buf = &req;
	arg.ibuf[0].len = sizeof(req);
	arg.ibuf[1].buf = syndrome_data_addr.buf;
	arg.ibuf[1].len = syndrome_data_addr.alloc_len;
	arg.ibuf[2].buf = hash_addr.buf;
	arg.ibuf[2].len = hash_addr.alloc_len;
	arg.ibuf[3].buf = aux_addr.buf;
	arg.ibuf[3].len = aux_addr.alloc_len;
	arg.ibuf[4].buf = puf_id_addr.buf;
	arg.ibuf[4].len = puf_id_addr.alloc_len;
	arg.ibuf[5].buf = efuse_syn_data_addr.buf;
	arg.ibuf[5].len = efuse_syn_data_addr.alloc_len;

	req.efuse_syn_data_addr = virt_to_phys(efuse_syn_data_addr.buf);
	req.syndrome_data_addr = virt_to_phys(syndrome_data_addr.buf);
	req.puf_id_addr = virt_to_phys(puf_id_addr.buf);
	req.hash_addr = virt_to_phys(hash_addr.buf);
	req.aux_addr = virt_to_phys(aux_addr.buf);

	req.global_var_filter = cfg->global_var_filter;
	req.shutter_value = cfg->shutter_value;
	req.puf_operation = cfg->puf_operation;
	req.read_option = cfg->read_option;
	req.reg_mode = cfg->reg_mode;

	arg.data[0] = PUF_API_ID(PUF_REGENERATION);
	arg.data[1] = virt_to_phys(arg.ibuf[0].buf);
	arg.data[2] = virt_to_phys(arg.ibuf[0].buf) >> 32;

	if (versal_mbox_notify(&arg, NULL, NULL)) {
		EMSG("Failed to regenerate the PUF");
		ret = TEE_ERROR_GENERIC;
	}

	/* return the updated puf id */
	memcpy(buf->puf_id, puf_id_addr.buf, sizeof(buf->puf_id));

	free(syndrome_data_addr.buf);
	free(hash_addr.buf);
	free(aux_addr.buf);
	free(puf_id_addr.buf);
	free(syndrome_addr.buf);
	free(efuse_syn_data_addr.buf);

	return ret;
}

TEE_Result versal_puf_clear_id(void)
{
	struct ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(PUF_CLEAR_PUF_ID);

	if (versal_mbox_notify(&arg, NULL, NULL)) {
		EMSG("Failed to clear the PUFID");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result versal_puf_check_api(enum versal_puf_api id)
{
	struct ipi_cmd arg = { };

	arg.data[0] = PUF_API_ID(PUF_API_FEATURES);
	arg.data[1] = id;

	if (versal_mbox_notify(&arg, NULL, NULL))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
