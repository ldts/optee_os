// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019 Bryan O'Donoghue
 * Copyright 2019 NXP
 *
 * Bryan O'Donoghue <bryan.odonoghue@linaro.org>
 */

#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_trace.h>
#include <caam_utils_mem.h>
#include <drivers/imx_caam_mkvb.h>
#include <stdint.h>
#include <tee/cache.h>
#include <string.h>
#include <mm/core_memprot.h>


TEE_Result caam_get_mkvb(uint8_t *dest)
{
	struct caam_jobctx jobctx = { 0 };
	TEE_Result ret = TEE_ERROR_SECURITY;
	uint8_t *outbuf = NULL;
	uint32_t *desc = NULL;

	outbuf = caam_calloc(32);
	desc = caam_calloc_desc(5);
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, MKVB_DESC_SEQ_OUT);
	caam_desc_add_ptr(desc, virt_to_phys(outbuf));
	cache_operation(TEE_CACHEFLUSH, outbuf, MKVB_SIZE);
	caam_desc_add_word(desc, MKVB_DESC_BLOB);
	HASH_DUMPDESC(desc);


	jobctx.desc = desc;
	ret = caam_jr_enqueue(&jobctx, NULL);
	DMSG("caam ret: %d", ret);
	if (ret == CAAM_JOB_STATUS)
		DMSG("HuK Job status 0x%08" PRIx32, jobctx.status);
	if (ret == CAAM_NO_ERROR)
		ret = TEE_SUCCESS;
	else
		goto out;

	cache_operation(TEE_CACHEINVALIDATE, outbuf, MKVB_SIZE);
	DHEXDUMP(outbuf, MKVB_SIZE);

	memcpy(dest, outbuf, MKVB_SIZE);
	ret = TEE_SUCCESS;
out:
	/* Increment PRIBLOB to 11 to lock out same MKVB from normal world */
	caam_hal_ctrl_inc_priblob();
	caam_free_desc(&desc);
	caam_free(outbuf);
	return ret;
}
