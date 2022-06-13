// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

static struct {
	uint8_t key[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} huk;

#define SHA3_UPDATE 32
#define SHA3_MODULE_SHIFT 8
#define SHA3_MODULE_ID 5
#define SHA3_API_ID(__x) ((SHA3_MODULE_ID << SHA3_MODULE_SHIFT) | (__x))

static TEE_Result versal_create_digest(uint8_t *src, size_t src_len,
				       uint8_t *dst, size_t dst_len)
{
	struct versal_mbox_mem p = { };
	struct ipi_cmd cmd = { };

	versal_mbox_alloc(src_len, src, &p);
	cmd.data[0] = SHA3_API_ID(SHA3_UPDATE);
	cmd.data[1] = virt_to_phys(p.buf);
	cmd.data[2] = virt_to_phys(p.buf) >> 32;
	cmd.data[3] = BIT(30) |  BIT(31) | src_len;
	cmd.ibuf[0].buf = p.buf;
	cmd.ibuf[0].len = p.alloc_len;

	if (versal_mbox_notify(&cmd, NULL))
		goto out;

	free(p.buf);
	memset(&cmd, 0, sizeof(cmd));

	versal_mbox_alloc(dst_len, NULL, &p);
	cmd.data[0] = SHA3_API_ID(SHA3_UPDATE);
	cmd.data[4] = virt_to_phys(p.buf);
	cmd.data[5] = virt_to_phys(p.buf) >> 32;
	cmd.ibuf[0].buf = p.buf;
	cmd.ibuf[0].len = p.alloc_len;

	if (versal_mbox_notify(&cmd, NULL))
		goto out;

	memcpy(dst, p.buf, p.len);

	free(p.buf);
	return TEE_SUCCESS;
out:
	free(p.buf);
	return TEE_ERROR_GENERIC;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t dna[EFUSE_DNA_LEN / sizeof(uint32_t)] = { 0 };
	uint8_t sha[48] = { 0 };

	if (huk.ready)
		goto out;

	if (versal_get_efuse_ops()->read->dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

	if (versal_create_digest((uint8_t *)dna, sizeof(dna), sha, sizeof(sha)))
		return TEE_ERROR_GENERIC;

	memcpy(huk.key, sha, sizeof(huk.key));
	huk.ready = true;
out:
	memcpy(hwkey->data, huk.key, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}
