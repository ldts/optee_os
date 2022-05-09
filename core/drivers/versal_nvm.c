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

#include "drivers/versal_nvm.h"

#define NVM_WORD_LEN 4

/* Protocol API with the remote processor */
#define NVM_MODULE_SHIFT	8
#define NVM_MODULE		11
#define NVM_API_ID(_id) ((NVM_MODULE << NVM_MODULE_SHIFT) | (_id))

/*
 * Max size of the buffer needed for the remote processor to DMA efuse _data_
 * to/from
 */
#define EFUSE_MAX_LEN (EFUSE_MAX_USER_FUSES * sizeof(uint32_t))

enum versal_nvm_api_id {
	API_FEATURES			= 0,
	BBRAM_WRITE_AES_KEY		= 1,
	BBRAM_ZEROIZE			= 2,
	BBRAM_WRITE_USER_DATA		= 3,
	BBRAM_READ_USER_DATA		= 4,
	BBRAM_LOCK_WRITE_USER_DATA	= 5,
	EFUSE_WRITE			= 6,
	EFUSE_WRITE_PUF			= 7,
	EFUSE_PUF_USER_FUSE_WRITE	= 8,
	EFUSE_READ_IV			= 9,
	EFUSE_READ_REVOCATION_ID	= 10,
	EFUSE_READ_OFFCHIP_REVOCATION_ID = 11,
	EFUSE_READ_USER_FUSES		= 12,
	EFUSE_READ_MISC_CTRL		= 13,
	EFUSE_READ_SEC_CTRL		= 14,
	EFUSE_READ_SEC_MISC1		= 15,
	EFUSE_READ_BOOT_ENV_CTRL	= 16,
	EFUSE_READ_PUF_SEC_CTRL		= 17,
	EFUSE_READ_PPK_HASH		= 18,
	EFUSE_READ_DEC_EFUSE_ONLY	= 19,
	EFUSE_READ_DNA			= 20,
	EFUSE_READ_PUF_USER_FUSES	= 21,
	EFUSE_READ_PUF			= 22,
	EFUSE_INVALID			= 23,
};

struct versal_efuse_glitch_cfg_bits {
	uint8_t prgm_glitch;
	uint8_t glitch_det_wr_lk;
	uint32_t glitch_det_trim;
	uint8_t gd_rom_monitor_en;
	uint8_t gd_halt_boot_en;
	uint8_t pad[56];
} __packed;

struct versal_efuse_aes_keys {
	uint8_t prgm_aes_key;
	uint8_t prgm_user_key0;
	uint8_t prgm_user_key1;
	uint32_t aes_key[8];
	uint32_t user_key0[8];
	uint32_t user_key1[8];
	uint8_t pad[29];
} __packed;

struct versal_efuse_ppk_hash {
	uint8_t prgm_ppk0_hash;
	uint8_t prgm_ppk1_hash;
	uint8_t prgm_ppk2_hash;
	uint32_t ppk0_hash[8];
	uint32_t ppk1_hash[8];
	uint32_t ppk2_hash[8];
	uint8_t pad[29];
} __packed;

struct versal_efuse_dec_only {
	uint8_t prgm_dec_only;
	uint8_t pad[63];
} __packed;

struct versal_efuse_revoke_ids {
	uint8_t prgm_revoke_id;
	uint32_t revoke_id[8];
	uint8_t pad[31];
} __packed;

struct versal_efuse_offchip_ids {
	uint8_t prgm_offchip_id;
	uint32_t offchip_id[8];
	uint8_t pad[31];
} __packed;

struct versal_efuse_user_data {
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[48];
} __packed;

struct versal_efuse_puf_fuse {
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint32_t start;
	uint32_t num;
	uint64_t addr;
	uint8_t pad[46];
} __packed;

struct versal_efuse_puf_hd {
	struct versal_efuse_puf_sec_ctrl_bits puf_sec_ctrl_bits;
	uint8_t prgm_puf_helper_data;
	uint8_t env_monitor_dis;
	uint32_t efuse_syn_data[127];
	uint32_t chash;
	uint32_t aux;
	uint8_t pad[58];
} __packed;

struct versal_efuse_data {
	uint64_t env_mon_dis_flag;
	uint64_t aes_key_addr;
	uint64_t ppk_hash_addr;
	uint64_t dec_only_addr;
	uint64_t sec_ctrl_addr;
	uint64_t misc_ctrl_addr;
	uint64_t revoke_id_addr;
	uint64_t iv_addr;
	uint64_t user_fuse_addr;
	uint64_t glitch_cfg_addr;
	uint64_t boot_env_ctrl_addr;
	uint64_t misc1_ctrl_addr;
	uint64_t offchip_id_addr;
	uint8_t pad[24];
} __packed;

/* Helper read and write requests (not part of the protocol) */
struct versal_nvm_read_req {
	enum versal_nvm_api_id efuse_id;
	enum versal_nvm_revocation_id revocation_id;
	enum versal_nvm_offchip_id offchip_id;
	enum versal_nvm_ppk_type ppk_type;
	enum versal_nvm_iv_type iv_type;
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

enum versal_nvm_write_efuse_id {
	EFUSE_WRITE_USER_FUSES,
	EFUSE_WRITE_IVS_FUSES,
	EFUSE_WRITE_REVOKE_PPK_FUSES,
	EFUSE_WRITE_REVOKE_ID_FUSES,
	EFUSE_WRITE_PUF_FUSES,
	EFUSE_WRITE_INVALID = 0xffff,
};

struct versal_nvm_write_req {
	struct versal_efuse_data data;
	enum versal_nvm_write_efuse_id id;
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

struct cmd_args {
	uint32_t data[3];
	size_t len;
};

static TEE_Result prepare_cmd(struct ipi_cmd *cmd, enum versal_nvm_api_id efuse,
			      struct ipi_buf *ibufs, struct cmd_args *arg)
{
	size_t i = 0;

	cmd->data[0] = NVM_API_ID(efuse);
	for (i = 1; i < arg->len + 1; i++)
		cmd->data[i] = arg->data[i - 1];

	if (!ibufs[0].buf)
		return TEE_SUCCESS;

	cmd->data[i++] = virt_to_phys(ibufs[0].buf);
	cmd->data[i++] = virt_to_phys(ibufs[0].buf) >> 32;

	for (i = 0; i < MAX_IPI_BUF; i++) {
		cmd->ibuf[i].len = ibufs[i].len;
		cmd->ibuf[i].buf = ibufs[i].buf;
	}

	return TEE_SUCCESS;
}

static TEE_Result efuse_req(enum versal_nvm_api_id efuse, struct ipi_buf *ibufs,
			    struct cmd_args *arg)
{
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd cmd = { };

	ret = prepare_cmd(&cmd, efuse, ibufs, arg);
	if (ret)
		return ret;

	ret = versal_mbox_notify(&cmd, NULL);
	if (ret)
		EMSG("Mailbox error");

	return ret;
}

static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	struct cmd_args args = { };

	if (!req)
		return TEE_ERROR_GENERIC;

	switch (req->efuse_id) {
	case EFUSE_READ_DNA:
	case EFUSE_READ_DEC_EFUSE_ONLY:
	case EFUSE_READ_PUF_SEC_CTRL:
	case EFUSE_READ_BOOT_ENV_CTRL:
	case EFUSE_READ_SEC_CTRL:
	case EFUSE_READ_MISC_CTRL:
	case EFUSE_READ_SEC_MISC1:
	case BBRAM_READ_USER_DATA:
	case EFUSE_READ_USER_FUSES:
	case EFUSE_READ_PUF_USER_FUSES:
	case EFUSE_READ_PUF:
		break;
	case BBRAM_ZEROIZE:
	case BBRAM_LOCK_WRITE_USER_DATA:
		if (req->ibuf[0].buf)
			return TEE_ERROR_GENERIC;
		break;
	case EFUSE_READ_OFFCHIP_REVOCATION_ID:
		args.data[0] = req->offchip_id;
		args.len = 1;
		break;
	case EFUSE_READ_REVOCATION_ID:
		args.data[0] = req->revocation_id;
		args.len = 1;
		break;
	case EFUSE_READ_IV:
		args.data[0] = req->iv_type;
		args.len = 1;
		break;
	case EFUSE_READ_PPK_HASH:
		args.data[0] = req->ppk_type;
		args.len = 1;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, &args);
}

static TEE_Result versal_nvm_write(struct versal_nvm_write_req *req)
{
	enum versal_nvm_api_id efuse_id = EFUSE_INVALID;
	struct cmd_args args = { };

	switch (req->id) {
	case EFUSE_WRITE_USER_FUSES:
	case EFUSE_WRITE_IVS_FUSES:
	case EFUSE_WRITE_REVOKE_PPK_FUSES:
	case EFUSE_WRITE_REVOKE_ID_FUSES:
	case EFUSE_WRITE_PUF_FUSES:
		efuse_id = EFUSE_WRITE;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(efuse_id, req->ibuf, &args);
}

TEE_Result versal_read_efuse_dna(uint32_t *buf, size_t len)
{
	uint8_t lbuf[1024] __aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DNA,
	};

	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_DNA_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				  size_t num)
{
	uint8_t lbuf[1024] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num, /* fuses needs to be at least 40 bytes */
	};
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_USER_FUSES,
	};

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);
	req.ibuf[1].buf = lbuf;
	req.ibuf[1].len = sizeof(lbuf);

	cfg.addr = (paddr_t)virt_to_phys((void *)cfg.addr);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, num * sizeof(uint32_t));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	uint8_t lbuf[1024] __aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_IV,
		.iv_type = type,
	};

	if (len < EFUSE_IV_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_IV_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		req.efuse_id = EFUSE_READ_PPK_HASH,
		.ppk_type = type, };

	if (len < EFUSE_PPK_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_PPK_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_write_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				   size_t num)
{
	uint32_t lbuf[EFUSE_MAX_USER_FUSES] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num,
	};
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.env_mon_dis_flag = 1,
		.data.user_fuse_addr = (uintptr_t)&cfg,
		.id = EFUSE_WRITE_USER_FUSES,
	};
	size_t i = 0;

	if (first + num > EFUSE_MAX_USER_FUSES || len  < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Update the command buffers with physical addresses */
	req.data.user_fuse_addr = (paddr_t)
				  virt_to_phys((void *)req.data.user_fuse_addr);
	cfg.addr = (paddr_t)virt_to_phys(lbuf);

	/* Request cache management */
	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);
	req.ibuf[2].buf = lbuf;
	req.ibuf[2].len = sizeof(lbuf);

	/* Prepare fuses to write with some random data */
	for (i = 0; i < cfg.num; i++)
		lbuf[i] = buf[i];

	return versal_nvm_write(&req);
}

TEE_Result versal_write_efuse_iv(struct versal_efuse_ivs *p)
{
	struct versal_efuse_ivs cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.id = EFUSE_WRITE_IVS_FUSES,
		.data.env_mon_dis_flag = 1,
		.data.iv_addr = (uintptr_t)&cfg,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.data.iv_addr = (paddr_t)virt_to_phys((void *)req.data.iv_addr);
	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);

	return versal_nvm_write(&req);
}

TEE_Result versal_write_efuse_revoke_ppk(enum versal_nvm_ppk_type type)
{
	struct versal_efuse_misc_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req  __aligned_efuse= {
		.id = EFUSE_WRITE_REVOKE_PPK_FUSES,
		.data.misc_ctrl_addr = (uintptr_t)&cfg,
		.data.env_mon_dis_flag = 1,
	};

	req.data.misc_ctrl_addr = (paddr_t)virt_to_phys((void *)
						req.data.misc_ctrl_addr);
	if (type == EFUSE_PPK0)
		cfg.ppk0_invalid = 1;
	else if (type == EFUSE_PPK1)
		cfg.ppk1_invalid = 1;
	else if (type == EFUSE_PPK2)
		cfg.ppk2_invalid = 1;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);

	return versal_nvm_write(&req);
}

TEE_Result versal_write_efuse_revoke_id(uint32_t id)
{
	struct versal_efuse_revoke_ids cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.id = EFUSE_WRITE_REVOKE_ID_FUSES,
		.data.misc_ctrl_addr = (uintptr_t)&cfg,
		.data.env_mon_dis_flag = 1,
	};
	uint32_t row = 0;
	uint32_t bit = 0;

	row = id >> (NVM_WORD_LEN + 1);
	bit = id >> (NVM_WORD_LEN - 1);

	cfg.revoke_id[row] = 1 << bit;
	cfg.prgm_revoke_id = 1;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);

	return versal_nvm_write(&req);
}

TEE_Result versal_read_efuse_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_REVOCATION_ID,
		.revocation_id = id,
	};

	if (len < EFUSE_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_REVOCATION_ID_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_MISC_CTRL,
	};

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof(*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf)
{
	uint8_t lbuf[EFUSE_MAX_LEN]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_CTRL,
	};

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof(*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_sec_misc1(struct versal_efuse_sec_misc1_bits *buf)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_MISC1,
	};

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof(*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_boot_env_ctrl(struct
					   versal_efuse_boot_env_ctrl_bits *buf)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_BOOT_ENV_CTRL,
	};

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof(*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_OFFCHIP_REVOCATION_ID,
		.offchip_id = id, };

	if (len < EFUSE_OFFCHIP_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_REVOCATION_ID_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_dec_only(uint32_t *buf, size_t len)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DEC_EFUSE_ONLY,
	};

	if (len < EFUSE_DEC_ONLY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, EFUSE_DEC_ONLY_LEN);

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_puf_sec_ctrl(struct
					  versal_efuse_puf_sec_ctrl_bits *buf)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF_SEC_CTRL,
	};

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof (*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_read_efuse_puf(struct versal_efuse_puf_header *buf)
{
	uint8_t lbuf[1024]__aligned_efuse = { 0 };
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF,
	};

	memcpy(lbuf, buf, sizeof(*buf));

	req.ibuf[0].buf = lbuf;
	req.ibuf[0].len = sizeof(lbuf);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, lbuf, sizeof(*buf));

	return TEE_SUCCESS;
}

TEE_Result versal_write_efuse_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_efuse_puf_header cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.id = EFUSE_WRITE_PUF_FUSES,
	};

	memcpy(&cfg, buf, sizeof(*buf));

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
