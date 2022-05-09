/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_NVM_H__
#define __DRIVERS_VERSAL_NVM_H__

#include <drivers/versal_mbox.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define PUF_SYN_DATA_WORDS		127
#define EFUSE_MAX_USER_FUSES		64

#define EFUSE_OFFCHIP_REVOCATION_ID_LEN	8
#define EFUSE_REVOCATION_ID_LEN		8
#define EFUSE_DEC_ONLY_LEN		8
#define EFUSE_DNA_LEN			16
#define EFUSE_PPK_LEN			32
#define EFUSE_IV_LEN			12

enum versal_nvm_iv_type {
	EFUSE_META_HEADER_IV_RANGE = 0,
	EFUSE_BLACK_IV,
	EFUSE_PLM_IV_RANGE,
	EFUSE_DATA_PARTITION_IV_RANGE
};

enum versal_nvm_ppk_type {
	EFUSE_PPK0 = 0,
	EFUSE_PPK1,
	EFUSE_PPK2
};

enum versal_nvm_revocation_id {
	EFUSE_REVOCATION_ID_0 = 0,
	EFUSE_REVOCATION_ID_1,
	EFUSE_REVOCATION_ID_2,
	EFUSE_REVOCATION_ID_3,
	EFUSE_REVOCATION_ID_4,
	EFUSE_REVOCATION_ID_5,
	EFUSE_REVOCATION_ID_6,
	EFUSE_REVOCATION_ID_7
};

enum versal_nvm_offchip_id {
	EFUSE_INVLD = -1,
	EFUSE_OFFCHIP_REVOKE_ID_0 = 0,
	EFUSE_OFFCHIP_REVOKE_ID_1,
	EFUSE_OFFCHIP_REVOKE_ID_2,
	EFUSE_OFFCHIP_REVOKE_ID_3,
	EFUSE_OFFCHIP_REVOKE_ID_4,
	EFUSE_OFFCHIP_REVOKE_ID_5,
	EFUSE_OFFCHIP_REVOKE_ID_6,
	EFUSE_OFFCHIP_REVOKE_ID_7
};

/*
 * all structures mapped to the PLM processor must be address_and_size aligned
 * to the cacheline_len.
 */

struct versal_efuse_ivs {
	uint8_t prgm_meta_header_iv;
	uint8_t prgm_blk_obfus_iv;
	uint8_t prgm_plm_iv;
	uint8_t prgm_data_partition_iv;
	uint32_t meta_header_iv[3];
	uint32_t blk_obfus_iv[3];
	uint32_t plm_iv[3];
	uint32_t data_partition_iv[3];
	uint8_t pad[12];
} __packed;

struct versal_efuse_misc_ctrl_bits {
	uint8_t glitch_det_halt_boot_en;
	uint8_t glitch_det_rom_monitor_en;
	uint8_t halt_boot_error;
	uint8_t halt_boot_env;
	uint8_t vrypto_kat_en;
	uint8_t lbist_en;
	uint8_t safety_mission_en;
	uint8_t ppk0_invalid;
	uint8_t ppk1_invalid;
	uint8_t ppk2_invalid;
	uint8_t pad[54];
} __packed;

struct versal_efuse_puf_sec_ctrl_bits {
	uint8_t puf_regen_dis;
	uint8_t puf_hd_invalid;
	uint8_t puf_test2_dis;
	uint8_t puf_dis;
	uint8_t puf_syn_lk;
	uint8_t pad[59];
} __packed;

struct versal_efuse_sec_misc1_bits {
	uint8_t lpd_mbist_en;
	uint8_t pmc_mbist_en;
	uint8_t lpd_noc_sc_en;
	uint8_t sysmon_volt_mon_en;
	uint8_t sysmon_temp_mon_en;
	uint8_t pad[59];
} __packed;

struct versal_efuse_boot_env_ctrl_bits {
	uint8_t prgm_sysmon_temp_hot;
	uint8_t prgm_sysmon_volt_pmc;
	uint8_t prgm_sysmon_volt_pslp;
	uint8_t prgm_sysmon_temp_cold;
	uint8_t sysmon_temp_en;
	uint8_t sysmon_volt_en;
	uint8_t sysmon_volt_soc;
	uint8_t sysmon_temp_hot;
	uint8_t sysmon_volt_pmc;
	uint8_t sysmon_volt_pslp;
	uint8_t sysmon_temp_cold;
	uint8_t pad[53];
} __packed;

struct versal_efuse_sec_ctrl_bits {
	uint8_t aes_dis;
	uint8_t jtag_err_out_dis;
	uint8_t jtag_dis;
	uint8_t ppk0_wr_lk;
	uint8_t ppk1_wr_lk;
	uint8_t ppk2_wr_lk;
	uint8_t aes_crc_lk;
	uint8_t aes_wr_lk;
	uint8_t user_key0_crc_lk;
	uint8_t user_key0_wr_lk;
	uint8_t user_key1_crc_lk;
	uint8_t user_key1_wr_lk;
	uint8_t sec_dbg_dis;
	uint8_t sec_lock_dbg_dis;
	uint8_t boot_env_wr_lk;
	uint8_t reg_init_dis;
	uint8_t pad[48];
} __packed;

struct versal_efuse_puf_header {
	struct versal_efuse_puf_sec_ctrl_bits_nopad {
		uint8_t puf_regen_dis;
		uint8_t puf_hd_invalid;
		uint8_t puf_test2_dis;
		uint8_t puf_dis;
		uint8_t puf_syn_lk;
	} sec_ctrl;
	uint8_t prmg_puf_helper_data;
	uint8_t env_monitor_dis;
	uint32_t efuse_syn_data[PUF_SYN_DATA_WORDS];
	uint32_t chash;
	uint32_t aux;
	uint8_t pad[52];
}__packed;

#define __aligned_efuse			__aligned(CACHELINE_LEN)

TEE_Result versal_write_efuse_iv(struct versal_efuse_ivs *p);
TEE_Result versal_write_efuse_revoke_ppk(enum versal_nvm_ppk_type type);
TEE_Result versal_write_efuse_revoke_id(uint32_t id);
TEE_Result versal_write_efuse_user(uint32_t *buf, size_t len,
				   uint32_t first, size_t num);
TEE_Result versal_write_efuse_puf(struct versal_efuse_puf_header *buf);

TEE_Result versal_read_efuse_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type);
TEE_Result versal_read_efuse_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id);

TEE_Result versal_read_efuse_user(uint32_t *buf, size_t len, uint32_t first,
				  size_t num);
TEE_Result versal_read_efuse_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf);
TEE_Result versal_read_efuse_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf);
TEE_Result versal_read_efuse_sec_misc1(struct versal_efuse_sec_misc1_bits *buf);
TEE_Result versal_read_efuse_boot_env_ctrl(struct
					   versal_efuse_boot_env_ctrl_bits *buf);
TEE_Result versal_read_efuse_puf_sec_ctrl(struct
					  versal_efuse_puf_sec_ctrl_bits *buf);
TEE_Result versal_read_efuse_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id);
TEE_Result versal_read_efuse_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type);
TEE_Result versal_read_efuse_dec_only(uint32_t *buf, size_t len);
TEE_Result versal_read_efuse_dna(uint32_t *buf, size_t len);
TEE_Result versal_read_efuse_puf(struct versal_efuse_puf_header *buf);

#endif /*__DRIVERS_VERSAL_NVM_H__*/
