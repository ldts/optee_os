/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#ifndef __DRIVERS_VERSAL_PUF_H__
#define __DRIVERS_VERSAL_PUF_H__

#include <drivers/versal_mbox.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define PUF_EFUSE_SYN_WORDS 127
#define PUF_SYNDROME_WORDS 350
#define PUF_ID_WORDS 8
#define PUF_HASH_LEN 4
#define PUF_AUX_LEN 4

struct versal_puf_data {
	uint32_t syndrome_data[PUF_SYNDROME_WORDS];
	uint32_t chash;
	uint32_t aux;
	uint32_t puf_id[PUF_ID_WORDS];
	uint32_t efuse_syn_data[PUF_EFUSE_SYN_WORDS];
};

struct versal_puf_cfg {
	uint8_t reg_mode;
	uint8_t puf_operation;
	uint8_t global_var_filter;
	uint8_t read_option;
};

struct versal_puf_data_req {
	uint8_t reg_mode;
	uint8_t puf_operation;
	uint8_t global_var_filter;
	uint8_t read_option;
	uint32_t shutter_value;
	uint64_t syndrome_data_addr;
	uint64_t hash_addr;
	uint64_t aux_addr;
	uint64_t puf_id_addr;
	uint64_t syndrome_addr;
	uint64_t efuse_syn_data_addr;
	uint8_t pad[8];
}__packed ;

enum versal_puf_api {
	PUF_API_FEATURES = 0U,
	PUF_REGISTRATION,
	PUF_REGENERATION,
	PUF_CLEAR_PUF_ID,
};

#define __aligned_puf			__aligned(CACHELINE_LEN)

TEE_Result versal_puf_regenerate(struct versal_puf_data *buf,
				 struct versal_puf_cfg *cfg);
TEE_Result versal_puf_register(struct versal_puf_data *buf,
			       struct versal_puf_cfg *cfg);
TEE_Result versal_puf_check_api(enum versal_puf_api id);
TEE_Result versal_puf_clear_id(void);

#endif
