// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * The proper way to run this test would be to write the eFuses using some
 * Xilinx tool and then just memcmp the read results.
 *
 * For writing would be the inverse test.
 *
 * Foundries has validated this manually and through visual inspection of the
 * output.
 *
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

#define __STR(X) #X
#define STR(X) __STR(X)

#define HEXDUMP 0

static TEE_Result efuse_read_ppk(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t hash[8] = { 0xff };

	if (ops->read->ppk(hash, sizeof(hash), EFUSE_PPK1))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("PPK1 hash:");
	DHEXDUMP((void *)hash, sizeof(hash));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_iv(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t iv[3] = { 0xff };

	if (ops->read->iv(iv, sizeof(iv), EFUSE_PLM_IV_RANGE))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("EFUSE_PLM_IV_RANGE eFuse:");
	DHEXDUMP((void *)iv, sizeof(iv));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_dna(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t dna[4] = { 0 };

	if (ops->read->dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

#if HEXDUMP
	DMSG("DNA eFuse");
	DHEXDUMP((void *)dna, sizeof(dna));
	DMSG("DNA: 0x%x.0x%x.0x%x.0x%x", dna[0], dna[1], dna[2], dna[3]);
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_user_data(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t fuses[64] = { 0xff };

	if (ops->read->user_data(fuses, sizeof(fuses), 1, 10))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("User eFuse(s)");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_write_user_data(void)
{
#if 0
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	/* the length of the source buffer must be cacheline aligned */
	uint32_t fuses[4] = { 0xab123456, 0xbc123456, 0xcd123456, 0xde123456 };

	if (ops->write->user_data(fuses, sizeof(fuses), 3, 4))
	return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif

}

static TEE_Result efuse_write_revoke_id(void)
{
#if 0
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();

	/* write revocation REVOCATION_ID_2 bit 0*/
	if (ops->write->revoke_id(64))
	    return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif

}

static TEE_Result efuse_write_aes_key_user_1(void)
{
#if 0
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_aes_keys keys = { };
#if 0
	uint8_t fuses[] = {
		0xf8, 0x78, 0xb8, 0x38, 0xd8, 0x58, 0x98, 0x18, 0xe8, 0x68,
		0xa8, 0x28, 0xc8, 0x48, 0x88, 0x08, 0xf0, 0x70, 0xb0, 0x30,
		0xd0, 0x50, 0x90, 0x10, 0xe0, 0x60, 0xa0, 0x20, 0xc0, 0x40,
		0x80, 0x00,
	};
#else
	/* the PLM is little endian so we would need to BSWAP in this format */
	uint32_t fuses[8] = {
		0xf878b838, 0xd8589818, 0xe868a828, 0xc8488808,
		0xf070b030, 0xd0509010, 0xe060a020, 0xc0408000,
	};

	for (size_t i = 0; i < 8; i++)
	fuses[i] = TEE_U32_BSWAP(fuses[i]);
#endif
	keys.prgm_user_key1 = 1;
	memcpy(keys.user_key1, fuses, sizeof(fuses));

	if (ops->write->aes_keys(&keys))
	return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

static TEE_Result efuse_write_aes_key_bbram(void)
{
	struct versal_bbram_ops const *ops = versal_get_bbram_ops();
#if 0
	uint8_t fuses[] = {
		0xf8, 0x78, 0xb8, 0x38, 0xd8, 0x58, 0x98, 0x18, 0xe8, 0x68,
		0xa8, 0x28, 0xc8, 0x48, 0x88, 0x08, 0xf0, 0x70, 0xb0, 0x30,
		0xd0, 0x50, 0x90, 0x10, 0xe0, 0x60, 0xa0, 0x20, 0xc0, 0x40,
		0x80, 0x00,
	};
#else
	/* the PLM is little endian so we would need to BSWAP in this format */
	uint32_t fuses[8] = {
		0xf878b838, 0xd8589818, 0xe868a828, 0xc8488808,
		0xf070b030, 0xd0509010, 0xe060a020, 0xc0408000,
	};

	for (size_t i = 0; i < 8; i++)
		fuses[i] = TEE_U32_BSWAP(fuses[i]);
#endif

	if (ops->write->aes_key((uint8_t *)fuses, sizeof(fuses)))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result efuse_read_revoke_id(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t fuses[2] = { 0xff };

	memset(fuses, 0xff, sizeof(fuses));
	if (ops->read->revoke_id(fuses, sizeof(fuses), EFUSE_REVOCATION_ID_2))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Revokeid (last workd should be 0xff)");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_misc_ctrl(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_misc_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->misc_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Misc Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_sec_ctrl(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_sec_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->sec_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Sec Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_sec_misc1(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_sec_misc1_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->sec_misc1(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Sec Misc1");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_boot_env_ctrl(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_boot_env_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->boot_env_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Boot Env Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_offchip_revoke_id(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t fuses[2] = { 0xff };
	enum versal_nvm_offchip_id id = EFUSE_OFFCHIP_REVOKE_ID_5;

	memset(fuses, 0xff, sizeof(fuses));
	if (ops->read->offchip_revoke_id(fuses, sizeof(fuses), id))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("Offchip revokeid (last word should be 0xff)");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}


static TEE_Result efuse_read_dec_only(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	uint32_t fuses[2] = { 0xff };

	memset(fuses, 0xff, sizeof(fuses));
	if (ops->read->dec_only(fuses, sizeof(fuses)))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("DecOnly (last word should be 0xff");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_puf(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_puf_header buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->puf(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("PUF");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_read_puf_sec_ctrl(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct  versal_efuse_puf_sec_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (ops->read->puf_sec_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("PUF sec ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result bbram_read_write_user(void)
{
	struct versal_bbram_ops const *ops = versal_get_bbram_ops();
	uint32_t user = 10;

	if (ops->write->user_data(user))
		return TEE_ERROR_GENERIC;

	user = 0;
	if (ops->read->user_data(&user))
		return TEE_ERROR_GENERIC;

	if (user != 10)
		return TEE_ERROR_GENERIC;
#if HEXDUMP
	DMSG("BBRAM user data");
	DMSG(" - 0x%x", user);
#endif
	return TEE_SUCCESS;
}

static TEE_Result efuse_write_puf_as_user_fuse(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_puf_user_fuse user_fuse = { };

	for (size_t i = 0; i < PUF_EFUSES_WORDS; i++)
		user_fuse.data_addr[i] = i;

	user_fuse.num_rows = PUF_EFUSES_WORDS - 1;
	user_fuse.env_monitor_dis = 1;
	user_fuse.prgm_puf_fuse = 0;
	user_fuse.start_row = 1;

	if (ops->write->puf_as_user_fuse(&user_fuse))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result efuse_read_puf_as_user_fuse(void)
{
	struct versal_efuse_ops const *ops = versal_get_efuse_ops();
	struct versal_efuse_puf_user_fuse user_fuse = { };

	user_fuse.num_rows = PUF_EFUSES_WORDS - 1;
	user_fuse.env_monitor_dis = 1;
	user_fuse.prgm_puf_fuse = 0;
	user_fuse.start_row = 1;

	if (ops->read->puf_as_user_fuse(&user_fuse))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	TEE_Result failed;
}
test[] = {
	/* add to the bottom or update PUF_AS_USE_FUSE and PUF ids in main */
	{ .f = efuse_write_puf_as_user_fuse, .name = STR(EFUSE wr puf userf), },
	{ .f = efuse_write_aes_key_bbram,    .name = STR(EFUSE wr aes bbram), },
	{ .f = efuse_write_aes_key_user_1,   .name = STR(EFUSE wr aes usr1), },
	{ .f = efuse_write_user_data,        .name = STR(EFUSE wr usr), },
	{ .f = efuse_write_revoke_id,        .name = STR(EFUSE wr revoke id), },
	{ .f = efuse_read_puf_as_user_fuse,  .name = STR(EFUSE rd puf userf), },
	{ .f = efuse_read_user_data,         .name = STR(EFUSE rd usr), },
	{ .f = efuse_read_dna,               .name = STR(EFUSE rd dna), },
	{ .f = efuse_read_ppk,               .name = STR(EFUSE rd ppk), },
	{ .f = efuse_read_iv,                .name = STR(EFUSE rd iv data), },
	{ .f = efuse_read_revoke_id,         .name = STR(EFUSE rd rvk), },
	{ .f = efuse_read_misc_ctrl,         .name = STR(EFUSE rd misc), },
	{ .f = efuse_read_sec_ctrl,          .name = STR(EFUSE rd sec ctrl), },
	{ .f = efuse_read_sec_misc1,         .name = STR(EFUSE rd sec misc), },
	{ .f = efuse_read_boot_env_ctrl,     .name = STR(EFUSE rd boot env), },
	{ .f = efuse_read_offchip_revoke_id, .name = STR(EFUSE rd off rvk), },
	{ .f = efuse_read_dec_only,          .name = STR(EFUSE rd dec only), },
	{ .f = efuse_read_puf_sec_ctrl,      .name = STR(EFUSE rd puf ctrl), },
	{ .f = efuse_read_puf,               .name = STR(EFUSE rd puf), },
	{ .f = bbram_read_write_user,        .name = STR(BBRAM RD / WR usr), },
	{.f = NULL, .name = ""},
};

static TEE_Result versal_nvm_test(void) {
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;
	uint32_t const PUF_AS_USE_FUSE = 0;
	uint32_t const PUF = 17;

	do {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = ret;
		i++;

	} while (test[i].f);


	if (test[PUF_AS_USE_FUSE].failed && !test[PUF].failed)
		test[PUF_AS_USE_FUSE].failed = TEE_ERROR_NOT_IMPLEMENTED;
	else if (!test[PUF_AS_USE_FUSE].failed && test[PUF].failed)
		test[PUF].failed = TEE_ERROR_NOT_IMPLEMENTED;

	IMSG("Versal: Test NVM");
	for (i = 0; i < ARRAY_SIZE(test) - 1; i++)
		IMSG("---- %s:\t\t\t\t [%s]",
		     test[i].name, test[i].failed ?
		     (test[i].failed == TEE_ERROR_NOT_IMPLEMENTED ? "DISABLED" : "KO") :
		     "OK");
	return TEE_SUCCESS;;
}
driver_init(versal_nvm_test);

