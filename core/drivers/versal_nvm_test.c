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
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "drivers/versal_nvm.h"

#define __STR(X) #X
#define STR(X) __STR(X)

static TEE_Result test_read_ppk(void)
{
	uint32_t hash[8] = { 0xff };

	if (versal_read_efuse_ppk(hash, sizeof(hash), EFUSE_PPK1))
		return TEE_ERROR_GENERIC;

#if 0
	DMSG("PPK1 hash:");
	DHEXDUMP((void *)hash, sizeof(hash));
#endif

	return TEE_SUCCESS;
}

static TEE_Result test_read_iv(void)
{
	uint32_t iv[3] = { 0xff };

	if (versal_read_efuse_iv(iv, sizeof(iv), EFUSE_PLM_IV_RANGE))
		return TEE_ERROR_GENERIC;

#if 0
	DMSG("EFUSE_PLM_IV_RANGE eFuse:");
	DHEXDUMP((void *)iv, sizeof(iv));
#endif

	return TEE_SUCCESS;
}

static TEE_Result test_read_dna(void)
{
	uint32_t dna[4];

	if (versal_read_efuse_dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

#if 0
	DMSG("DNA eFuse");
	DHEXDUMP((void *)dna, sizeof(dna));
#endif

	return TEE_SUCCESS;
}

static TEE_Result test_read_user_fuses(void)
{
	uint32_t fuses[64] = { 0xff };

	if (versal_read_efuse_user(fuses, sizeof(fuses), 1, 10))
		return TEE_ERROR_GENERIC;

#if 0
	DMSG("User eFuse(s)");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif

	return TEE_SUCCESS;
}

static TEE_Result test_write_user_fuses(void)
{
#if 0
	/* the length of the source buffer must be cacheline aligned */
	uint32_t fuses[4] = { 0xab123456, 0xbc123456, 0xcd123456, 0xde123456 };

	if (versal_write_efuse_user(fuses, sizeof(fuses), 3, 4))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif

}

static TEE_Result test_read_revoke_id(void)
{
	uint32_t fuses[EFUSE_REVOCATION_ID_LEN + 1]  = { 0xff };

	memset(fuses, 0xff, sizeof(fuses));
	if (versal_read_efuse_revoke_id(fuses, sizeof(fuses),
					EFUSE_REVOCATION_ID_3))
		return TEE_ERROR_GENERIC;

#if 0
	DMSG("Revokeid");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif

	return TEE_SUCCESS;
}

static TEE_Result test_read_misc_ctrl(void)
{
	struct versal_efuse_misc_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_misc_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("Misc Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_sec_ctrl(void)
{
	struct versal_efuse_sec_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_sec_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("Sec Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_sec_misc1(void)
{
	struct versal_efuse_sec_misc1_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_sec_misc1(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("Sec Misc1");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_boot_env_ctrl(void)
{
	struct versal_efuse_boot_env_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_boot_env_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("Boot Env Ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_offchip_revoke_id(void)
{
	uint32_t fuses[EFUSE_OFFCHIP_REVOCATION_ID_LEN + 1] = { 0xff };
	enum versal_nvm_offchip_id id = EFUSE_OFFCHIP_REVOKE_ID_5;

	memset(fuses, 0xff, sizeof(fuses));
	if (versal_read_efuse_offchip_revoke_id(fuses, sizeof(fuses), id))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("Offchip revokeid");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}


static TEE_Result test_read_dec_only(void)
{
	uint32_t fuses[EFUSE_DEC_ONLY_LEN + 1] = { 0xff };

	memset(fuses, 0xff, sizeof(fuses));
	if (versal_read_efuse_dec_only(fuses, sizeof(fuses)))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("DecOnly");
	DHEXDUMP((void *)fuses, sizeof(fuses));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_puf(void)
{
	struct versal_efuse_puf_header buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_puf(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("PUF");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}

static TEE_Result test_read_puf_sec_ctrl(void)
{
	struct  versal_efuse_puf_sec_ctrl_bits buf = { };

	memset(&buf, 0xff, sizeof(buf));
	if (versal_read_efuse_puf_sec_ctrl(&buf))
		return TEE_ERROR_GENERIC;
#if 0
	DMSG("PUF sec ctrl");
	DHEXDUMP((void *)&buf, sizeof(buf));
#endif
	return TEE_SUCCESS;
}



static struct {
	TEE_Result (*f)(void);
	const char *name;
	TEE_Result failed;
} test[] = {
	{ .f = test_write_user_fuses,       .name = STR(wr usr     ),},
	{ .f = test_read_user_fuses,        .name = STR(rd usr     ),},
	{ .f = test_read_dna,               .name = STR(rd dna     ),},
	{ .f = test_read_ppk,               .name = STR(rd ppk     ),},
	{ .f = test_read_iv,                .name = STR(rd iv      ),},
	{ .f = test_read_revoke_id,         .name = STR(rd rvk     ), },
	{ .f = test_read_misc_ctrl,         .name = STR(rd misc    ), },
	{ .f = test_read_sec_ctrl,          .name = STR(rd sec ctrl), },
	{ .f = test_read_sec_misc1,         .name = STR(rd sec misc), },
	{ .f = test_read_boot_env_ctrl,     .name = STR(rd boot env), },
	{ .f = test_read_offchip_revoke_id, .name = STR(rd off rvk ), },
	{ .f = test_read_dec_only,          .name = STR(rd dec only), },
	{ .f = test_read_puf_sec_ctrl,      .name = STR(rd puf ctrl), },
	{ .f = test_read_puf,               .name = STR(rd puf), },
	{ .f = NULL, .name = "" },
};

static TEE_Result versal_nvm_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	do {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = ret;
		i++;

	} while (test[i].f);

	IMSG("Versal: Test NVM");

	for (i = 0; i < ARRAY_SIZE(test) - 1; i++)
		IMSG("---- %s:\t\t\t\t\t [%s]",
		     test[i].name, test[i].failed ?
	                    (test[i].failed == TEE_ERROR_NOT_IMPLEMENTED ? "DISABLED" : "KO") :
			    "OK");
	return TEE_SUCCESS;;
}
driver_init(versal_nvm_test);

