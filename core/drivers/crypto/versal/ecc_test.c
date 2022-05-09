// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */


#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

#define __STR(X) #X
#define STR(X) __STR(X)

static struct ecc_keypair keypair = { };
static struct ecc_public_key key = { };

/* size for TEE_ALG_ECDSA_P384 */
#define TEE_ALG_ECDSA_P384_SIG_LEN 96

size_t sig_len = TEE_ALG_ECDSA_P384_SIG_LEN;
uint8_t sig[TEE_ALG_ECDSA_P384_SIG_LEN];
uint8_t msg[48] = {
	0x89U, 0x1EU, 0x78U, 0x0AU, 0x0EU, 0xF7U, 0x8AU, 0x2BU,
	0xCBU, 0xD6U, 0x30U, 0x6CU, 0x9DU, 0x14U, 0x11U, 0x74U,
	0x5AU, 0x8BU, 0x3FU, 0x0BU, 0x5EU, 0x9FU, 0x52U, 0xC9U,
	0x99U, 0x02U, 0xEEU, 0x49U, 0x70U, 0xBCU, 0xDBU, 0x6AU,
	0x6CU, 0x83U, 0x6DU, 0x12U, 0x20U, 0x7DU, 0x05U, 0x35U,
	0x1BU, 0x6EU, 0x4FU, 0x1CU, 0x7DU, 0x18U, 0xEAU, 0x5AU,
};

static void crypto_bignum_bn2bin_eswap(struct bignum *from, uint8_t *to)
{
	uint8_t tmp = 0;
	size_t i = 0;
	size_t j = 0;

	crypto_bignum_bn2bin(from, to);
	for(i = 0, j = crypto_bignum_num_bytes(from) - 1; i < j; i++, j--) {
		tmp = to[i];
		to[i] = to[j];
		to[j] = tmp;
	}
}

static TEE_Result test_generate_signature(void)
{
	return keypair.ops->sign(TEE_ALG_ECDSA_P384, &keypair, msg, sizeof(msg),
				sig, &sig_len);
}

static TEE_Result test_validate_signature(void)
{
	return key.ops->verify(TEE_ALG_ECDSA_P384, &key, msg, sizeof(msg),
			       sig, sig_len);
}

static TEE_Result test_validate_keypair_gen(void)
{
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	struct versal_mbox_mem p = { };
	void *q = NULL;
	size_t qlen = 0;

	ret = drvcrypt_asym_alloc_ecc_keypair(&keypair,
					      TEE_TYPE_ECDSA_KEYPAIR, 1024);
	if (ret)
		return ret;

	keypair.curve = TEE_ECC_CURVE_NIST_P384;

	ret = crypto_acipher_gen_ecc_key(&keypair, 1024);
	if (ret)
		return ret;

	versal_mbox_alloc(crypto_bignum_num_bytes(keypair.x) +
			    crypto_bignum_num_bytes(keypair.y), NULL, &p);

	crypto_bignum_bn2bin_eswap(keypair.x, p.buf);
	crypto_bignum_bn2bin_eswap(keypair.y, (uint8_t *)
				   p.buf + crypto_bignum_num_bytes(keypair.x));

	arg.data[0] = TEE_ECC_CURVE_NIST_P384;
	arg.dlen = 1;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;

	if (!versal_crypto_request(ELLIPTIC_VALIDATE_PUBLIC_KEY, &arg))
		goto public;

	ret = TEE_ERROR_GENERIC;

	qlen = crypto_bignum_num_bytes(keypair.d);
	q = calloc(1, qlen);
	if (!q)
		return TEE_ERROR_GENERIC;

	crypto_bignum_bn2bin(keypair.d, q);
#if 0
	IMSG("Privat Key: d = %ld", crypto_bignum_num_bytes(keypair.d));
	DHEXDUMP(q, qlen);

	IMSG("Public Key: x = %ld", crypto_bignum_num_bytes(keypair.x));
	DHEXDUMP(p, crypto_bignum_num_bytes(keypair.x));

	IMSG("Public Key: y = %ld", crypto_bignum_num_bytes(keypair.y));
	DHEXDUMP( (uint8_t *)p + crypto_bignum_num_bytes(keypair.x),
		 crypto_bignum_num_bytes(keypair.y));
#endif
public:
	/*
	 * Create a public key for the private key so we can verify on the
	 * next test in the sequence
	 */
	if (drvcrypt_asym_alloc_ecc_public_key(&key, TEE_TYPE_ECDSA_PUBLIC_KEY,
		1024)) {
		/* panic since there is no reason to test further */
		panic();
	}
	key.curve = TEE_ECC_CURVE_NIST_P384;
	key.x = keypair.x;
	key.y = keypair.y;

	free(q);
	free(p.buf);

	return ret;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_validate_keypair_gen, .name = STR(ecc gen pair), },
	{ .f = test_generate_signature,   .name = STR(ecc gen sign), },
	{ .f = test_validate_signature,   .name = STR(ecc ver sign), },
};

static TEE_Result versal_crypto_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(test); i++) {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = true;
	}

	IMSG("Versal: Test ECC");
	for (i = 0; i < ARRAY_SIZE(test); i++) {
		IMSG("---- %s:\t\t\t\t [%s]",
		     test[i].name,
		     test[i].failed ? "KO" : "OK");
	}

	return TEE_SUCCESS;;
}

driver_init_late(versal_crypto_test);
