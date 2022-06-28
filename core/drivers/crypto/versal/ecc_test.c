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


/* size for TEE_ALG_ECDSA_P521 */
#define TEE_ALG_ECDSA_P521_SIG_LEN 132
size_t sig_len_521 = TEE_ALG_ECDSA_P521_SIG_LEN;
uint8_t sig_521[TEE_ALG_ECDSA_P521_SIG_LEN];
uint8_t hash521[66] = {
	0x32U, 0xF9U, 0xE1U, 0x0BU, 0xE6U, 0x1DU, 0xF7U, 0xB6U,
	0xA8U, 0x67U, 0x17U, 0x58U, 0x8EU, 0x6DU, 0xD6U, 0xC0U,
	0x72U, 0x91U, 0xCDU, 0xDDU, 0x6CU, 0xBDU, 0xBEU, 0x2FU,
	0x13U, 0xFAU, 0x02U, 0x5BU, 0x02U, 0x90U, 0xAFU, 0x32U,
	0x5DU, 0x20U, 0x09U, 0xA7U, 0x1CU, 0x2CU, 0x58U, 0x94U,
	0x9FU, 0xBBU, 0x75U, 0xDCU, 0xE1U, 0x8DU, 0x36U, 0xD7U,
	0xCEU, 0xB1U, 0xB6U, 0x7CU, 0x7FU, 0xB7U, 0x25U, 0xF9U,
	0x00U, 0x1EU, 0xA3U, 0xEDU, 0xDEU, 0xE1U, 0xF0U, 0x9BU,
	0x00U, 0x00U,
};

static TEE_Result ecc_get_key_size(uint32_t curve, uint32_t algo,
				   size_t *bytes, size_t *bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		if (algo && algo != TEE_ALG_ECDSA_P384 &&
			algo != TEE_ALG_ECDH_P384)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		if (algo && algo != TEE_ALG_ECDSA_P521 &&
			algo != TEE_ALG_ECDH_P521)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static void crypto_bignum_bn2bin_eswap(uint32_t curve,
				       struct bignum *from, uint8_t *to)
{
	uint8_t tmp = 0;
	uint8_t pad[66] = { 0 };
	size_t i = 0;
	size_t j = 0;
	size_t len = crypto_bignum_num_bytes(from);
	size_t bytes = 0;
	size_t bits = 0;

	if (ecc_get_key_size(curve, 0, &bytes, &bits))
		panic();

	crypto_bignum_bn2bin(from, pad + bytes - len);
	for (i = 0, j = bytes - 1; i < j; i++, j--) {
		tmp = pad[i];
		pad[i] = pad[j];
		pad[j] = tmp;
	}
	memcpy(to, pad, bytes);
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

	ret = drvcrypt_asym_alloc_ecc_keypair(&keypair,
					      TEE_TYPE_ECDSA_KEYPAIR, 1024);
	if (ret)
		return ret;

	keypair.curve = TEE_ECC_CURVE_NIST_P384;
	ret = crypto_acipher_gen_ecc_key(&keypair, 1024);
	if (ret)
		return ret;

	versal_mbox_alloc(48 * 2, NULL, &p);
	crypto_bignum_bn2bin_eswap(TEE_ECC_CURVE_NIST_P384, keypair.x, p.buf);
	crypto_bignum_bn2bin_eswap(TEE_ECC_CURVE_NIST_P384, keypair.y,
				   (uint8_t *)p.buf + 48);
	arg.data[0] = TEE_ECC_CURVE_NIST_P384;
	arg.dlen = 1;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;
	if (versal_crypto_request(ELLIPTIC_VALIDATE_PUBLIC_KEY, &arg, NULL))
		panic();

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

static TEE_Result test_generate_signature_521(void)
{
	return keypair.ops->sign(TEE_ALG_ECDSA_P521, &keypair,
				 hash521, sizeof(hash521),
				 sig_521, &sig_len_521);
}

static TEE_Result test_validate_signature_521(void)
{
	return key.ops->verify(TEE_ALG_ECDSA_P521, &key,
			       hash521, sizeof(hash521),
			       sig_521, sig_len_521);
}

static TEE_Result test_validate_keypair_gen_521(void)
{
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	struct versal_mbox_mem p = { };
	void *q = NULL;

	ret = drvcrypt_asym_alloc_ecc_keypair(&keypair,
					      TEE_TYPE_ECDSA_KEYPAIR, 4096);
	if (ret)
		return ret;

	keypair.curve = TEE_ECC_CURVE_NIST_P521;
	ret = crypto_acipher_gen_ecc_key(&keypair, 4096);
	if (ret)
		return ret;

	versal_mbox_alloc(66 * 2, NULL, &p);

	crypto_bignum_bn2bin_eswap(TEE_ECC_CURVE_NIST_P521, keypair.x, p.buf);
	crypto_bignum_bn2bin_eswap(TEE_ECC_CURVE_NIST_P521, keypair.y,
				   (uint8_t *)p.buf + 66);
	arg.data[0] = TEE_ECC_CURVE_NIST_P521;
	arg.dlen = 1;
	arg.ibuf[0].buf = p.buf;
	arg.ibuf[0].len = p.alloc_len;
	if (versal_crypto_request(ELLIPTIC_VALIDATE_PUBLIC_KEY, &arg, NULL))
		panic();

	/*
	 * Create a public key for the private key so we can verify on the
	 * next test in the sequence
	 */
	if (drvcrypt_asym_alloc_ecc_public_key(&key, TEE_TYPE_ECDSA_PUBLIC_KEY,
		4096)) {
		/* panic since there is no reason to test further */
		panic();
	}

	key.curve = TEE_ECC_CURVE_NIST_P521;
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
	{ .f = test_validate_keypair_gen, .name = STR(ecc-384 genpair), },
	{ .f = test_generate_signature,   .name = STR(ecc-384 sign), },
	{ .f = test_validate_signature,   .name = STR(ecc-384 verify), },
	{ .f = test_validate_keypair_gen_521, .name = STR(ecc-521 genpair), },
	{ .f = test_generate_signature_521,   .name = STR(ecc-521 sign), },
	{ .f = test_validate_signature_521,   .name = STR(ecc-521 verify), },
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
