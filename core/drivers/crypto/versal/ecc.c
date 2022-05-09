// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

/* Xilinx Versal Known Answer Tests */
#define XSECURE_ECDSA_KAT_NIST_P384	0
#define XSECURE_ECDSA_KAT_NIST_P521	2

static const struct crypto_ecc_keypair_ops *soft_keypair_ops;
static const struct crypto_ecc_public_ops *soft_public_ops;

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

static TEE_Result ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t *msg_len, struct versal_crypto_mem *p)
{
	size_t len = 0;

	switch (algo) {
	case TEE_ALG_ECDSA_P384:
		len = TEE_SHA384_HASH_SIZE;
		break;
	case TEE_ALG_ECDSA_P521:
		len = TEE_SHA512_HASH_SIZE;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	if (*msg_len >= len)
		*msg_len = len;

	versal_crypto_alloc(len, msg, p);
	*msg_len = len;

	return TEE_SUCCESS;
}

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_ecc_verify_param *cmd = NULL;
	struct versal_crypto_mem x = { };
	struct versal_crypto_mem s = { };
	struct versal_crypto_mem p = { };
	struct versal_crypto_mem cmd_buf = { };
	struct cmd_args arg = { };
	size_t key_bytes = 0;
	size_t key_bits = 0;

	ret = ecc_get_key_size(key->curve, 0, &key_bytes, &key_bits);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = ecc_prepare_msg(algo, msg, &msg_len, &p);
	if (ret)
		return ret;

	versal_crypto_alloc(crypto_bignum_num_bytes(key->x) +
			    crypto_bignum_num_bytes(key->y), NULL, &x);

	/* Public key */
	crypto_bignum_bn2bin_eswap(key->x, x.buf);
	crypto_bignum_bn2bin_eswap(key->y, (uint8_t *)
				   x.buf + crypto_bignum_num_bytes(key->x));
	/* Signature */
	versal_crypto_alloc(sig_len, sig, &s);

	/* IPI cmd */
	versal_crypto_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->signature_addr = virt_to_phys(s.buf);
	cmd->pub_key_addr = virt_to_phys(x.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = msg_len;
	cmd->curve = key->curve;

	arg.ibuf[0].buf = cmd;
	arg.ibuf[0].len = cmd_buf.alloc_len;
	arg.ibuf[1].buf = p.buf;
	arg.ibuf[1].len = p.alloc_len;
	arg.ibuf[1].only_cache = true;
	arg.ibuf[2].buf = x.buf;
	arg.ibuf[2].len = x.alloc_len;
	arg.ibuf[3].buf = s.buf;
	arg.ibuf[3].len = s.alloc_len;

	if (versal_crypto_request(ELLIPTIC_VERIFY_SIGN, &arg))
		ret = TEE_ERROR_GENERIC;

	free(p.buf);
	free(x.buf);
	free(s.buf);
	free(cmd);

	return ret;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	struct versal_ecc_sign_param *cmd = NULL;
	struct versal_crypto_mem cmd_buf = { };
	struct versal_crypto_mem p = { };
	struct versal_crypto_mem k = { };
	struct versal_crypto_mem d = { };
	struct versal_crypto_mem s = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	size_t key_bytes = 0;
	size_t key_bits = 0;

	ret = ecc_get_key_size(key->curve, 0, &key_bytes, &key_bits);
	if (ret != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = ecc_prepare_msg(algo, msg, &msg_len, &p);
	if (ret)
		return ret;

	/* Ephemeral private key */
	versal_crypto_alloc(key_bytes, NULL, &k);

	ret = crypto_rng_read(k.buf, key_bytes);
	if (ret)
		goto out;

	/* Private key*/
	versal_crypto_alloc(key_bytes, NULL, &d);
	crypto_bignum_bn2bin_eswap(key->d, d.buf);

	/* Signature */
	versal_crypto_alloc(*sig_len, NULL, &s);

	/* IPI command */
	versal_crypto_alloc(sizeof(*cmd), NULL, &cmd_buf);

	cmd = cmd_buf.buf;
	cmd->priv_key_addr = virt_to_phys(d.buf);
	cmd->epriv_key_addr = virt_to_phys(k.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = msg_len;
	cmd->curve = key->curve;

	arg.ibuf[0].buf = cmd;
	arg.ibuf[0].len = cmd_buf.alloc_len;
	arg.ibuf[1].buf = s.buf;
	arg.ibuf[1].len = s.alloc_len;
	arg.ibuf[2].buf = k.buf;
	arg.ibuf[2].len = k.alloc_len;
	arg.ibuf[3].buf = d.buf;
	arg.ibuf[3].len = d.alloc_len;
	arg.ibuf[4].buf = p.buf;
	arg.ibuf[4].len = p.alloc_len;

	if (versal_crypto_request(ELLIPTIC_GENERATE_SIGN, &arg)) {
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	memcpy(sig, s.buf, *sig_len);
out:
	free(cmd);
	free(k.buf);
	free(p.buf);
	free(s.buf);
	free(d.buf);

	return ret;
}

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	return soft_keypair_ops->shared_secret(private_key, public_key,
					       secret, secret_len);
}

static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	return shared_secret(sdata->key_priv,
			     sdata->key_pub,
			     sdata->secret.data,
			     &sdata->secret.length);
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	return sign(sdata->algo,
		    sdata->key,
		    sdata->message.data,
		    sdata->message.length,
		    sdata->signature.data,
		    &sdata->signature.length);
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	return verify(sdata->algo,
		      sdata->key,
		      sdata->message.data,
		      sdata->message.length,
		      sdata->signature.data,
		      sdata->signature.length);
}

static TEE_Result do_gen_keypair(struct ecc_keypair *keypair, size_t size_bytes)
{
	/* Versal requires little endian so need to eswap on Versal IP ops */
	return soft_keypair_ops->generate(keypair, size_bytes);
}

static TEE_Result do_alloc_keypair(struct ecc_keypair *s, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = crypto_asym_alloc_ecc_keypair(s, TEE_TYPE_ECDSA_KEYPAIR,
					    size_bits);
	if (!ret)
		s->ops = NULL;

	return ret;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = crypto_asym_alloc_ecc_public_key(s, TEE_TYPE_ECDSA_PUBLIC_KEY,
					       size_bits);
	if (!ret)
		s->ops = NULL;

	return ret;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	return soft_public_ops->free(s);
}

static struct drvcrypt_ecc driver_ecc = {
	.shared_secret = do_shared_secret,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.alloc_keypair = do_alloc_keypair,
	.gen_keypair = do_gen_keypair,
	.verify = do_verify,
	.sign = do_sign,
};

static TEE_Result ecc_init(void)
{
	struct ecc_public_key public_dummy = { };
	struct ecc_keypair pair_dummy = { };
	struct cmd_args arg = { .dlen = 1 };
	TEE_Result ret = TEE_ERROR_GENERIC;

	arg.data[0] = XSECURE_ECDSA_KAT_NIST_P384;
	arg.dlen = 1;

	if (versal_crypto_request(ELLIPTIC_KAT, &arg)) {
		EMSG("Versal KAG NIST_P384 failed");
		return TEE_ERROR_GENERIC;
	}

	arg.data[0] = XSECURE_ECDSA_KAT_NIST_P521;
	arg.dlen = 1;

	if (versal_crypto_request(ELLIPTIC_KAT, &arg)) {
		EMSG("Versal KAG NIST_P521 failed");
		return TEE_ERROR_GENERIC;
	}

	ret = crypto_asym_alloc_ecc_keypair(&pair_dummy,
					    TEE_TYPE_ECDSA_KEYPAIR, 0);
	if (ret)
		return ret;

	ret = crypto_asym_alloc_ecc_public_key(&public_dummy,
					       TEE_TYPE_ECDSA_PUBLIC_KEY, 0);
	if (ret)
		return ret;

	public_dummy.ops->free(&public_dummy);
	soft_keypair_ops = pair_dummy.ops;
	soft_public_ops = public_dummy.ops;

	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init(ecc_init);
