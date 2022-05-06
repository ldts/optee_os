#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

const struct crypto_ecc_keypair_ops *soft_keypair_ops;
const struct crypto_ecc_public_ops *soft_public_ops;

#if 0
static uint32_t curve_tee2versal(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P384:
	case TEE_ECC_CURVE_NIST_P521:
		return curve;

	case TEE_ECC_CURVE_NIST_P192:
	case TEE_ECC_CURVE_NIST_P224:
	case TEE_ECC_CURVE_NIST_P256:
	default:
		EMSG("curve %#"PRIx32" not enabled", curve);
		return 0;
	}
}
#endif

static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t size_bytes)
{
	return soft_keypair_ops->generate(key, size_bytes);
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
	.alloc_keypair = do_alloc_keypair,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.gen_keypair = do_gen_keypair,
	.sign = NULL,
	.verify = NULL,
};

#define XSECURE_ECDSA_KAT_NIST_P384	0
#define XSECURE_ECDSA_KAT_NIST_P521	2

static TEE_Result ecc_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct ecc_public_key public_dummy = { };
	struct ecc_keypair pair_dummy = { };
	struct cmd_args arg = { };

	arg.len = 1;

	arg.data[0] = XSECURE_ECDSA_KAT_NIST_P384;
	if (versal_crypto_request(ELLIPTIC_KAT, NULL, &arg)) {
		EMSG("Versal KAG NIST_P384 failed");
		return TEE_ERROR_GENERIC;
	}

	arg.data[0] = XSECURE_ECDSA_KAT_NIST_P521;
	if (versal_crypto_request(ELLIPTIC_KAT, NULL, &arg)) {
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
