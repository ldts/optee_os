#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

static TEE_Result ecc_test(void)
{
	struct ecc_keypair keypair = { };
	TEE_Result ret = TEE_SUCCESS;
	struct cmd_args arg = { };
	struct ipi_buf ibuf[MAX_IPI_BUF] = { };
	void *p = NULL;
	size_t len = 0;

	ret = drvcrypt_asym_alloc_ecc_keypair(&keypair,
					      TEE_TYPE_ECDSA_KEYPAIR, 1024);
	if (ret) {
		EMSG("cant alloc keypair");
		return ret;
	}

	keypair.curve = TEE_ECC_CURVE_NIST_P384;

	ret = crypto_acipher_gen_ecc_key(&keypair, 1024);
	if (ret) {
		EMSG("cant generate NIST P384");
		return ret;
	}

	len = ROUNDUP(CACHELINE_LEN,
		      crypto_bignum_num_bytes(keypair.x) +
		      crypto_bignum_num_bytes(keypair.y));

	p = memalign(CACHELINE_LEN, len);
	if (!p)
		return TEE_ERROR_GENERIC;

	crypto_bignum_bn2bin(keypair.x, p);
	crypto_bignum_bn2bin(keypair.y,
			     (uint8_t *)p + crypto_bignum_num_bytes(keypair.x));

	IMSG("Public key:");
	DHEXDUMP(p, len);

	arg.data[0] = TEE_ECC_CURVE_NIST_P384;
	arg.len = 1;

	memset(ibuf, 0, sizeof(ibuf));
	ibuf[0].p = p;
	ibuf[0].len = len;

	if (versal_crypto_request(ELLIPTIC_VALIDATE_PUBLIC_KEY, ibuf, &arg)) {
		EMSG("Failed to validate the public key");
		return TEE_ERROR_GENERIC;
	} else
		IMSG("Public key [OK]");

	return TEE_SUCCESS;
}

driver_init_late(ecc_test);
