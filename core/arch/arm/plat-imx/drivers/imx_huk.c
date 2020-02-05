#include <drivers/imx_caam_mkvb.h>
#include <kernel/tee_common_otp.h>
#include <string.h>

static uint8_t stored_key[MKVB_SIZE];
static bool mkvb_retrieved;

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	int ret = TEE_ERROR_SECURITY;

	if (!mkvb_retrieved) {
		ret = caam_get_mkvb(stored_key);
		if (ret)
			return ret;
		mkvb_retrieved = true;
	}
	memcpy(&hwkey->data, &stored_key, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
