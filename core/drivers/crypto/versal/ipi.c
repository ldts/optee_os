
#include <arm.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

#define SEC_MODULE_SHIFT 8
#define SEC_MODULE_ID 5

#define CRYPTO_API_ID(__x) ((SEC_MODULE_ID << SEC_MODULE_SHIFT) | (__x))

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct ipi_buf *ibufs, struct cmd_args *arg)
{
	struct ipi_cmd cmd = { };
	size_t i = 0;

	cmd.data[i++] = CRYPTO_API_ID(id);
	for (i = 1; i < arg->len + 1; i++)
		cmd.data[i] = arg->data[i];

	if (!ibufs)
		goto notify;

	cmd.data[i++] = virt_to_phys(ibufs[0].p);
	cmd.data[i++] = virt_to_phys(ibufs[0].p) >> 32;

	for (i = 0; i < MAX_IPI_BUF; i++) {
		cmd.ibuf[i].len = ibufs[i].len;
		cmd.ibuf[i].p = ibufs[i].p;
	}

notify:
	return 	versal_mbox_notify(&cmd, NULL);
}

