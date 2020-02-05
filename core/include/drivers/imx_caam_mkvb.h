#ifndef __IMX_CAAM_H_
#define __IMX_CAAM_H_

#include <tee_api_types.h>

TEE_Result caam_get_mkvb(uint8_t *dest);

/* Descriptor and MKVB Definitions */
#define MKVB_SIZE			32
#define MKVB_DESC_SEQ_OUT		0xf8000020
#define MKVB_DESC_HEADER		0xb0800004
#define MKVB_DESC_BLOB			0x870d0002

/* PRIBLOB Bits */
#define PRIBLOB_11			3

#endif // __IMX_CAAM_H_
