// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <string.h>

#include "ipi.h"

#define __STR(X) #X
#define STR(X) __STR(X)

#define u32 uint32_t
#define u8  uint8_t

#define XSECURE_GCM_TAG_SIZE	(16U)

#define	XSECURE_AES_KEY	\
	"F878B838D8589818E868A828C8488808F070B030D0509010E060A020C0408000"
#define XSECURE_KEY_SIZE	(32)

#define	XSECURE_IV		"D2450E07EA5DE0426C0FA133"
#define XSECURE_IV_SIZE		(12)

#define XSECURE_AAD		"67e21cf3cb29e0dcbc4d8b1d0cc5334b"
#define XSECURE_AAD_SIZE	(16)

static u8 Iv[XSECURE_IV_SIZE];
static u8 Key[XSECURE_KEY_SIZE];
static u8 Aad[XSECURE_AAD_SIZE];

#define XSECURE_DATA	\
	"1234567808F070B030D0509010E060A020C0408000A5DE08D85898A5A5FEDCA10134" \
	"ABCDEF12345678900987654321123487654124456679874309713627463801AD1056"
#define XSECURE_DATA_SIZE	(68)

static uint8_t Data[XSECURE_DATA_SIZE];
static uint8_t DecData[XSECURE_DATA_SIZE];
static uint8_t EncData[XSECURE_DATA_SIZE];
static uint8_t Tag[XSECURE_GCM_TAG_SIZE];

#define XST_SUCCESS	0
#define XST_FAILURE	1

static u32 Xil_ConvertCharToNibble(u8 InChar, u8 *Num)
{
	u32 Status;

	/* Convert the char to nibble */
	if ((InChar >= (u8)'0') && (InChar <= (u8)'9')) {
		*Num = InChar - (u8)'0';
		Status = XST_SUCCESS;
	} else if ((InChar >= (u8)'a') && (InChar <= (u8)'f')) {
		*Num = InChar - (u8)'a' + 10U;
		Status = XST_SUCCESS;
	} else if ((InChar >= (u8)'A') && (InChar <= (u8)'F')) {
		*Num = InChar - (u8)'A' + 10U;
		Status = XST_SUCCESS;
	} else {
		Status = XST_FAILURE;
	}

	return Status;
}

static u32 Secure_ConvertStringToHexBE(const char *Str, u8 *Buf, u32 Len)
{
	u32 ConvertedLen = 0;
	u8 LowerNibble, UpperNibble;

	/* Check the parameters */
	if (Str == NULL)
		return XST_FAILURE;

	if (Buf == NULL)
		return XST_FAILURE;

	/* Len has to be multiple of 2 */
	if ((Len == 0) || (Len % 2 == 1))
		return XST_FAILURE;

	ConvertedLen = 0;
	while (ConvertedLen < Len) {
		/* Convert char to nibble */
		if (Xil_ConvertCharToNibble(Str[ConvertedLen],
					    &UpperNibble) == XST_SUCCESS) {
			/* Convert char to nibble */
			if (Xil_ConvertCharToNibble(
						    Str[ConvertedLen + 1],
						    &LowerNibble) == XST_SUCCESS) {
				/* Merge upper and lower nibble to Hex */
				Buf[ConvertedLen / 2] =
							(UpperNibble << 4) | LowerNibble;
			} else {
				/* Error converting Lower nibble */
				return XST_FAILURE;
			}
		} else {
			/* Error converting Upper nibble */
			return XST_FAILURE;
		}
		ConvertedLen += 2;
	}

	return XST_SUCCESS;
}

static int do_init(void)
{
	int Status;

	/* Covert strings to buffers */
	Status = Secure_ConvertStringToHexBE(
					     (const char *)(XSECURE_AES_KEY),
					     Key, XSECURE_KEY_SIZE * 2);
	if (Status != XST_SUCCESS) {
		EMSG("String Conversion error (KEY):%08x !!!\r\n", Status);
		return Status;
	}

	Status = Secure_ConvertStringToHexBE(
					     (const char *)(XSECURE_IV),
					     Iv, XSECURE_IV_SIZE * 2);
	if (Status != XST_SUCCESS) {
		EMSG("String Conversion error (IV):%08x !!!\r\n", Status);
		return Status;
	}

	Status = Secure_ConvertStringToHexBE(
					     (const char *)(XSECURE_AAD),
					     Aad, XSECURE_AAD_SIZE * 2);
	if (Status != XST_SUCCESS) {
		EMSG("String Conversion error (IV):%08x !!!\r\n", Status);
		return Status;
	}


	Status = Secure_ConvertStringToHexBE(
					     (const char *)(XSECURE_DATA),
					     Data, XSECURE_DATA_SIZE * 2);
	if (Status != XST_SUCCESS) {
		EMSG("String Conversion error (Data):%08x !!!\r\n", Status);
		return Status;
	}

	return Status;
}

#define TEE_AES_BLOCK_SIZE  16UL

static TEE_Result test_authenc_enc(void)
{
	size_t tag_len = XSECURE_GCM_TAG_SIZE;
	size_t enc_len = XSECURE_DATA_SIZE;
	TEE_Result ret = TEE_SUCCESS;
	void *ctx;

	ret = crypto_authenc_alloc_ctx(&ctx, TEE_ALG_AES_GCM);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	ret = crypto_authenc_init(ctx, TEE_MODE_ENCRYPT,
				  Key, XSECURE_KEY_SIZE,
				  Iv, XSECURE_IV_SIZE,
				  TEE_AES_BLOCK_SIZE, 0, 0);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	ret = crypto_authenc_update_aad(ctx, TEE_MODE_ENCRYPT,
					Aad, XSECURE_AAD_SIZE);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	/* ONLY ONE BLOCK
	 *  therefore we cant send an update, needs to be done in a final call
	 *  compile it out
	 */
#if 0

	ret = crypto_authenc_update_payload(ctx, TEE_MODE_ENCRYPT,
					    Data, XSECURE_DATA_SIZE);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}
#endif
	ret = crypto_authenc_enc_final(ctx,
			Data, XSECURE_DATA_SIZE,
			EncData, &enc_len,
			Tag, &tag_len);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	crypto_authenc_final(ctx);
	crypto_authenc_free_ctx(ctx);

	return TEE_SUCCESS;
}

static TEE_Result test_authenc_dec(void)
{
	size_t tag_len = XSECURE_GCM_TAG_SIZE;
	size_t dec_len = XSECURE_DATA_SIZE;
	TEE_Result ret = TEE_SUCCESS;
	void *ctx;

	ret = crypto_authenc_alloc_ctx(&ctx, TEE_ALG_AES_GCM);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	ret = crypto_authenc_init(ctx, TEE_MODE_DECRYPT,
				  Key, XSECURE_KEY_SIZE,
				  Iv, XSECURE_IV_SIZE,
				  TEE_AES_BLOCK_SIZE, 0, 0);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	ret = crypto_authenc_update_aad(ctx, TEE_MODE_ENCRYPT,
					Aad, XSECURE_AAD_SIZE);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	ret = crypto_authenc_dec_final(ctx,
				       EncData, XSECURE_DATA_SIZE,
				       DecData, &dec_len,
				       Tag, tag_len);
	if (ret) {
		EMSG("%s %d", __func__, __LINE__);
		return ret;
	}

	crypto_authenc_final(ctx);
	crypto_authenc_free_ctx(ctx);

	return TEE_SUCCESS;
}

static struct {
	TEE_Result (*f)(void);
	const char *name;
	bool failed;
} test[] = {
	{ .f = test_authenc_enc, .name = STR(auth enc), },
	{ .f = test_authenc_dec, .name = STR(auth dec), },
};

#define AES_USER_KEYS 8

static TEE_Result versal_authenc_test(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;

	/* initialize the data and the global context */
	do_init();

	for (i = 0; i < ARRAY_SIZE(test); i++) {
		ret = (test[i].f)();
		if (ret)
			test[i].failed = ret;
	}

	IMSG("Versal: Test AUTHENC");
	for (i = 0; i < ARRAY_SIZE(test); i++) {
		IMSG("---- %s:\t\t\t\t\t [%s]",
		     test[i].name,
		     test[i].failed ? "KO" : "OK");
	}

	return TEE_SUCCESS;;
}

boot_final(versal_authenc_test);
