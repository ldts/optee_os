// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include "crypto/aes.h"
#include "crypto/aes_cmac.h"
#include "fsl_sss_ftr.h"
#include "fsl_sss_user_apis.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAC_BLOCK_SIZE 16

static bool is_null(int count, ...)
{
	va_list ap;
	int i = 0;

	va_start(ap, count);
	for (i = 0; i < count; i++) {
		if (!va_arg(ap, void *))
			break;
	}
	va_end(ap);

	if (i < count)
		return true;

	return false;
}

/* readability */
#define USR_FUNC(_x) sss_user_impl_ ##_x

/*
 * Session
 */
sss_status_t USR_FUNC(session_open)(sss_user_impl_session_t *s,
				    sss_type_t subsystem,
				    uint32_t application_id __unused,
				    sss_connection_type_t type,
				    void *data __unused)
{
	if (!s || type != kSSS_ConnectionType_Plain)
		return kStatus_SSS_Fail;

	memset(s, 0, sizeof(*s));
	s->subsystem = subsystem;

	return kStatus_SSS_Success;
}

void USR_FUNC(session_close)(sss_user_impl_session_t *session)
{
	if (session)
		memset(session, 0, sizeof(*session));
}

/*
 * Key object
 */
sss_status_t USR_FUNC(key_object_init)(sss_user_impl_object_t *key,
				       sss_user_impl_key_store_t *store)
{
	if (is_null(2, key, store))
		return kStatus_SSS_Fail;

	memset(key, 0, sizeof(*key));
	key->keyStore = store;

	return kStatus_SSS_Success;
}

void USR_FUNC(key_object_free)(sss_user_impl_object_t *p)
{
	if (!p)
		return;

	if (p->contents) {
		free(p->contents);
		p->contents = NULL;
		p->contents_size = 0;
	}

	memset(p, 0, sizeof (*p));
}

sss_status_t USR_FUNC(key_object_allocate_handle)(sss_user_impl_object_t *key,
						  uint32_t key_id,
						  sss_key_part_t key_part,
						  sss_cipher_type_t type,
						  size_t len,
						  uint32_t options)
{
	if (is_null(2, key, len))
		return  kStatus_SSS_Fail;

	key->contents = calloc(1, len);
	if (!key->contents)
		return kStatus_SSS_Fail;

	key->contents_size = len;

	return kStatus_SSS_Success;
}

/*
 * Key Store
 */
sss_status_t USR_FUNC(key_store_context_init)(sss_user_impl_key_store_t *store,
					      sss_user_impl_session_t *s)
{
	if (is_null(2, s, store))
		return kStatus_SSS_Fail;

	memset(store, 0, sizeof(*store));
	store->session = s;

	return kStatus_SSS_Success;
}

void USR_FUNC(key_store_context_free)(sss_user_impl_key_store_t *store)
{
	if (store)
		memset(store, 0, sizeof(*store));
}

sss_status_t USR_FUNC(key_store_allocate)(sss_user_impl_key_store_t *store,
					  uint32_t id __unused)
{
	if (is_null(2, store, store->session))
		return kStatus_SSS_Fail;

	return  kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_set_key)(sss_user_impl_key_store_t *store,
					 sss_user_impl_object_t *key,
					 const uint8_t *data,
					 size_t data_len,
					 size_t key_len __unused,
					 void *options __unused,
					 size_t options_len __unused)
{
	if (is_null(2, data, key) || data_len > key->contents_size)
		return kStatus_SSS_Fail;

	memcpy(key->key, data, data_len);
	key->contents_size = data_len;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_get_key)(sss_user_impl_key_store_t *store,
					 sss_user_impl_object_t *key,
					 uint8_t *data, size_t *data_len,
					 size_t *key_len)
{
	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(key_store_generate_key)(sss_user_impl_key_store_t *s,
					      sss_user_impl_object_t *k,
					      size_t len, void *options)
{
	return kStatus_SSS_Fail;
}

/*
 * Cipher
 */
sss_status_t USR_FUNC(cipher_one_go)(sss_user_impl_symmetric_t *context,
				     uint8_t *iv, size_t iv_len,
				     const uint8_t *src, uint8_t *dst,
				     size_t data_len)
{
	uint8_t buffer[AES_BLOCKSIZE] = { 0 };
	size_t i = 0;

	if (is_null(4, context, iv, src, dst) || (data_len % AES_BLOCKSIZE))
		return kStatus_SSS_Fail;

	if (context->mode == kMode_SSS_Encrypt) {
		while (data_len > 0) {
			memcpy(buffer, src, AES_BLOCKSIZE);

			for (i = 0; i < AES_BLOCKSIZE; i++)
				buffer[i] ^= iv[i];

			AES_encrypt(context->aes, buffer, dst);
			memcpy(iv, dst, AES_BLOCKSIZE);

			src += AES_BLOCKSIZE;
			dst += AES_BLOCKSIZE;

			data_len -= AES_BLOCKSIZE;
		}
		return kStatus_SSS_Success;
	}

	if (context->mode == kMode_SSS_Decrypt) {
		while (data_len > 0) {
			memcpy(buffer, src, AES_BLOCKSIZE);

			AES_decrypt(context->aes, buffer, dst);

			for (i = 0; i < AES_BLOCKSIZE; i++)
				dst[i] ^= iv[i];

			memcpy(iv, buffer, AES_BLOCKSIZE);

			src += AES_BLOCKSIZE;
			dst += AES_BLOCKSIZE;

			data_len -= AES_BLOCKSIZE;
		}
		return kStatus_SSS_Success;
	}

	return kStatus_SSS_Fail;
}

/*
 * Mac
 */
sss_status_t USR_FUNC(mac_context_init)(sss_user_impl_mac_t *context,
					sss_user_impl_session_t *session,
					sss_user_impl_object_t *key,
					sss_algorithm_t algorithm,
					sss_mode_t mode)
{
	SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));

	if (is_null(2, context, key))
		return kStatus_SSS_Fail;

	memset(context, 0, sizeof(*context));
	context->keyObject = key;

	context->aes = AES_ctx_alloc(key->key, sizeof(key->key));
	if (!context->aes)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

void USR_FUNC(mac_context_free)(sss_user_impl_mac_t *context)
{
	if (!context)
		return;

	if (context->aes) {
		memset(context->aes, 0, sizeof(*context->aes));
		free(context->aes);
	}

	memset(context->calc_mac, 0, MAC_BLOCK_SIZE);
	memset(context->cache_data, 0, MAC_BLOCK_SIZE);
}

sss_status_t USR_FUNC(mac_init)(sss_user_impl_mac_t *context)
{
	if (!context)
		return kStatus_SSS_Fail;

	memset(context->calc_mac, 0, sizeof(*context->calc_mac));
	memset(context->cache_data, 0, sizeof(*context->cache_data));
	context->cache_len = 0;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_update)(sss_user_impl_mac_t *context,
				  const uint8_t *msg, size_t msg_len)
{
	uint8_t input[MAC_BLOCK_SIZE] = { 0 };
	uint8_t mac[MAC_BLOCK_SIZE] = { 0 };
	size_t n = 0, i = 0;

	if (!context)
		return kStatus_SSS_Fail;

	SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));

	if (context->cache_len > 0 &&
	    msg_len > (MAC_BLOCK_SIZE - context->cache_len)) {
		memcpy(&context->cache_data[context->cache_len], msg,
		       MAC_BLOCK_SIZE - context->cache_len);

		aes_cmac_update(context->aes, context->cache_data,
				context->calc_mac, MAC_BLOCK_SIZE,
				context->keyObject->key, mac);

		memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);

		msg += MAC_BLOCK_SIZE - context->cache_len;
		msg_len -= MAC_BLOCK_SIZE - context->cache_len;
		context->cache_len = 0;
	}

	n = (msg_len + MAC_BLOCK_SIZE - 1) / MAC_BLOCK_SIZE;

	for (i = 1; i < n; i++) {
		memcpy(input, msg, MAC_BLOCK_SIZE);

		aes_cmac_update(context->aes, input, context->calc_mac,
				MAC_BLOCK_SIZE, context->keyObject->key, mac);

		memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);
		msg_len -= MAC_BLOCK_SIZE;
		msg += MAC_BLOCK_SIZE;
	}

	if (msg_len) {
		memcpy(context->cache_data, msg, msg_len);
		context->cache_len += msg_len;
	}

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_finish)(sss_user_impl_mac_t *context,
				  uint8_t *mac, size_t *len)
{
	uint8_t input[MAC_BLOCK_SIZE] = { 0 };

	if (is_null(3, context, mac, len))
		return kStatus_SSS_Fail;

	memcpy(input, context->cache_data, context->cache_len);

	aes_cmac_finish(context->aes, input, context->calc_mac,
			context->cache_len, context->keyObject->key, mac);

	*len = MAC_BLOCK_SIZE;

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(mac_one_go)(sss_user_impl_mac_t *context,
				  const uint8_t *msg, size_t msg_len,
				  uint8_t *mac, size_t *mac_len)
{
	uint8_t input[1024] = { 0 };

	if (!context)
		return kStatus_SSS_Fail;

	memcpy(input, msg, msg_len);

	aes_cmac(input, msg_len, context->keyObject->key, mac);

	*mac_len = AES_BLOCKSIZE;

	return kStatus_SSS_Success;
}

/*
 * Symmetric
 */
sss_status_t USR_FUNC(symmetric_context_init)(sss_user_impl_symmetric_t *c,
					      sss_user_impl_session_t *s,
					      sss_user_impl_object_t *key,
					      sss_algorithm_t algorithm,
					      sss_mode_t mode)
{
	if (is_null(3, c, s, key))
		return kStatus_SSS_Fail;

	SSS_ASSERT(sizeof(sss_user_impl_symmetric_t) <=
		   sizeof(sss_symmetric_t));

	c->session = s;
	c->keyObject = key;
	c->algorithm = algorithm;
	c->mode = mode;

	c->aes = AES_ctx_alloc(key->key, sizeof(key->key));
	if (!c->aes)
		return kStatus_SSS_Fail;

	return kStatus_SSS_Success;
}

void USR_FUNC(symmetric_context_free)(sss_user_impl_symmetric_t *context)
{
	if (!context->aes)
		return;

	free(context->aes);
	context->aes = NULL;
}

/*
 * Derive key
 */
sss_status_t USR_FUNC(derive_key_context_init)(sss_user_impl_derive_key_t *dk,
					       sss_user_impl_session_t *s,
					       sss_user_impl_object_t *k,
					       sss_algorithm_t algorithm,
					       sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(derive_key_go)(sss_user_impl_derive_key_t *context,
				     const uint8_t *salt, size_t salt_len,
				     const uint8_t *info, size_t info_len,
				     sss_user_impl_object_t *p, uint16_t d,
				     uint8_t *h, size_t *h_len)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(derive_key_dh)(sss_user_impl_derive_key_t *context,
				     sss_user_impl_object_t *p,
				     sss_user_impl_object_t *q)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(derive_key_context_free)(sss_user_impl_derive_key_t *context)
{
}

/*
 * Asymmetric
 */
sss_status_t USR_FUNC(asymmetric_context_init)(sss_user_impl_asymmetric_t *c,
					       sss_user_impl_session_t *s,
					       sss_user_impl_object_t *k,
					       sss_algorithm_t algorithm,
					       sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(asymmetric_context_free)(sss_user_impl_asymmetric_t *context)
{
}

sss_status_t USR_FUNC(asymmetric_sign_digest)(sss_user_impl_asymmetric_t *c,
					      uint8_t *dgst, size_t dgst_len,
					      uint8_t *sig, size_t *sig_len)
{
	return kStatus_SSS_Fail;
}

/*
 * Digest
 */
sss_status_t USR_FUNC(digest_context_init)(sss_user_impl_digest_t *context,
					   sss_user_impl_session_t *session,
					   sss_algorithm_t algorithm,
					   sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t USR_FUNC(digest_one_go)(sss_user_impl_digest_t *context,
				     const uint8_t *m, size_t m_len,
				     uint8_t *d, size_t *d_len)
{
	return kStatus_SSS_Fail;
}

void USR_FUNC(digest_context_free)(sss_user_impl_digest_t *context)
{
}

/*
 * RNG
 */
sss_status_t USR_FUNC(rng_context_free)(sss_user_impl_rng_context_t *context)
{
	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(rng_context_init)(sss_user_impl_rng_context_t *context,
					sss_user_impl_session_t *session)
{
	srand(time(NULL));

	return kStatus_SSS_Success;
}

sss_status_t USR_FUNC(rng_get_random)(sss_user_impl_rng_context_t *context,
				      uint8_t *data, size_t len)
{
	size_t i = 0;

	if (!context)
		return kStatus_SSS_Fail;

	for (i = 0; i < len; i++)
		data[i] = (uint8_t)rand();

	return kStatus_SSS_Success;
}
