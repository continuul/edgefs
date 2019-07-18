/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * AES encryption/decryption using OpenSSL EVP api
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>

#include "ccowutil.h"
#include "enc_host.h"

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added
 * for taste. Fills in the encryption and decryption ctx objects and
 * returns 0 on success
 **/
int
ccowd_host_encrypt_init(const EVP_CIPHER *cipher, unsigned char *key_data,
    int key_data_len, unsigned char *salt, ccowd_host_enc_t **ctx)
{
	int i, nrounds = 5;

	*ctx = je_calloc(1, sizeof (ccowd_host_enc_t));
	if (*ctx == NULL)
		return -ENOMEM;

	(*ctx)->cipher = cipher;

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash
	 * the supplied key material.  nrounds is the number of times the we
	 * hash the material. More rounds are more secure but slower.
	 */
	i = EVP_BytesToKey(cipher, EVP_sha1(), salt, key_data,
	    key_data_len, nrounds, (*ctx)->key, (*ctx)->iv);
	if (i != 32) {
		log_error(lg, "Key size is %d bits - should be 256 bits", i);
		return -1;
	}

	return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
rtbuf_t*
ccowd_host_encrypt(ccowd_host_enc_t *ctx, rtbuf_t *rb)
{
	int len = rtbuf_len(rb);
	/* max cipherdata len for a n bytes of data is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = len + ctx->cipher_block_size, f_len = 0;
	unsigned char *cipherdata = je_malloc(c_len);
	if (cipherdata == NULL)
		return rb;

	EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(e);
	EVP_EncryptInit_ex(e, ctx->cipher, NULL, ctx->key, ctx->iv);

	c_len = 0;
	for (size_t i = 0; i < rb->nbufs; i++) {

		/* update cipherdata, enc_len is filled with the length of
		 * cipherdata generated, aggregate it in c_len */
		int enc_len;
		if (!EVP_EncryptUpdate(e, cipherdata + c_len, &enc_len,
		    (unsigned char *)rtbuf(rb, i).base, rtbuf(rb, i).len)) {
			goto _error;
		}
		c_len += enc_len;
	}

	/* update cipherdata with the final remaining bytes */
	if (!EVP_EncryptFinal_ex(e, cipherdata + c_len, &f_len)) {
		goto _error;
	}

	uv_buf_t buf = { .base = (char *)cipherdata, .len = c_len + f_len };
	rtbuf_t *rb_out = rtbuf_init(&buf, 1);
	if (!rb_out) {
		goto _error;
	}

	rtbuf_destroy(rb);

	log_debug(lg, "ENC OK %ld bytes", buf.len);

	EVP_CIPHER_CTX_cleanup(e);
	EVP_CIPHER_CTX_free(e);

	return rb_out;

_error:
	EVP_CIPHER_CTX_free(e);
	je_free(cipherdata);
	return rb;
}

/*
 * Decrypt *len bytes of cipherdata
 */
rtbuf_t*
ccowd_host_decrypt(ccowd_host_enc_t *ctx, rtbuf_t *rb)
{
	/* data will always be equal to or lesser than length of cipherdata*/
	int p_len = rtbuf_len(rb), f_len = 0;
	unsigned char *data = je_malloc(p_len);
	if (data == NULL)
		return rb;

	EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(d);
	EVP_EncryptInit_ex(d, ctx->cipher, NULL, ctx->key, ctx->iv);

	p_len = 0;
	for (size_t i = 0; i < rb->nbufs; i++) {

		/* update cipherdata, enc_len is filled with the length of
		 * data generated, aggregate it in c_len */
		int dec_len;
		if (!EVP_DecryptUpdate(d, data + p_len, &dec_len,
		    (unsigned char *)rtbuf(rb, i).base, rtbuf(rb, i).len)) {
			goto _error;
		}
		p_len += dec_len;
	}

	if (!EVP_DecryptFinal_ex(d, data + p_len, &f_len)) {
		goto _error;
	}

	uv_buf_t buf = { .base = (char *)data, .len = p_len + f_len };
	rtbuf_t *rb_out = rtbuf_init(&buf, 1);
	if (!rb_out) {
		goto _error;
	}

	rtbuf_destroy(rb);

	log_debug(lg, "DEC OK %ld bytes", buf.len);

	EVP_CIPHER_CTX_cleanup(d);
	EVP_CIPHER_CTX_free(d);

	return rb_out;

_error:
	EVP_CIPHER_CTX_free(d);
	je_free(data);
	return rb;
}

void
ccowd_host_encrypt_cleanup(ccowd_host_enc_t *ctx)
{
	je_free(ctx);
}
