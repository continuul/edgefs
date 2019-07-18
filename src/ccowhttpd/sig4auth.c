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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "sig4auth.h"
#include "ccowutil.h"
#include "param.h"

#define BLOCK_LENGTH 64U
#define INNER_PAD '\x36'
#define OUTER_PAD '\x5c'

#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_HEX_LENGTH (SHA256_DIGEST_LENGTH *2)+4

#define AWS_KEY_PREFIX "AWS4"
#define AWS_ALGORITHM "AWS4-HMAC-SHA256"
#define AWS_REQUEST_TYPE "aws4_request"
#define AWS_DATE_LABEL "x-amz-date"
#define AWS_EMPTY_HASH "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define BUF_SIZE 8192


static void
sig4auth_hmac_gen(uint8_t *input_key, uint8_t key_len, uint8_t *msg,
    uint8_t hmac_out[SHA256_DIGEST_LENGTH])
{
	uint8_t key[BLOCK_LENGTH];
	uint8_t inner_key[BLOCK_LENGTH];
	uint8_t outer_key[BLOCK_LENGTH];
	EVP_MD_CTX inner_s[1];
	EVP_MD_CTX outer_s[1];
	uint8_t inner_hash[SHA256_DIGEST_LENGTH];

	memcpy(key, input_key, key_len);
	memset(key + key_len, '\0', BLOCK_LENGTH - key_len);

	for (size_t i = 0; i < BLOCK_LENGTH; i++) {
		inner_key[i] = key[i] ^ INNER_PAD;
		outer_key[i] = key[i] ^ OUTER_PAD;
	}

	EVP_MD_CTX_init(inner_s);
	if (EVP_DigestInit_ex(inner_s, EVP_sha256(), NULL) == 0)
		assert(0);
	if (EVP_DigestUpdate(inner_s, inner_key, BLOCK_LENGTH) == 0)
		assert(0);
	if (EVP_DigestUpdate(inner_s, msg, strlen((char *)msg)) == 0)
		assert(0);
	memset(inner_hash, 0, SHA256_DIGEST_LENGTH);
	if (EVP_DigestFinal_ex(inner_s, inner_hash, NULL) == 0)
		assert(0);
	EVP_MD_CTX_cleanup(inner_s);

	EVP_MD_CTX_init(outer_s);
	if (EVP_DigestInit_ex(outer_s, EVP_sha256(), NULL) == 0)
		assert(0);
	if (EVP_DigestUpdate(outer_s, outer_key, BLOCK_LENGTH) == 0)
		assert(0);
	if (EVP_DigestUpdate(outer_s, inner_hash, SHA256_DIGEST_LENGTH) == 0)
		assert(0);
	memset(hmac_out, 0, SHA256_DIGEST_LENGTH);
	if (EVP_DigestFinal_ex(outer_s, hmac_out, NULL) == 0)
		assert(0);
	EVP_MD_CTX_cleanup(outer_s);
}

static void
sig4auth_hash_sha256_hex_gen(char *in, size_t in_len, char *out)
{
	int ret;
	uint8_t digest[SHA256_DIGEST_LENGTH];

	if (EVP_Digest(in, in_len, digest, NULL, EVP_sha256(), NULL) == 0)
		assert(0);

	out[0] = '\0';
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(out, "%s%02x", out, digest[i]);
}


static int
signed_headers_parse(h2o_mem_pool_t *pool, char *signedHeaders, param_vector *params) {
	int err = param_init(pool, 16, 1, params);
	if (err)
		return -err;

	if (signedHeaders == NULL || *signedHeaders == '\0')
		return 0;


	// SignedHeaders=host;x-amz-content-sha256;x-amz-date

	char *p, *sptr;
	char *token, *peq;
	param *q;

	p = signedHeaders;
	while (1) {
		token = strtok_r(p, ";", &sptr);
		if (token == NULL)
			break;
		err = param_add(PARAM_STR(token), NULL, 0, params);
		if (err)
			return -err;
		p = NULL;
	}

	log_trace(lg, "signed_headers size: %d", params->size);
	return params->size;
}


int
sig4auth_sign_request(h2o_mem_pool_t *pool, param_vector *query_params, param_vector *headers, char *method, char *path,
    char *credential_scope, char *signedHeaders, char *secret, char *region,
    char *signature, int signature_max_size)
{
	int err = 0;
	char path_str[BUF_SIZE];

	param_sort(query_params);

	if (!path || strlen(path) == 0) {
		strcpy(path_str, "/");
	} else if (path[0] != '/') {
		sprintf(path_str, "/%s", path);
	} else {
		strcpy(path_str, path);
	}

	int n = 0;
	int res = 0;
	char query[BUF_SIZE] = "";
	char tmp[BUF_SIZE];
	int count = param_count(query_params);
	if (count > 0) {
		for (int i=0; i<count; i++) {
			param *q = param_get(i, query_params);
			sprintf(tmp, ",%s,", q->key.base);
			if (n > 0)
				strcat(query,"&");
			n++;
			strcat(query,q->key.base);
			strcat(query, "=");
			if (q->val.base != NULL) {
				res = uri_escape(q->val.base, q->val.len, tmp, BUF_SIZE, 1);
				if (res <= 0)
					return -EINVAL;
				strncat(query, tmp, res);
			}
		}
	}


	param_vector signed_headers ;
	char signed_save[BUF_SIZE];
	strcpy(signed_save, signedHeaders);

	err = signed_headers_parse(pool, signedHeaders, &signed_headers);
	if (err < 0) {
		log_error(lg, "signed headers %s parse error: %d", signedHeaders, err);
		return err;
	}
	param_sort(&signed_headers);

	// canonical headers
	char canonical_headers[BUF_SIZE] = "";
	char header[BUF_SIZE];
	int hlen = 0;
	param *q;
	param *value;

	for (int i = 0; i < signed_headers.size; i++) {
		hlen = 0;
		q = &signed_headers.pairs[i];
		memcpy(header, q->key.base, q->key.len);
		hlen += q->key.len;
		header[hlen] = ':';
		hlen++;
		header[hlen] = 0;
		value = param_find_value(q->key.base, q->key.len, headers);
		if (value && value->val.base && value->val.len > 0) {
			memcpy(header + hlen, value->val.base, value->val.len);
			hlen += value->val.len;
		} else {
			if (strcmp(header, "x-amz-content-sha256") == 0) {
				strcat(header, AWS_EMPTY_HASH);
				hlen += strlen(AWS_EMPTY_HASH);
			}
		}
		header[hlen] = '\n';
		hlen++;
		header[hlen] = 0;
		strcat(canonical_headers, header);
	}


	// Payload hash
	char hmac_payload_hex[BUF_SIZE] = AWS_EMPTY_HASH;
	value = param_find_value(H2O_STRLIT("x-amz-content-sha256"), headers);
	if (value && value->val.base && value->val.len > 0) {
		if (str_iovec(value->val, hmac_payload_hex, BUF_SIZE) != 0)
			return -EINVAL;
	}
	log_trace(lg, "payload hash: %s", hmac_payload_hex);

	// Date/time
	char datetime[BUF_SIZE] = "";
	char date[16] = "";
	value = param_find_value(H2O_STRLIT("x-amz-date"), headers);
	if (value && value->val.base && value->val.len >= 8) {
		if (str_iovec(value->val, datetime, BUF_SIZE) != 0)
			return -EINVAL;
		memcpy(date, value->val.base, 8);
		date[8] = 0;
	} else {
		log_error(lg, "no x-amz-date header");
		param_free(&signed_headers);
		return -EINVAL;
	}
	log_trace(lg, "date: %s, datetime: %s", date, datetime);


	// "AWS4-HMAC-SHA256
	// Credential=PTAA8RZIP6WJP5SRH2MS/20180214/us-west-1/s3/aws4_request,
	// SignedHeaders=host;x-amz-content-sha256;x-amz-date
	//,Signature=fd3560cd198508e84b665b86626593d1b2d9f89a5b322c61438b6c5df2d54de9"

	log_trace(lg, "credential_scope: %s", credential_scope);
	if (strstr(credential_scope, region) == NULL) {
		log_error(lg, "no region %s inside the scope %s", region, credential_scope);
		param_free(&signed_headers);
		return -EINVAL;
	}

	char canonical_request[BUF_SIZE];
	sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s", method,
	    path_str, query, canonical_headers, signed_save, hmac_payload_hex);

	log_trace(lg, "canonical request:\n%s", canonical_request);

	char hmac_canonical_request_hex[SHA256_DIGEST_HEX_LENGTH + 1];
	sig4auth_hash_sha256_hex_gen(canonical_request, strlen(canonical_request),
	    hmac_canonical_request_hex);


	char string_to_sign[BUF_SIZE];
	sprintf(string_to_sign, "%s\n%s\n%s\n%s", AWS_ALGORITHM, datetime,
	    credential_scope, hmac_canonical_request_hex);

	log_trace(lg, "string_to_sign:\n%s", string_to_sign);

	uint8_t hmac_signing_interim[SHA256_DIGEST_LENGTH + 1];
	uint8_t hmac_signing_key[SHA256_DIGEST_LENGTH + 1];
	char prefixed_secret_key[64] = AWS_KEY_PREFIX;
	strcat(prefixed_secret_key, secret);
	sig4auth_hmac_gen((uint8_t *)prefixed_secret_key,
	    (uint8_t)strlen(prefixed_secret_key), (uint8_t *)date, hmac_signing_interim);
	sig4auth_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)region, hmac_signing_interim);
	sig4auth_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)"s3", hmac_signing_interim);
	sig4auth_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)AWS_REQUEST_TYPE, hmac_signing_key);

	uint8_t hmac_signature[SHA256_DIGEST_LENGTH+1];
	sig4auth_hmac_gen((uint8_t *)&hmac_signing_key, SHA256_DIGEST_LENGTH,
	    (uint8_t *)string_to_sign, hmac_signature);
	char hmac_signature_hex[SHA256_DIGEST_HEX_LENGTH+1];

	hmac_signature_hex[0] = 0;
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(hmac_signature_hex, "%s%02x", hmac_signature_hex, hmac_signature[i] );

	memcpy(signature, hmac_signature_hex, SHA256_DIGEST_HEX_LENGTH);
	signature[SHA256_DIGEST_HEX_LENGTH] = 0;

	param_free(&signed_headers);

	return 0;
}
