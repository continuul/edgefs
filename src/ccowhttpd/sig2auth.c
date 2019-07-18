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
#include "sig2auth.h"
#include "ccowutil.h"
#include "param.h"

#define QSTRINGS ",acl,torrent,logging,location,policy,requestPayment,versioning,"\
            "versions,versionId,notification,uploadId,uploads,partNumber,website,"\
            "delete,lifecycle,tagging,cors,restore,replication,accelerate,"\
            "inventory,analytics,metrics,"\
            "response-cache-control,response-content-disposition,response-content-encoding,"\
            "response-content-language,response-content-type,response-expires,"
#define BUF_SIZE 16384


/**
* Function to compute the sha1 digest
*
*/
static int hmac_sha1(const uint8_t *secret,  /* secret key */
        int secret_len,    /* length of the key in bytes */
        const uint8_t *data,  /* data */
        size_t data_len,       /* length of data in bytes */
        uint8_t *out,      /* output buffer */
		unsigned int *out_len) { // output buffer length
	if (HMAC(EVP_sha1(), secret, secret_len, data, data_len, out, out_len) == NULL) {
	    return EINVAL;
	}

    return 0;
}

static int b64_encode_buffer(const unsigned char* buffer, size_t length,
		char *out, size_t out_length)
{
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	size_t output_length = (*bufferPtr).length;
	if (output_length > out_length)
		return EINVAL;
	out[output_length] = 0;
	memcpy(out, (*bufferPtr).data, output_length);
	BIO_free_all(bio);

	return 0;
}


int sig2auth_sign_request(param_vector *query_param, param_vector *headers, char *method,
    char *path, char *secret, char *signature, int signature_max_size) {
	int err = 0;

	param_sort(query_param);
	param_sort(headers);

	param *md5 = param_find_value(H2O_STRLIT("content-md5"), headers);
	param *content_type = param_find_value(H2O_STRLIT("content-type"), headers);
	param *date = param_find_value(H2O_STRLIT("date"), headers);
	param *amz_date = param_find_value(H2O_STRLIT("x-amz-date"), headers);
	param *expires = param_find_value(H2O_STRLIT("expires"), headers);

	if (amz_date) {
		date = NULL;
	}
	if (expires) {
		date = expires;
	}

	char out[BUF_SIZE] = "";
	char tmp[2048] = "";

	sprintf(out, "%s\n%s\n%s\n%s\n",
	    method,
	    (md5 != NULL ? md5->val.base : ""),
	    (content_type != NULL ? content_type->val.base : ""),
	    (date != NULL ? date->val.base : "")
	    );


	// Add amz headers
	int count = param_count(headers);
	if (count > 0) {
		for (int i=0; i<count; i++) {
			param *h = param_get(i, headers);
			if (h) {
				if (!strstr(h->key.base,"x-amz-"))
					continue;
				sprintf(tmp, "%s:%s\n",
				    h->key.base,
				    (h->val.base != NULL ? h->val.base : "")
				    );
				strcat(out, tmp);
			}
		}
	}

	// canonical request
	if (path == NULL || *path == '\0') {
		strcat(out, "/");
	} else {
		if (path[0] != '/') {
			strcat(out, "/");
		}
		strcat(out, path);
	}

	int n = 0;
	char query[BUF_SIZE] = "";
	count = param_count(query_param);
	if (count > 0) {
		for (int i=0; i<count; i++) {
			param *q = param_get(i, query_param);
			sprintf(tmp, ",%s,", q->key.base);
			if (!strstr(QSTRINGS, tmp))
				continue;
			if (n > 0)
				strcat(query,"&");
			n++;
			strcat(query,q->key.base);
			if (q->val.base != NULL) {
				strcat(query, "=");
				strcat(query, q->val.base);
			}
		}
	}
	if (n > 0) {
		strcat(out,"?");
		strcat(out, query);
	}

	log_trace(lg, "string to sign:\n%s\n", out);

	int len = strlen(out);

	unsigned int out_len;

	uint8_t hmac_out[EVP_MAX_MD_SIZE];
	err = hmac_sha1((uint8_t *)secret,  /* secret key */
	    (uint8_t)strlen(secret),       /* length of the key in bytes */
	    (uint8_t *)out,  /* data */
	    (size_t) len,       /* length of data in bytes */
	    hmac_out,      /* output buffer */
	    &out_len);
	if (err)
		return err;

	err = b64_encode_buffer(hmac_out, out_len, signature, signature_max_size);
	return err;
}


int query_sign_request(param_vector *query_param, char *method,
    char *path, char *secret, char *signature, int signature_max_size) {
	int err = 0;


	long expires = param_find_long(H2O_STRLIT("Expires"), 0, query_param);
	long current = (long) get_timestamp_us()/1000000;

	log_trace(lg, "path %s, expires %ld: current: %ld", path, expires, current);

	if (secret == NULL) {
		log_error(lg, "Secret undefined");
		return -EINVAL;
	}

	if (expires < current) {
		log_error(lg, "link too old");
		return -EINVAL;
	}

	char out[BUF_SIZE] = "";
	char tmp[2048] = "";

	if (!path || strlen(path) == 0) {
		sprintf(out, "%s\n\n\n%ld\n/", method, expires);
	} else if (path[0] != '/') {
		sprintf(out, "%s\n\n\n%ld\n/%s", method, expires, path);
	} else {
		sprintf(out, "%s\n\n\n%ld\n%s", method, expires, path);
	}

	int n = 0;
	char query[BUF_SIZE] = "";
	int count = param_count(query_param);
	if (count > 0) {
		for (int i=0; i<count; i++) {
			param *q = param_get(i, query_param);
			sprintf(tmp, ",%s,", q->key.base);
			if (!strstr(QSTRINGS, tmp))
				continue;
			if (n > 0)
				strcat(query,"&");
			n++;
			strcat(query,q->key.base);
			if (q->val.base != NULL) {
				strcat(query, "=");
				strcat(query, q->val.base);
			}
		}
	}
	if (n > 0) {
		strcat(out,"?");
		strcat(out, query);
	}


	log_trace(lg, "string to sign:\n%s\n", out);

	int len = strlen(out);
	unsigned int out_len;

	uint8_t hmac_out[EVP_MAX_MD_SIZE];
	err = hmac_sha1((uint8_t *)secret,  /* secret key */
	    (uint8_t)strlen(secret),       /* length of the key in bytes */
	    (uint8_t *)out,  /* data */
	    (size_t) len,       /* length of data in bytes */
	    hmac_out,      /* output buffer */
	    &out_len);
	if (err)
		return err;

	err = b64_encode_buffer(hmac_out, out_len, signature, signature_max_size);
	return err;
}
