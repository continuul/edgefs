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
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "ccowutil.h"
#include "payload-s3.h"

#define BLOCK_LENGTH 64U
#define INNER_PAD '\x36'
#define OUTER_PAD '\x5c'

#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_HEX_LENGTH (SHA256_DIGEST_LENGTH *2)+4

#define AWS_KEY_PREFIX "AWS4"
#define AWS_ALGORITHM "AWS4-HMAC-SHA256"
#define AWS_SIGNED_HEADERS "host;x-amz-date"
#define AWS_REQUEST_TYPE "aws4_request"
#define AWS_DATE_LABEL "x-amz-date"

static volatile int curl_global = 0;
static int curl_verb = 1;

static int
payload_s3_trace(CURL *handle, curl_infotype type, char *data, size_t size,
    void *userp)
{
	return 0;
}

static void
payload_s3_hmac_gen(uint8_t *input_key, uint8_t key_len, uint8_t *msg,
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
payload_s3_hash_sha256_hex_gen(char *in, size_t in_len, char *out, size_t out_size)
{
	int ret;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned out_idx = 0;

	if (EVP_Digest(in, in_len, digest, NULL, EVP_sha256(), NULL) == 0)
		assert(0);

	out[0] = '\0';
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
		out_idx += snprintf(out + out_idx, out_size - out_idx,
				"%02x", digest[i]);
}

static int
payload_s3_sign_request(struct payload_s3 *ctx, char *objname, char *method,
    char *date_header, char *auth_header)
{
	char datetime[32];
	time_t sig_time = time(0);
	struct tm  *tstruct = gmtime(&sig_time);
	strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", tstruct);

	char date[12];
	memset(date, '\0', 12);
	strncpy(date, datetime, 8);

	char aws_host[1024];
	if (ctx->port == 80 || ctx->port == 443)
		sprintf(aws_host, "%s", ctx->host);
	else
		sprintf(aws_host, "%s:%d", ctx->host, ctx->port);

	// = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
	char canonical_headers[1024];
	sprintf(canonical_headers, "host:%s\n%s:%s\n", aws_host,
	    AWS_DATE_LABEL, datetime);

	char hmac_payload_hex[SHA256_DIGEST_HEX_LENGTH];
	strcpy(hmac_payload_hex, "UNSIGNED-PAYLOAD");

	char canonical_request[4096];
	sprintf(canonical_request, "%s\n%s/%s\n%s\n%s\n%s\n%s", method,
	    ctx->path, objname, "", canonical_headers, AWS_SIGNED_HEADERS, hmac_payload_hex);

	log_trace(lg, "canonical request:\n%s", canonical_request);

	char hmac_canonical_request_hex[SHA256_DIGEST_HEX_LENGTH];
	payload_s3_hash_sha256_hex_gen(canonical_request, strlen(canonical_request),
	    hmac_canonical_request_hex, sizeof(hmac_canonical_request_hex));

	char credential_scope[64];
	sprintf(credential_scope, "%s/%s/%s/%s", date, ctx->aws_region,
	    "s3", AWS_REQUEST_TYPE);

	char string_to_sign[4096 + 256];
	sprintf(string_to_sign, "%s\n%s\n%s\n%s", AWS_ALGORITHM, datetime,
	    credential_scope, hmac_canonical_request_hex);

	log_trace(lg, "string_to_sign:\n%s", string_to_sign);

	uint8_t hmac_signing_interim[SHA256_DIGEST_LENGTH];
	uint8_t hmac_signing_key[SHA256_DIGEST_LENGTH];
	char prefixed_secret_key[64] = AWS_KEY_PREFIX;
	strcat(prefixed_secret_key,ctx->secret_key);
	payload_s3_hmac_gen((uint8_t *)prefixed_secret_key,
	    (uint8_t)strlen(prefixed_secret_key), (uint8_t *)date, hmac_signing_interim);
	payload_s3_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)ctx->aws_region, hmac_signing_interim);
	payload_s3_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)"s3", hmac_signing_interim);
	payload_s3_hmac_gen((uint8_t *)&hmac_signing_interim, SHA256_DIGEST_LENGTH,
	    (uint8_t *)AWS_REQUEST_TYPE, hmac_signing_key);

	uint8_t hmac_signature[SHA256_DIGEST_LENGTH];
	payload_s3_hmac_gen((uint8_t *)&hmac_signing_key, SHA256_DIGEST_LENGTH,
	    (uint8_t *)string_to_sign, hmac_signature);
	char hmac_signature_hex[SHA256_DIGEST_HEX_LENGTH];
	unsigned hmac_signature_hex_idx = 0;
	memset(hmac_signature_hex, '\0', 4);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
		hmac_signature_hex_idx += snprintf(hmac_signature_hex + hmac_signature_hex_idx,
				sizeof(hmac_signature_hex) - hmac_signature_hex_idx,
				"%02x", hmac_signature[i] );

	sprintf(auth_header, "Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
	    AWS_ALGORITHM, ctx->access_key, credential_scope, AWS_SIGNED_HEADERS, hmac_signature_hex);
	sprintf(date_header, "%s: %s", AWS_DATE_LABEL, datetime);
	return 0;
}

static void
payload_s3_lock(CURL *handle, curl_lock_data data, curl_lock_access laccess,
    void *useptr)
{
	(void)handle;
	(void)data;
	(void)laccess;
	struct payload_s3 *ctx = useptr;
	uv_mutex_lock(&ctx->conn_lock);
}

static void
payload_s3_unlock(CURL *handle, curl_lock_data data, void *useptr)
{
	(void)handle;
	(void)data;
	struct payload_s3 *ctx = useptr;
	uv_mutex_unlock(&ctx->conn_lock);
}

struct payload_s3_write_ctx {
	const char *readptr;
	size_t sizeleft;
};

static size_t
payload_s3_memread_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct payload_s3_write_ctx *upload = (struct payload_s3_write_ctx *)userp;
	size_t max = size*nmemb;

	if(max < 1)
		return 0;

	if(upload->sizeleft) {
		size_t copylen = max;
		if(copylen > upload->sizeleft)
			copylen = upload->sizeleft;
		memcpy(ptr, upload->readptr, copylen);
		upload->readptr += copylen;
		upload->sizeleft -= copylen;
		return copylen;
	}

	/* no more data left to deliver */
	return 0;
}

int
payload_s3_put(struct payload_s3 *ctx, const uint512_t *chid, uv_buf_t *data)
{
	CURL *curl;
	CURLcode res;
	struct payload_s3_write_ctx upload;
	char url[2048];
	char date_header[32];
	char auth_header[256];
	char errbuf[CURL_ERROR_SIZE];
	char chidbuf[UINT512_BYTES * 2 + 1];
	struct curl_slist *headers = NULL;
	int err = 0;

	uint512_dump(chid, chidbuf, UINT512_BYTES * 2 + 1);
	sprintf(url, "%s/%s", ctx->bucket_url, chidbuf);

	payload_s3_sign_request(ctx, chidbuf, "PUT", date_header, auth_header);
	headers = curl_slist_append(headers, "content-type: application/octet-stream");
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, date_header);
	headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_SHARE, ctx->share);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	errbuf[0] = 0;
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	if (curl_verb) {
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, payload_s3_trace);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	}

	FILE *pfd = fopen("/dev/null", "w");
	if (pfd)
		curl_easy_setopt(curl, CURLOPT_STDERR, pfd);

	upload.readptr = data->base;
	upload.sizeleft = data->len;
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_s3_memread_callback);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload.sizeleft);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, EDGE_USER_AGENT);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		log_error(lg, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
		err = -EIO;
	} else {
		long response_code;
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		if (res == CURLE_OK && (response_code / 100) != 2)
			err = -EIO;
	}
	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	if (pfd)
		fclose(pfd);
	return err;
}

struct payload_s3_read_ctx {
	uv_buf_t *chunk;
	size_t netlen;
};

static size_t
payload_s3_memwrite_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct payload_s3_read_ctx *read_ctx = (struct payload_s3_read_ctx *)userp;
	uv_buf_t *chunk = read_ctx->chunk;

	if (read_ctx->netlen + realsize > chunk->len) {
		chunk->base = je_realloc(chunk->base, read_ctx->netlen + realsize);
		chunk->len = read_ctx->netlen + realsize;
	}

	memcpy(&(chunk->base[read_ctx->netlen]), contents, realsize);
	read_ctx->netlen += realsize;

	return realsize;
}

int
payload_s3_get(struct payload_s3 *ctx, const uint512_t *chid, uv_buf_t *outbuf)
{
	CURL *curl;
	CURLcode res;
	char url[2048];
	char date_header[32];
	char auth_header[256];
	char errbuf[CURL_ERROR_SIZE];
	char chidbuf[UINT512_BYTES * 2 + 1];
	struct curl_slist *headers = NULL;
	int err = 0;

	uint512_dump(chid, chidbuf, UINT512_BYTES * 2 + 1);
	sprintf(url, "%s/%s", ctx->bucket_url, chidbuf);

	payload_s3_sign_request(ctx, chidbuf, "GET", date_header, auth_header);
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, date_header);
	headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");

	struct payload_s3_read_ctx read_ctx = { .chunk = outbuf, .netlen = 0 };

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_SHARE, ctx->share);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, payload_s3_memwrite_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_ctx);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, EDGE_USER_AGENT);

	errbuf[0] = 0;
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	if (curl_verb) {
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, payload_s3_trace);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	}

	FILE *pfd = fopen("/dev/null", "w");
	if (pfd)
		curl_easy_setopt(curl, CURLOPT_STDERR, pfd);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		log_error(lg, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
		err = -EIO;
	} else {
		long response_code;
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		if (res == CURLE_OK && (response_code / 100) != 2) {
			log_warn(lg, "s3 payload ok, but unexpected response_code %ld: "
			    "verify that clocks NTP synchronized on the host",
			    response_code);
			err = -ENOENT;
		}
	}
	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	if (pfd)
		fclose(pfd);
	return err;
}

int
payload_s3_delete(struct payload_s3 *ctx, const uint512_t *chid)
{
	CURL *curl;
	CURLcode res;
	char url[2048];
	char date_header[32];
	char auth_header[256];
	char errbuf[CURL_ERROR_SIZE];
	char chidbuf[UINT512_BYTES * 2 + 1];
	struct curl_slist *headers = NULL;
	int err = 0;

	uint512_dump(chid, chidbuf, UINT512_BYTES * 2 + 1);
	sprintf(url, "%s/%s", ctx->bucket_url, chidbuf);

	payload_s3_sign_request(ctx, chidbuf, "DELETE", date_header, auth_header);
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, date_header);
	headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_SHARE, ctx->share);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_USERAGENT, EDGE_USER_AGENT);

	errbuf[0] = 0;
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	if (curl_verb) {
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, payload_s3_trace);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	}

	FILE *pfd = fopen("/dev/null", "w");
	if (pfd)
		curl_easy_setopt(curl, CURLOPT_STDERR, pfd);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		log_error(lg, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
		err = -EIO;
	} else {
		long response_code;
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		if (res == CURLE_OK) {
			if ((response_code / 100) == 4)
				err = -ENOENT;
			else if ((response_code / 100) != 2)
				err = -EIO;
		}
	}
	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	if (pfd)
		fclose(pfd);
	return err;
}

int
payload_s3_init(char *url, char *region, char *keyfile, struct payload_s3 **ctx_out)
{
	char key[256] = { 0 };
	struct payload_s3 *ctx = je_calloc(1, sizeof(struct payload_s3));
	if (!ctx)
		return -ENOMEM;

	ctx->port = 80;
	ctx->path[0] = '/';

	int ok = 0;
	if (sscanf(url, "http://%1023[^:]:%i/%2047[^\n]", ctx->host, &ctx->port, &ctx->path[1]) == 3) { ok = 1;}
	else if (sscanf(url, "http://%1023[^/]/%2047[^\n]", ctx->host, &ctx->path[1]) == 2) { ok = 1;}
	else if (sscanf(url, "http://%1023[^:]:%i[^\n]", ctx->host, &ctx->port) == 2) { ok = 1;}
	else if (sscanf(url, "http://%1023[^\n]", ctx->host) == 1) { ok = 1;}
	else if (sscanf(url, "https://%1023[^/]/%2047[^\n]", ctx->host, &ctx->path[1]) == 2) { ok = 1; ctx->port=443; }
	else if (sscanf(url, "https://%1023[^\n]", ctx->host) == 1) { ok = 1; ctx->port = 443; }

	if (!ok) {
		je_free(ctx);
		log_error(lg, "Cannot parse payload_s3_bucket_url");
		return -EBADF;
	}
	ctx->bucket_url = je_strdup(url);
	ctx->aws_region = je_strdup(region);

	int fd = open(keyfile, 0);
	if (fd == -1) {
		je_free(ctx);
		return -errno;
	}
	if (read(fd, &key[0], 256) == -1) {
		close(fd);
		je_free(ctx);
		return -errno;
	}
	close(fd);

	char *saveptr = NULL;
	char *access = strtok_r(key, ",", &saveptr);
	char *secret = strtok_r(NULL, ",", &saveptr);
	if (!access || !secret) {
		je_free(ctx);
		return -EBADF;
	}
	char secret_trimmed[256];
	sscanf(secret, "%s", secret_trimmed);

	uv_mutex_init(&ctx->conn_lock);

	if (curl_global++ == 0)
		curl_global_init(CURL_GLOBAL_ALL);

	ctx->access_key = je_strdup(access);
	ctx->secret_key = je_strdup(secret_trimmed);
	ctx->share = curl_share_init();
	curl_share_setopt(ctx->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
	curl_share_setopt(ctx->share, CURLSHOPT_LOCKFUNC, payload_s3_lock);
	curl_share_setopt(ctx->share, CURLSHOPT_UNLOCKFUNC, payload_s3_unlock);
	curl_share_setopt(ctx->share, CURLSHOPT_USERDATA, ctx);

	*ctx_out = ctx;
	return 0;
}

void
payload_s3_destroy(struct payload_s3 *ctx)
{
	curl_share_cleanup(ctx->share);
	uv_mutex_destroy(&ctx->conn_lock);
	je_free(ctx->aws_region);
	je_free(ctx->access_key);
	je_free(ctx->secret_key);
	je_free(ctx->bucket_url);
	je_free(ctx);
}
