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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "ccowutil.h"
#include "common.h"
#include "cmocka.h"
#include "ccow.h"



/*
 * input_buf MUST be 512 byte aligned : size % 512 = 0!
 */
unsigned char *
getMd5sum(char *input_buf, size_t size)
{
	int n;
	MD5_CTX c;
	char *buf = input_buf;
	size_t bytes;
	unsigned char out[MD5_DIGEST_LENGTH];

	MD5_Init(&c);
	bytes = size - 512;
	while (bytes > 0)
	{
		MD5_Update(&c, buf += 512, 512);
		bytes -= 512;
	}

	MD5_Final(out, &c);

	for (n = 0; n < MD5_DIGEST_LENGTH; n++)
	{
		printf("%02x", out[n]);
	}
	printf("\n");

	unsigned char *ret = je_malloc(MD5_DIGEST_LENGTH);
	memcpy(ret, out, MD5_DIGEST_LENGTH);
	return ret;
}




int
test_send_multicast(char *addr, int port, char *buf, int len)
{
	struct sockaddr_in6 saddr;
	struct ipv6_mreq mreq;
	int sd, on = 1, hops = 255, ifidx = 0;

	sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx,
		    sizeof (ifidx))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
		    sizeof (hops))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,
		    sizeof (on))) {
		perror("setsockopt");
		return 1;
	}

	memset(&saddr, 0, sizeof (struct sockaddr_in6));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(port);
	inet_pton(AF_INET6, addr, &saddr.sin6_addr);

	memcpy(&mreq.ipv6mr_multiaddr, &saddr.sin6_addr,
	    sizeof (mreq.ipv6mr_multiaddr));
	mreq.ipv6mr_interface = ifidx;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&mreq,
		    sizeof (mreq))) {
		perror("setsockopt");
		return 1;
	}

	sendto(sd, buf, len, 0, (const struct sockaddr *) &saddr,
	    sizeof (saddr));

	close(sd);

	return 0;
}


void
put_simple(ccow_completion_t c, char *bid, char *oid, struct iovec *iov,
    size_t iovcnt, uint64_t off)
{
	int err;
	static char rand_buf[128] = { 0 };
	static int cnt = 0;

	assert(bid);
	assert(oid);

	if (*rand_buf == 0 && *(rand_buf + 1) == 0) {
		unsigned int v = rand(), *ptr = (unsigned int *)rand_buf;
		for (size_t j = 0; j < 128 / 4; j++)
			ptr[j] = (v << 16) ^ rand();
	}

	/* make all iov's random, so that it will stress compression algos  */
	for (size_t i = 0; i < iovcnt; i++) {
		rand_buf[0] = cnt++;
		memcpy(iov[i].iov_base, rand_buf, iov[i].iov_len < 128 ?
		    iov[i].iov_len : 128);
	}
	err = ccow_put(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off);
	assert_int_equal(err, 0);
}

void
get_simple(ccow_completion_t c, char *bid, char *oid, struct iovec *iov,
    size_t iovcnt, uint64_t off, ccow_lookup_t *iter)
{
	int err;

	assert(bid);
	assert(oid);

	err = ccow_get(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c, iov,
	    iovcnt, off, iter);
	assert_int_equal(err, 0);
}

void
get(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg, ccow_lookup_t *iter)
{
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	get_simple(c, bid, oid, iov, iovcnt, off, iter);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);

	if (err != 0) {
		printf("%s : %s : %d : ccow_wait returned %d \n",
		    __FUNCTION__, __FILE__, __LINE__, err);
	}

	assert_int_equal(err, 0);
}

void
put(ccow_t tc, char *bid, char *oid, struct iovec *iov, size_t iovcnt,
    uint64_t off, ccow_callback_t cb_async, void *arg)
{
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	assert_int_equal(err, 0);

	put_simple(c, bid, oid, iov, iovcnt, off);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);
	assert_int_equal(err, 0);
}

void
get_offsets(ccow_t tc, char *bid, char *oid, size_t bs, int *offsets, int num_items)
{

	struct iovec *iov = je_calloc(1, sizeof (struct iovec));
	assert_non_null(iov);

	char *buf = je_malloc(bs);
	assert_non_null(buf);

	iov->iov_base = buf;
	iov->iov_len = bs;

	for(int j = 0; j < num_items; j++) {
		get(tc, bid, oid, iov, 1, offsets[j], NULL, NULL, NULL);
	}
	je_free(buf);
	je_free(iov);
}

void
put_offsets(ccow_t tc, char *bid, char *oid, size_t bs, int *offsets, int num_items)
{

	int err = 0;
	struct iovec *iov = je_calloc(1, sizeof (struct iovec));
	assert_non_null(iov);

	char *buf = je_malloc(bs);
	assert_non_null(buf);

	iov->iov_base = buf;
	iov->iov_len = bs;

	for(int j = 0; j < num_items; j++) {
		put(tc, bid, oid, iov, 1, offsets[j], NULL, NULL);
	}

	je_free(buf);
	je_free(iov);
}


void
delete(ccow_t tc, char *bid, char *oid, ccow_callback_t cb_async, void *arg)
{
	int err;

	ccow_completion_t c;
	err = ccow_create_completion(tc, arg, cb_async, 1, &c);
	if (err != 0) {
		printf("ccow_create_completion returned err %d, \n"
		    "bid = \"%s\" : oid = \"%s\n ", err, bid, oid);
	}
	assert_int_equal(err, 0);

	err = ccow_delete(bid, strlen(bid) + 1, oid, strlen(oid) + 1, c);
	if (err != 0) {
		printf("ccow_delete returned err %d, \n"
		    "bid = \"%s\" : oid = \"%s\n ", err, bid, oid);
	}
	assert_int_equal(err, 0);

	if (cb_async)
		return;

	err = ccow_wait(c, -1);
	if (err != 0) {
		printf("ccow_wait returned err %d, \n"
		    "bid = \"%s\" : oid = \"%s\n ", err, bid, oid);
	}
	assert_int_equal(err, 0);
}


/*
 * Timer which will sleep to allow auditserver to complete updating buckets
 * on bucket_delete.
 */
void asleep()
{
	int timer = 1000;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/auditd.ini", nedge_path());
	FILE* fh = fopen(path, "r");
	if (fh == NULL)
		return;
	char line[128];
	while (fgets(line, 128, fh) != NULL) {
		char *p = strstr(line, "flush_interval");
		if (!p)
			continue;
		*(p + strlen(p) - 1) = 0;
		p = strrchr(p, '=');
		if (!p)
			continue;
		if (*(p + 2) == ' ')
			p = p + 3;
		else
			p = p + 2;
		timer = atoi(p) * 3000;
	}
	fclose(fh);
	char *time_string = getenv("CCOW_TEST_AUDIT_REFRESH_TIMER");
	if (time_string)
		timer = atoi(time_string);
	printf("sleeping for ... %d ms\n", timer);
	usleep(timer * 1000);
}

/*
 * mdtype is a bitmask defined as :
 * #define CCOW_MDTYPE_METADATA		0x1
 * #define CCOW_MDTYPE_CUSTOM		0x2
 * #define CCOW_MDTYPE_ACL		0x4
 * #define CCOW_MDTYPE_NAME_INDEX	0x8
 * #define CCOW_MDTYPE_ALL		0xFF
 */
void
dump_iter_to_stdout(ccow_lookup_t iter, int mdtype)
{
	struct ccow_metadata_kv *kv = NULL;
	int pos = 0;
	while ((kv = ccow_lookup_iter(iter, mdtype, pos++))) {
		if (kv->type == CCOW_KVTYPE_INT8)
			printf("%s: %d\n", kv->key, *(int8_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT16)
			printf("%s: %d\n", kv->key, *(int16_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT32)
			printf("%s: %d\n", kv->key, *(int32_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_INT64)
			printf("%s: %ld\n", kv->key, *(int64_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT8)
			printf("%s: %" PRIu8 "\n", kv->key, *(uint8_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT16)
			printf("%s: %" PRIu16 "\n", kv->key, *(uint16_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT64)
			printf("%s: %" PRIu64"\n", kv->key, *(uint64_t *)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT32)
			printf("%s: %" PRIu32 "\n", kv->key, *(uint32_t*)kv->value);
		if (kv->type == CCOW_KVTYPE_UINT128) {
			char vv[sizeof (uint128_t) * 2 + 1];
			uint128_dump((uint128_t *)kv->value, vv, sizeof (uint128_t) * 2 + 1);
			printf("%s: %s\n", kv->key, vv);
		}
		if (kv->type == CCOW_KVTYPE_UINT512) {
			char vv[sizeof (uint512_t) * 2 + 1];
			uint512_dump((uint512_t *)kv->value, vv, sizeof (uint512_t) * 2 + 1);
			printf("%s: %s\n", kv->key, vv);
		}
		if (kv->type == CCOW_KVTYPE_STR) {
			char *b = je_malloc(kv->key_size + 1);
			assert(b);
			char *c = je_malloc(kv->value_size + 1);
			assert(c);
			if (kv->key)
				memcpy(b, kv->key, kv->key_size);
			b[kv->key_size] = '\0';
			if (kv->value)
				memcpy(c, kv->value, kv->value_size);
			c[kv->value_size] = '\0';
			printf("%s: %s\n", b, c);
			je_free(b);
			je_free(c);
		}
		if (kv->type == CCOW_KVTYPE_RAW) {
			char *b = je_malloc(kv->key_size + 1);
			assert(b);
			char *c = je_malloc(kv->value_size + 1);
			assert(c);
			if (kv->key)
				memcpy(b, kv->key, kv->key_size);
			b[kv->key_size] = '\0';
			if (kv->value)
				memcpy(c, kv->value, kv->value_size);
			c[kv->value_size] = '\0';
			printf("%s: %s\n", b, c);
			je_free(b);
			je_free(c);
		}
	}
	assert_null(kv);
}


/*
 * sst_convert_bytes
 *
 * convert a null terminated string in the form "[0-9]+[GMKB]?" to the
 * corresponding number of bytes.
 */
uint64_t sst_convert_bytes(const char * in_string)
{
	uint64_t rv = 0;
	size_t len = strlen(in_string);
	size_t factor = 1;
	char str[128];

	if ((len == 0) || (len > 127))
		return rv;

	strcpy(str, in_string);

	switch(str[len - 1]) {
	case 'G':
	case 'g':
		factor *= 1024;
	case 'M':
	case 'm':
		factor *= 1024;

	case 'K':
	case 'k':
		factor *= 1024;
	case 'B':
	case 'b':
		str[len - 1] = 0;
		break;
	default:
		break;
	}

	sscanf(str, "%"PRIu64, &rv);
	rv *= factor;

	return rv;
}

