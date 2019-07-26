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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <uuid/uuid.h>
#include <json-c/json.h>

#include <ccowutil.h>

#include <param.h>
#include <request_util.h>
#include <sig2auth.h>
#include <sig4auth.h>

#define AKEY "a"
#define SKEY "abc"
#define SECRET "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define BUF_SIZE 4096


void
test_md5()
{
	char buf[BUF_SIZE], md5[BUF_SIZE];

	calc_md5("xxxxy", strlen("xxxxy") , md5);

	printf("\nMd5: %s\n", md5);


	printf("\nDone md5\n");
}

void
test_escape()
{
	printf("\nEescape\n");

	char s[] = "vHt0OPOOa+zJJ0P2kc9ZQVi9teU=/";
	char buf[BUF_SIZE];

	printf("\nS: %s\n", s);

	int res = uri_escape(s, strlen(s), buf, BUF_SIZE, 1);
	assert(res >= 0);

	printf("\nEscape: %s[%d]\n", buf, res);

	assert(strcmp(buf,"vHt0OPOOa%2BzJJ0P2kc9ZQVi9teU%3D%2F") == 0);
	printf("\nDone escape\n");
}


void
test_unescape()
{
	printf("\nUnescape\n");

	char s[] = "vHt0OPOOa%2BzJJ0P2kc9ZQVi9teU%3D";

	printf("\nS: %s\n", s);

	int res = uri_unescape(s, strlen(s));

	assert(res >= 0);
	s[res] = 0;

	printf("\nUnescape: %s[%d]\n", s, res);

	assert(strcmp(s,"vHt0OPOOa+zJJ0P2kc9ZQVi9teU=") == 0);
	printf("\nDone unescape\n");
}


void
test_query(char *q)
{
	char buf[BUF_SIZE];
	param *qf;

	printf("\nQuery: %s\n", q);

	h2o_iovec_t query;
	param_vector params;

	query.base = je_strdup(q);
	query.len = strlen(q) + 1;

	int num = query_parse(NULL, &query, &params);
	assert(num >= 0);

	param_dump("params", &params);

	printf("\nSorting query..\n");
	char **keys = param_sort(&params);
	for (int i=0; i<param_count(&params); i++) {
		param *p = param_find(keys[i], strlen(keys[i]), &params);
		printf("Sorted %s\n", param_str(p, buf, BUF_SIZE));
	}
	param_sort_free(keys, &params);

	qf = param_find(H2O_STRLIT(SKEY), &params);
	if (qf != NULL) {
		printf("Found %s\n", param_str(qf, buf, BUF_SIZE));
		printf("Found long: %ld\n", param_find_long(H2O_STRLIT(SKEY), 111, &params));
		printf("Found int64: %ld\n", param_find_int64(H2O_STRLIT(SKEY), 111, &params));
		printf("Equal 10: %d\n", param_value_equal(qf, H2O_STRLIT("10")));
		printf("Has: %d\n", param_has(H2O_STRLIT(SKEY), &params));
	}

	qf = param_find(H2O_STRLIT(AKEY), &params);
	if (qf != NULL) {
		printf("Found %s\n", param_str(qf, buf, BUF_SIZE));
		printf("Found long: %ld\n", param_find_long(H2O_STRLIT(AKEY), 211, &params));
		printf("Found int64: %ld\n", param_find_int64(H2O_STRLIT(AKEY), 211, &params));
		printf("Equal 10: %d\n", param_value_equal(qf, H2O_STRLIT("10")));
		printf("Has: %d\n", param_has(H2O_STRLIT(AKEY), &params));
	}

	param_free(&params);

	je_free(query.base);

	printf("\nDone query\n");
}


void
test_headers()
{
	printf("\nHeaders\n");

	param_vector params;
	char buf[BUF_SIZE];


	h2o_mem_pool_t pool;
	h2o_headers_t headers;
	headers.size = 0;
	headers.capacity = 0;

	h2o_mem_init_pool(&pool);

	// void *p = h2o_mem_alloc_pool(&pool, 1024*10);

	h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("XName2"),  0,
	    "XNAME2", H2O_STRLIT("xvalue2"));

	h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("Name1"),  0,
	    "NAME1", H2O_STRLIT("value1"));

	h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("Name2"),  0,
	    "NAME2", H2O_STRLIT("value2"));

	printf("Headers size: %d\n", (int) headers.size);


	int num = headers_parse(NULL, &headers, &params);
	assert(num >= 0);

	param_dump("headers", &params);

	param *p = param_find(H2O_STRLIT("name1"), &params);
	printf("Found %s\n", param_str(p, buf, BUF_SIZE));

	printf("\nSorting headers..\n");
	char **keys = param_sort(&params);
	for (int i=0; i<param_count(&params); i++) {
		param *p = param_find(keys[i], strlen(keys[i]), &params);
		printf("Sorted %s\n", param_str(p, buf, BUF_SIZE));
	}
	param_sort_free(keys, &params);

	param *q = param_find(H2O_STRLIT("name1"), &params);
	printf("Found %s\n", param_str(q, buf, BUF_SIZE));

	param_free(&params);


	h2o_mem_clear_pool(&pool);
	printf("\nDone headers\n");
}


void
test_signature2(char * cquery, char * cdate, char *path, char *method,
    char *content_type, char *expected, char **extra_key, char **extra_value, int nextra)
{
	int num, err;

	printf("\nSignature2\n");

	h2o_iovec_t query;

	param_vector pheaders;
	param_vector pquery;

	query.base = je_strdup(cquery);
	query.len = strlen(cquery) + 1;

	num = query_parse(NULL, &query, &pquery);
	assert(num >= 0);


	h2o_mem_pool_t pool;
	h2o_headers_t headers;
	headers.size = 0;
	headers.capacity = 0;

	h2o_mem_init_pool(&pool);

	h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("Date"),  0,
	    "Date", PARAM_STR(cdate));

	if (content_type) {
		h2o_add_header_by_str(&pool, &headers, H2O_STRLIT("Content-Type"),  0,
		    "Content-Type", PARAM_STR(content_type));
	}

	for (int n=0; n<nextra; n++) {
		printf("Extra headers: %s - %s\n", extra_key[n], extra_value[n]);
		h2o_add_header_by_str(&pool, &headers, PARAM_STR(extra_key[n]),  0,
		    extra_key[n], PARAM_STR(extra_value[n]));
	}

	num = headers_parse(NULL, &headers, &pheaders);
	assert(num >= 0);

	param_dump("headers", &pheaders);

	char signature[MAX_SIGNATURE_LENGTH];
	err = sig2auth_sign_request(&pquery,
	    &pheaders,
	    method,
	    path,
	    SECRET,
	    signature,
	    MAX_SIGNATURE_LENGTH);

	printf("\nSignature\n%s\n", signature);
	assert(err == 0);

	assert(strcmp(signature, expected) == 0);

	param_free(&pquery);
	param_free(&pheaders);
	je_free(query.base);
	h2o_mem_clear_pool(&pool);
	printf("\nDone signature2\n");
}


void
test_signature4(char * cquery, char *path, char *method,
    char *secret, char *expected)
{
	int num, err;

	printf("\nSignature query\n");

	h2o_iovec_t query;

	param_vector pheaders;
	param_vector pquery;

	query.base = je_strdup(cquery);
	query.len = strlen(cquery) + 1;

	num = query_parse(NULL, &query, &pquery);
	assert(num >= 0);

	char signature[MAX_SIGNATURE_LENGTH];
	err = query_sign_request(&pquery,
	    method,
	    path,
	    secret,
	    signature,
	    MAX_SIGNATURE_LENGTH);

	printf("\nSignature\n%s\n", signature);
	assert(err == 0);

	assert(strcmp(signature, expected) == 0);

	param_free(&pquery);
	je_free(query.base);
	printf("\nDone signature query\n");
}

void
test_signature_query(char * cquery, char *path, char *method,
    char *secret, char *expected)
{
	int num, err;

	printf("\nSignature query\n");

	h2o_iovec_t query;

	param_vector pheaders;
	param_vector pquery;

	query.base = je_strdup(cquery);
	query.len = strlen(cquery) + 1;

	num = query_parse(NULL, &query, &pquery);
	assert(num >= 0);

	char signature[MAX_SIGNATURE_LENGTH];
	err = query_sign_request(&pquery,
	    method,
	    path,
	    secret,
	    signature,
	    MAX_SIGNATURE_LENGTH);

	if (err) {
		printf("\nSignature error: %d\n", err);
	} else {
		printf("\nSignature\n%s\n", signature);
	}
	assert(err == 0);
		printf("\nExpected\n%s\n", expected);

	assert(strcmp(signature, expected) == 0);

	param_free(&pquery);
	je_free(query.base);
	printf("\nDone signature query\n");
}


int
main()
{
	lg = Logger_create("request_test");
	log_set_level(lg, 0);

	test_query("c=3&EEE=55&uu=90&a=1&dd=4&b=2");

	test_query("abc=10");

	test_query("oo=o1&zz=a3&abc=abc&acl");

	test_query("acl");

	test_query("");

	test_query("&");

	test_headers();

	test_signature2("", "Tue, 27 Mar 2007 19:36:42 +0000",
	    "/johnsmith/photos/puppy.jpg", "GET",
	    NULL,
	    "bWq2s1WEIj+Ydj0vQ697zp+IXMU=",NULL, NULL, 0);

	test_signature2("", "Tue, 27 Mar 2007 21:15:45 +0000",
	    "/johnsmith/photos/puppy.jpg", "PUT",
	    "image/jpeg",
	    "MyyxeRY7whkBe+bq8fHCL/2kKUg=",NULL, NULL, 0);

	test_signature2("prefix=photos&max-keys=50&marker=puppy",
	    "Tue, 27 Mar 2007 19:42:41 +0000",
	    "/johnsmith/", "GET",
	    "",
	    "htDYFYduRNen8P9ZfE/s9SuKy0U=",NULL, NULL, 0);

	test_signature2("acl",
	    "Tue, 27 Mar 2007 19:44:46 +0000",
	    "/johnsmith/", "GET",
	    "",
	    "c2WLPFtWHVgbEmeEG93a4cG37dM=",NULL, NULL, 0);

	/* Wrong
	   char *extra_key1[] = {"x-amz-date"};
	   char *extra_value1[] = {"Tue, 27 Mar 2007 21:20:26 +0000"};

	   test_signature2("",
	   "Tue, 27 Mar 2007 21:20:27 +0000",
	   "/johnsmith/photos/puppy.jpg", "DELETE",
	   "",
	   "lx3byBScXR6KzyMaifNkardMwNk=", extra_key1, extra_value1, 1);
	 */

	char *extra_key2[] = {"content-md5", "x-amz-acl","X-Amz-Meta-ReviewedBy",
		"X-Amz-Meta-FileChecksum","X-Amz-Meta-ChecksumAlgorithm","Content-Encoding"};
	char *extra_value2[] = {"4gJE4saaMU4BqNR0kLY+lw==","public-read","joe@johnsmith.net,jane@johnsmith.net",
		"0x02661779","crc32","gzip"};
	test_signature2("",
	    "Tue, 27 Mar 2007 21:06:08 +0000",
	    "/static.johnsmith.net/db-backup.dat.gz", "PUT",
	    "application/x-download",
	    "ilyl83RwaSoYIEdixDQcA4OnAnc=", extra_key2, extra_value2, 6);

	test_md5();

	// 	http://10.3.32.230:9982/bk1/x13?AWSAccessKeyId=PTAA8RZIP6WJP5SRH2MS&Expires=1618910725&Signature=vHt0OPOOa%2BzJJ0P2kc9ZQVi9teU%3D
	test_signature_query("Expires=1618910725", "/bk1/x13", "GET",
	    "lT3Mj0qCR74KhCt88L4fcEc2QFBHvnkAHEW08Wtj",	"Hu2PAY5tPDvbPUrPmb/umT77fSA=");

	test_unescape();

	test_escape();
}
