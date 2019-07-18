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

#ifndef __ENC_HOST_H__
#define __ENC_HOST_H__

#include <openssl/evp.h>
#include "rtbuf.h"

#define CCOWD_ENCRYPTION_TYPE_HOST_AES_256_GCM	"host_aes_256_gcm"
#define CCOWD_ENCRYPTION_TYPE_HOST_AES_256_CBC	"host_aes_256_cbc"
#define CCOWD_ENCRYPTION_HOST_TOKEN_DEFAULT	"23$84##g"

typedef struct ccowd_host_enc {
	const EVP_CIPHER *cipher;
	unsigned char key[32], iv[32];
	int cipher_block_size;
} ccowd_host_enc_t;

int ccowd_host_encrypt_init(const EVP_CIPHER *cipher, unsigned char *key_data,
    int key_data_len, unsigned char *salt, ccowd_host_enc_t **ctx);

void ccowd_host_encrypt_cleanup(ccowd_host_enc_t *ctx);

rtbuf_t* ccowd_host_encrypt(ccowd_host_enc_t *ctx, rtbuf_t *rb);

rtbuf_t* ccowd_host_decrypt(ccowd_host_enc_t *ctx, rtbuf_t *rb);

#endif
