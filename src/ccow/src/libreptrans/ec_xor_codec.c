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
#include "erasure-coding.h"

/* reference EC codec implementation.
 * Simple XOR codec
 */
struct xor_codec_instance {
	ec_codec_format format;
	rtbuf_t*	to_be_freed;
};

static int
xor_codec_info(struct ec_codec_info** info) {
	static ec_codec_format fmt[] = { EC_FORMAT_D2P1,
		EC_FORMAT_D3P1, EC_FORMAT_D4P1,
		EC_FORMAT_D5P1, EC_FORMAT_D6P1,
		EC_FORMAT_D7P1, EC_FORMAT_D8P1,
		EC_FORMAT_D9P1, EC_FORMAT_D10P1};
	static struct ec_codec_info xor = {
		.id = EC_CID_XOR,
		.formats = fmt,
		.n_formats = 9,
		.name = "xor"
	};
	*info = &xor;
	return 0;
}

static int
xor_codec_create(ec_codec_format format, void** instance) {
	int n_data = 0, n_parity = 0;
	FROM_CODECFMT(format, n_data, n_parity);
	if (n_data < 2 || n_data > 10 || n_parity != 1)
	    return -EINVAL;

	struct xor_codec_instance* inst = je_calloc(1, sizeof(*inst));
	if (!inst)
		return -ENOMEM;
	inst->to_be_freed = rtbuf_init_empty();
	if (!inst->to_be_freed) {
		je_free(inst);
		return -ENOMEM;
	}
	inst->format = format;
	*instance = inst;
	return 0;
}

static int
xor_codec_encode(void* instance, struct ec_fragment* data,
	struct ec_fragment* parity, uv_buf_t* context) {
	struct xor_codec_instance* inst = (struct xor_codec_instance*)instance;
	assert(inst);
	int n_data = 0, n_parity = 0;
	FROM_CODECFMT(inst->format, n_data, n_parity);
	assert(n_data >= 2 && n_data <= 10);
	assert(n_parity == 1);
	assert(data);
	assert(parity);

	parity->buf.len = 0;
	/* Calculate parity chunk size */
	for (int i = 0; i < n_data; i++) {
		if (data[i].buf.len > parity->buf.len)
			parity->buf.len = data[i].buf.len;
	}
	/* Allocate memory */
	parity->buf.base = je_calloc(1, parity->buf.len);
	if (!parity->buf.base)
		return -ENOMEM;
	/* NOTE: all data allocated by a codec have to be freed by the codec */
	int err = rtbuf_add(inst->to_be_freed, &parity->buf, 1);
	if (err) {
		je_free(parity->buf.base);
		return err;
	}
	parity->index = n_data;
	/* Do coding */
	for (size_t i = 0; i < parity->buf.len; i++) {
		parity->buf.base[i] = 0;
		for (int j = 0; j < n_data; j++)
			if (data[j].buf.len > i)
				parity->buf.base[i] ^= data[j].buf.base[i];
	}
	/* XOR codec doesn't use context, so just force its size to 0 */
	if (context)
		context->len = 0;
	return 0;
}

static int
xor_codec_recover(void* instance, struct ec_fragment* fragments,
	uv_buf_t* context) {
	struct xor_codec_instance* inst = (struct xor_codec_instance*)instance;
	assert(inst);
	int n_data = 0, n_parity = 0, n_from = 0;
	FROM_CODECFMT(inst->format, n_data, n_parity);
	assert(n_data >= 2 && n_data <= 10);
	assert(n_parity == 1);
	assert(fragments);
	uv_buf_t* to = NULL, *from[n_data];

	/* Iterate trough the fragments in order to detect
	 * what to restore and from where.
	 * The missing fragment has NULL data ptr
	 */
	for (int i = 0; i < n_data + n_parity; i++) {
	    if (!fragments[i].buf.base) {
		if (to)
			/* We can recover only one chunk */
			return -EFAULT;
		/* Caller has to provide us missing buffer size */
		if (!fragments[i].buf.len)
			return -EINVAL;
		to = &fragments[i].buf;
	    } else {
		    from[n_from++] = &fragments[i].buf;
	    }
	}
	if (!to) {
		/* Nothing to recover, exiting */
		return 0;
	}
	/* Allocate space for missing chunk */
	to->base = je_calloc(1, to->len);
	if (!to->base)
	    return -ENOMEM;
	int err = rtbuf_add(inst->to_be_freed, to, 1);
	if (err) {
	    je_free(to->base);
	    return err;
	}
	/* Do de-coding */
	for (size_t i = 0; i < to->len; i++) {
		for (int j = 0; j < n_from; j++)
			if (from[j]->len > i)
				to->base[i] ^= from[j]->base[i];
	}
	return 0;
}

static int
xor_codec_destroy(void* instance) {
	struct xor_codec_instance* inst = (struct xor_codec_instance*)instance;
	assert(inst);
	rtbuf_destroy(inst->to_be_freed);
	je_free(inst);
	return 0;
}

static int
xor_codec_init() {
	return 0;
}

static void
xor_codec_exit() {
}

static struct ec_codec_vtbl xor_codec = {
	.init = xor_codec_init,
	.exit = xor_codec_exit,
	.info = xor_codec_info,
	.create = xor_codec_create,
	.encode = xor_codec_encode,
	.recover = xor_codec_recover,
	.destroy = xor_codec_destroy
};

ec_codec_register(xor_codec);

#if EC_CM_TEST
static int
xor2_codec_info(struct ec_codec_info** info) {
	static ec_codec_format fmt[] = { EC_FORMAT_D2P1 };
	static struct ec_codec_info xor = {
		.id = EC_CID_XOR2,
		.formats = fmt,
		.n_formats = 1,
		.name = "xor2"
	};
	*info = &xor;
	return 0;
}

static struct ec_codec_vtbl xor2_codec = {
	.info = xor2_codec_info,
	.create = xor_codec_create,
	.encode = xor_codec_encode,
	.recover = xor_codec_recover,
	.destroy = xor_codec_destroy
};

ec_codec_register(xor2_codec);

static int
xor3_codec_info(struct ec_codec_info** info) {
	static ec_codec_format fmt[] = { EC_FORMAT_D2P1 };
	static struct ec_codec_info xor = {
		.id = EC_CID_XOR3,
		.formats = fmt,
		.n_formats = 1,
		.name = "xor3"
	};
	*info = &xor;
	return 0;
}

static struct ec_codec_vtbl xor3_codec = {
	.info = xor3_codec_info,
	.create = xor_codec_create,
	.encode = xor_codec_encode,
	.recover = xor_codec_recover,
	.destroy = xor_codec_destroy
};

ec_codec_register(xor3_codec);
#endif

