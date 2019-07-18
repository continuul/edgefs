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
#undef log_info
#undef log_warn
#undef log_error
#undef log_debug
#include <liberasurecode/erasurecode.h>
#include <liberasurecode/erasurecode_helpers.h>

void add_fragment_metadata(ec_backend_t be, char *fragment,
	int idx, uint64_t orig_data_size, int blocksize,
	ec_checksum_type_t ct, int add_chksum);

/*
 * RS codec using EC_BACKEND_JERASURE_RS_VAND
 */
struct rs_codec_instance {
	ec_codec_format format;
	rtbuf_t*	to_be_freed;
	int		desc;
};

static uv_mutex_t ec_rs_access_mutex;

static int
rs_codec_info(struct ec_codec_info** info) {
	static ec_codec_format fmt[] = { EC_FORMAT_D2P1,
		EC_FORMAT_D3P1, EC_FORMAT_D4P1,
		EC_FORMAT_D5P1, EC_FORMAT_D6P1,
		EC_FORMAT_D7P1, EC_FORMAT_D8P1,
		EC_FORMAT_D9P1, EC_FORMAT_D10P1,
		EC_FORMAT_D2P2, EC_FORMAT_D3P2,
		EC_FORMAT_D4P2, EC_FORMAT_D5P2,
		EC_FORMAT_D6P2, EC_FORMAT_D7P2,
		EC_FORMAT_D8P2, EC_FORMAT_D9P2,
		EC_FORMAT_D10P2,EC_FORMAT_D2P3,
		EC_FORMAT_D3P3, EC_FORMAT_D4P3,
		EC_FORMAT_D5P3, EC_FORMAT_D6P3,
		EC_FORMAT_D7P3, EC_FORMAT_D8P3,
		EC_FORMAT_D9P3, EC_FORMAT_D10P3
	};
	static struct ec_codec_info rs = {
		.id = EC_CID_RS,
		.formats = fmt,
		.n_formats = 26,
		.name = "rs"
	};
	*info = &rs;
	return 0;
}

static int
rs_codec_init() {
	static int inited = 0;
	if (!inited) {
		uv_mutex_init(&ec_rs_access_mutex);
		inited = 1;
	}
	return 0;
}

static void
rs_codec_exit() {
	static int done = 0;
	if (!done) {
		uv_mutex_destroy(&ec_rs_access_mutex);
		done = 1;
	}
}

static int
rs_codec_create(ec_codec_format format, void** instance) {
	int n_data = 0, n_parity = 0;
	FROM_CODECFMT(format, n_data, n_parity);
	struct ec_args args = {
		.k = n_data,
		.m = n_parity,
		.hd = n_parity,
		.ct = CHKSUM_NONE
	};
	if (n_data < 2 || n_data > 10)
		return -EINVAL;
	struct rs_codec_instance* inst = je_calloc(1, sizeof(*inst));
	if (!inst)
		return -ENOMEM;
	inst->to_be_freed = rtbuf_init_empty();
	if (!inst->to_be_freed) {
		je_free(inst);
		return -ENOMEM;
	}
	uv_mutex_lock(&ec_rs_access_mutex);
	inst->desc = liberasurecode_instance_create(EC_BACKEND_JERASURE_RS_VAND , &args);
	uv_mutex_unlock(&ec_rs_access_mutex);
	if (!inst->desc) {
		je_free(inst);
		return -ENOMEM;
	}
	inst->format = format;
	*instance = inst;
	return 0;
}

static int
rs_codec_encode(void* instance, struct ec_fragment* data,
	struct ec_fragment* parity, uv_buf_t* context) {
	struct rs_codec_instance* inst = (struct rs_codec_instance*)instance;
	assert(inst);
	int n_data = 0, n_parity = 0;
	FROM_CODECFMT(inst->format, n_data, n_parity);
	assert(n_data >= 2 && n_data <= 10);
	assert(n_parity != 0);
	assert(data);
	assert(parity);

	parity[0].buf.len = 0;
	/* Calculate parity chunk size */
	for (int i = 0; i < n_data; i++) {
		if (data[i].buf.len > parity[0].buf.len)
			parity[0].buf.len = data[i].buf.len;
	}

	parity[0].buf.len = liberasurecode_get_aligned_data_size(inst->desc,
		parity[0].buf.len*n_data)/n_data;

	/* Allocate memory */
	/* NOTE: all data allocated by a codec have to be freed by the codec */
	for (int i = 0; i < n_parity; i++) {
		parity[i].buf.len = parity[0].buf.len;
		parity[i].buf.base = je_calloc(1, parity[0].buf.len);
		if (!parity[i].buf.base)
			return -ENOMEM;
		int err = rtbuf_add(inst->to_be_freed, &parity[i].buf, 1);
		if (err) {
			je_free(parity[i].buf.base);
			return err;
		}
		parity[i].index = n_data + i;
	}

	char *orig_data = je_calloc(n_data, parity[0].buf.len);
	if (!orig_data)
		return -ENOMEM;
	size_t orig_size = n_data * parity[0].buf.len;

	for (int i = 0; i < n_data; i++)
		memcpy(orig_data + i * parity[0].buf.len,
				data[i].buf.base, data[i].buf.len);

	char** encoded_data = NULL, **encoded_parity = NULL;
	uint64_t fragment_len = 0;
	uv_mutex_lock(&ec_rs_access_mutex);
	int err = liberasurecode_encode(inst->desc, orig_data, orig_size,
			&encoded_data, &encoded_parity, &fragment_len);
	uv_mutex_unlock(&ec_rs_access_mutex);
	if (err) {
		printf("error during chunk encode: %d\n", err);
		return -EINVAL;
	}

	je_free(orig_data);

	for (int i = 0; i < n_parity; i++)
		assert(parity[i].buf.len == fragment_len - sizeof(fragment_header_t));
	for (int i = 0; i < n_parity; i++) {
		memcpy(parity[i].buf.base, encoded_parity[i] + sizeof(fragment_header_t),
			fragment_len - sizeof(fragment_header_t));
	}
	liberasurecode_encode_cleanup(inst->desc, encoded_data, encoded_parity);
	/* rs codec doesn't use context, so just force its size to 0 */
	if (context)
		context->len = 0;
	return 0;
}

static int
rs_codec_recover(void* instance, struct ec_fragment* fragments,
	uv_buf_t* context) {
	struct rs_codec_instance* inst = (struct rs_codec_instance*)instance;
	assert(inst);
	int n_data = 0, n_parity = 0, n_from = 0, n_to = 0, err = 0;
	size_t len = 0;
	FROM_CODECFMT(inst->format, n_data, n_parity);
	assert(n_data >= 2 && n_data <= 10);
	assert(n_parity != 0);
	assert(fragments);
	uv_buf_t* to[n_parity];
	int idx[n_parity];
	char *from[n_data + n_parity];

	/* Fragment length always corresponds to size of a parity chunk
	 * It's supposed to be properly aligned by encoder
	 **/
	len = fragments[n_data].buf.len;
	/* Iterate trough the fragments in order to detect
	 * what to restore and from where.
	 * The missing fragment has NULL data ptr
	 */
	for (int i = 0; i < n_data + n_parity; i++) {
		if (!fragments[i].buf.base) {
			/* Caller has to provide us missing buffer size */
			if (!fragments[i].buf.len)
				return -EINVAL;
			to[n_to] = &fragments[i].buf;
			idx[n_to] = i;
			/* Allocate space for missing chunk */
			to[n_to]->base = je_calloc(1, to[n_to]->len);
			if (!to[n_to]->base)
			    return -ENOMEM;
			int err = rtbuf_add(inst->to_be_freed, to[n_to], 1);
			if (err) {
			    goto err;
			}
			n_to++;
			continue;
		}
		from[n_from] = je_calloc(1, len + sizeof(fragment_header_t));
		if (!from[n_from])
			return -ENOMEM;
		memcpy(from[n_from] + sizeof(fragment_header_t),
			fragments[i].buf.base, fragments[i].buf.len);
		init_fragment_header(from[n_from]);
		ec_backend_t be =
			liberasurecode_backend_instance_get_by_desc(inst->desc);
		add_fragment_metadata(be, from[n_from], fragments[i].index,
			fragments[i].buf.len, len, CHKSUM_NONE, 0);
		n_from++;
	}

	for(int i = 0; i < n_to; i++) {
		char *out_fragment = je_calloc(1, len + sizeof(fragment_header_t));
		if (!out_fragment)
			return -ENOMEM;
		uv_mutex_lock(&ec_rs_access_mutex);
		err = liberasurecode_reconstruct_fragment(inst->desc, from,
				n_from, len + sizeof(fragment_header_t), idx[i], out_fragment);
		uv_mutex_unlock(&ec_rs_access_mutex);
		if (err) {
			je_free(out_fragment);
			printf("liberasurecode_reconstruct_fragment() "
					"returned error: %d\n", err);
			goto err;
		}
		memcpy(to[i]->base, out_fragment + sizeof(fragment_header_t), to[i]->len);
		je_free(out_fragment);
	}
err:
	for(int i = 0; i < n_from; i++)
		je_free(from[i]);
	return err;
}

static int
rs_codec_destroy(void* instance) {
	struct rs_codec_instance* inst = (struct rs_codec_instance*)instance;
	assert(inst);
	rtbuf_destroy(inst->to_be_freed);
	uv_mutex_lock(&ec_rs_access_mutex);
	liberasurecode_instance_destroy(inst->desc);
	uv_mutex_unlock(&ec_rs_access_mutex);
	je_free(inst);
	return 0;
}

static struct ec_codec_vtbl rs_codec = {
	.init = rs_codec_init,
	.exit = rs_codec_exit,
	.info = rs_codec_info,
	.create = rs_codec_create,
	.encode = rs_codec_encode,
	.recover = rs_codec_recover,
	.destroy = rs_codec_destroy
};
ec_codec_register(rs_codec);

/*
 * RS codec using EC_BACKEND_JERASURE_RS_CAUCHY
 */
static int
rs_codec_cauchy_info(struct ec_codec_info** info) {
	static ec_codec_format fmt[] = { EC_FORMAT_D2P1,
		EC_FORMAT_D3P1, EC_FORMAT_D4P1,
		EC_FORMAT_D5P1, EC_FORMAT_D6P1,
		EC_FORMAT_D7P1, EC_FORMAT_D8P1,
		EC_FORMAT_D9P1, EC_FORMAT_D10P1,
		EC_FORMAT_D2P2, EC_FORMAT_D3P2,
		EC_FORMAT_D4P2, EC_FORMAT_D5P2,
		EC_FORMAT_D6P2, EC_FORMAT_D7P2,
		EC_FORMAT_D8P2, EC_FORMAT_D9P2,
		EC_FORMAT_D10P2,
		EC_FORMAT_D3P3, EC_FORMAT_D4P3,
		EC_FORMAT_D5P3, EC_FORMAT_D6P3,
		EC_FORMAT_D7P3, EC_FORMAT_D8P3,
		EC_FORMAT_D9P3, EC_FORMAT_D10P3
	};
	static struct ec_codec_info rs = {
		.id = EC_CID_RS_CAUCHY,
		.formats = fmt,
		.n_formats = 26,
		.name = "rs_cauchy"
	};
	*info = &rs;
	return 0;
}

static int
rs_codec_cauchy_create(ec_codec_format format, void** instance) {
	int n_data = 0, n_parity = 0;
	FROM_CODECFMT(format, n_data, n_parity);
	struct ec_args args = {
		.k = n_data,
		.m = n_parity,
		.hd = n_parity,
		.ct = CHKSUM_NONE
	};
	if (n_data < 2 || n_data > 10)
		return -EINVAL;

	struct rs_codec_instance* inst = je_calloc(1, sizeof(*inst));
	if (!inst)
		return -ENOMEM;
	inst->to_be_freed = rtbuf_init_empty();
	if (!inst->to_be_freed) {
		je_free(inst);
		return -ENOMEM;
	}
	uv_mutex_lock(&ec_rs_access_mutex);
	inst->desc = liberasurecode_instance_create(EC_BACKEND_JERASURE_RS_CAUCHY , &args);
	uv_mutex_unlock(&ec_rs_access_mutex);
	if (!inst->desc) {
		je_free(inst);
		return -ENOMEM;
	}
	inst->format = format;
	*instance = inst;
	return 0;
}
static struct ec_codec_vtbl rs_cauchy_codec = {
	.init = rs_codec_init,
	.exit = rs_codec_exit,
	.info = rs_codec_cauchy_info,
	.create = rs_codec_cauchy_create,
	.encode = rs_codec_encode,
	.recover = rs_codec_recover,
	.destroy = rs_codec_destroy
};

ec_codec_register(rs_cauchy_codec);
