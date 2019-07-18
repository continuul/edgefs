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
#ifndef __RTBUF_H__
#define __RTBUF_H__

#include "ccowutil.h"
#include "crypto.h"

#ifdef	__cplusplus
extern "C" {
#endif

static uint8_t override_marker[116] = {
		0xbb,0x0f,0x54,0x04,0x8a,0x70,0xe7,0x09,
		0x09,0x0c,0xb9,0x8e,0x66,0x6e,0x71,0x42,
		0x2f,0x94,0x45,0x55,0x81,0x9c,0x85,0xd1,
		0xe3,0x4a,0x83,0x53,0x5e,0xe1,0x28,0x16,
		0x9b,0x73,0x01,0xf2,0xe2,0x74,0x00,0x88,
		0xa8,0x77,0x6a,0x9c,0x81,0xdb,0x1c,0x68,
		0xaa,0xbc,0x96,0xc9,0x97,0xf4,0x03,0x65,
		0xcf,0x7d,0x35,0xff,0xa6,0xe6,0x4d,0x15,
		0x1c,0xf1,0x97,0x2b,0x7b,0xb5,0x06,0x4e,
		0x0f,0x78,0x2e,0xe5,0x5b,0x37,0xdc,0x89,
		0x09,0x55,0x52,0xfe,0xfe,0x48,0x23,0x73,
		0xbe,0x44,0xf6,0x8a,0xda,0x89,0x87,0xad,
		0x96,0x6a,0xf9,0x68,0x95,0x52,0x6a,0x9c,
		0x28,0x0b,0xf7,0xca,0x91,0x33,0xc1,0xc7,
		0x52,0x1e,0x8f,0xff
};

static size_t override_marker_size = sizeof(override_marker) + 12;
/*
 * Replicast Transport Buffer API
 *
 * For performance purposes and since majority of functions small/compact,
 * it is implemented as fully inlined set of functions.
 *
 * rtbuf_init()	initialize rtbuf_t and allocate space for bufs/nbufs
 * rtbuf_add()	add more bufs/nbufs at the end
 */
typedef struct {
	uv_buf_t *bufs;
	size_t nbufs;
#define RTBUF_ATTR_MMAP		0x1	/* buffer is mmapped */
#define RTBUF_ATTR_RSVD1	0x2
#define RTBUF_ATTR_RSVD2	0x4

/* encode/decode compression type into rtbuf struct itself */
#define RTBUF_ATTR_COMP_TYPE(_attr)		((_attr >> 4) & 0xF)
#define RTBUF_ATTR_COMP_TYPE_SET(_attr, _compress_type) \
	(_attr) = (_compress_type) << 4 | ((_attr) & 0x0F)
	uint8_t *attrs;
} rtbuf_t;

/*
 * Accessor helper.
 *
 * For example, to access bufs[0] the following construct can be used:
 *
 * rtbuf(rb, 0).base
 * rtbuf(rb, 0).len
 *
 * @internal
 */
#define rtbuf(_rb, _n) (_rb)->bufs[(_n)]
#define rtbuf_iovec(_rb, _n) (struct iovec *)&(_rb)->bufs[(_n)]
#define rtbuf_attr(_rb, _n) (_rb)->attrs[(_n)]

/*
 * Allocate new rtbuf_t with supplied buffers assigned
 * @internal
 */
static inline rtbuf_t *
rtbuf_init(uv_buf_t bufs[], size_t nbufs)
{
	rtbuf_t *rb;
	rb = je_calloc(1, sizeof (rtbuf_t));
	if (!rb)
		return NULL;
	if (!nbufs)
		return rb;
	rb->bufs = je_calloc(nbufs, sizeof (uv_buf_t) + sizeof (uint64_t));
	if (!rb->bufs) {
		je_free(rb);
		return NULL;
	}
	if (bufs)
		memcpy(rb->bufs, bufs, nbufs * sizeof (uv_buf_t));
	rb->attrs = (uint8_t *)rb->bufs + (nbufs * sizeof (uv_buf_t));
	rb->nbufs = nbufs;
	return rb;
}

/*
 * Expand available number of buffers
 * @internal
 */
static inline int
rtbuf_expand(rtbuf_t* rb, size_t nbufs_new)
{
	if (rb->nbufs >= nbufs_new)
		return -EINVAL;

	uv_buf_t* buf_prev = rb->bufs;

	rb->bufs = je_calloc(nbufs_new, sizeof (uv_buf_t) + sizeof (uint64_t));
	if (!rb->bufs)
		return -ENOMEM;
	if (buf_prev) {
		memcpy(rb->bufs, buf_prev, rb->nbufs * sizeof (uv_buf_t));
		memcpy((uint8_t *)rb->bufs + (nbufs_new * sizeof (uv_buf_t)),
			rb->attrs, rb->nbufs*sizeof(uint64_t));
	}
	rb->attrs = (uint8_t *)rb->bufs + (nbufs_new * sizeof (uv_buf_t));
	rb->nbufs = nbufs_new;
	je_free(buf_prev);
	return 0;
}

/*
 * Allocate new empty rtbuf_t with zero buffers
 * @internal
 */
static inline rtbuf_t *
rtbuf_init_empty()
{
	return rtbuf_init(NULL, 0);
}

/*
 * Allocate new rtbuf_t with supplied buffers assigned as mapped memory
 * @internal
 */
static inline rtbuf_t *
rtbuf_init_mapped(uv_buf_t bufs[], size_t nbufs)
{
	rtbuf_t *rb = rtbuf_init(bufs, nbufs);
	if (!rb)
		return NULL;
	size_t i;
	for (i = 0; i < rb->nbufs; i++)
		rb->attrs[i] |= RTBUF_ATTR_MMAP;
	return rb;
}

/*
 * Allocate new rtbuf_t and one buffer of supplied size 'len'
 * @internal
 */
static inline rtbuf_t *
rtbuf_init_alloc_one(size_t len)
{
	uv_buf_t buf;
	buf.len = len;
	buf.base = je_malloc(len);
	if (!buf.base)
		return NULL;
	return rtbuf_init(&buf, 1);
}

/*
 * Allocate new rtbuf_t with and initial buffers with preallocated memory
 * @internal
 */
static inline rtbuf_t *
rtbuf_init_alloc(uv_buf_t bufs[], size_t nbufs)
{
	size_t i;
	uv_buf_t new_bufs[nbufs];

	for (i = 0; i < nbufs; i++) {
		int len = bufs[i].len;
		new_bufs[i].len = len;
		new_bufs[i].base = je_malloc(len);
		if (!new_bufs[i].base) {
			for (; i > 0; --i)
				je_free(new_bufs[i].base);
			return NULL;
		}
		memcpy(new_bufs[i].base, bufs[i].base, len);
	}
	rtbuf_t *rb = rtbuf_init(new_bufs, nbufs);
	if (!rb) {
		for (i = 0; i < nbufs; i++)
			je_free(new_bufs[i].base);
		return NULL;
	}
	return rb;
}

/*
 * Add new buffers to the end of rtbuf_t's uv_buf_t array
 * @internal
 */
static inline int
rtbuf_add(rtbuf_t *rb, uv_buf_t bufs[], size_t nbufs)
{
	/* nothig to add */
	if (!bufs || !nbufs)
		return 0;

	uv_buf_t *bufs_new = je_realloc(rb->bufs,
	    (sizeof (uint8_t) + sizeof (uv_buf_t)) * (rb->nbufs + nbufs));
	if (!bufs_new)
		return -ENOMEM;
	uint8_t *attrs_new = (uint8_t *)bufs_new +
		((rb->nbufs + nbufs) * sizeof (uv_buf_t));
	/* copyin old attributes to a new loc */
	memmove(attrs_new, bufs_new + rb->nbufs, rb->nbufs * sizeof(uint8_t));
	/* reseting newly allocated attributes */
	memset(attrs_new + rb->nbufs, 0, nbufs);
	/* adding new buffers at the end of old loc */
	memcpy(bufs_new + rb->nbufs, bufs, nbufs * sizeof (uv_buf_t));
	rb->bufs = bufs_new;
	rb->attrs = attrs_new;
	rb->nbufs += nbufs;
	return 0;
}


/*
 * Add new buffers with newly allocted memory to the end of
 * rtbuf_t's uv_bufs_t array and copy
 * @internal
 */
static inline int
rtbuf_add_alloc(rtbuf_t *rb, uv_buf_t bufs[], size_t nbufs)
{
	int err;
	size_t i;
	uv_buf_t new_bufs[nbufs];

	/* nothig to add */
	if (!bufs || !nbufs)
		return 0;

	for (i = 0; i < nbufs; i++) {
		int len = bufs[i].len;
		new_bufs[i].len = len;
		new_bufs[i].base = je_malloc(len);
		if (!new_bufs[i].base) {
			for (; i > 0; --i)
				je_free(new_bufs[i].base);
			return -ENOMEM;
		}
		memcpy(new_bufs[i].base, bufs[i].base, len);
	}
	err = rtbuf_add(rb, new_bufs, nbufs);
	if (err) {
		for (i = 0; i < nbufs; i++)
			je_free(new_bufs[i].base);
		return err;
	}
	return 0;
}

/*
 * Set existing buffers at offset with newly allocted memory and copy
 * @internal
 */
static inline int
rtbuf_set_alloc(rtbuf_t *rb, int offset, uv_buf_t bufs[], size_t nbufs)
{
	size_t i;
	uv_buf_t new_bufs[nbufs];

	for (i = 0; i < nbufs; i++) {
		int len = bufs[i].len;
		new_bufs[i].len = len;
		new_bufs[i].base = je_malloc(len);
		if (!new_bufs[i].base) {
			for (; i > 0; --i)
				je_free(new_bufs[i].base);
			return -ENOMEM;
		}

		/* copy bufs contents into newly allocated new_bufs */
		memcpy(new_bufs[i].base, bufs[i].base, len);

		rtbuf(rb, offset + i) = new_bufs[i];
		rtbuf_attr(rb, offset + i) = 0;
	}

	return 0;
}

static inline void
rtbuf_set(rtbuf_t *rb, int offset, uv_buf_t bufs[], size_t nbufs)
{
	assert(rb->nbufs >= offset + nbufs);
	for (size_t i = 0; i < nbufs; i++) {
		rtbuf(rb, offset + i) = bufs[i];
		rtbuf_attr(rb, offset + i) = 0;
	}
}

/*
 * Add new buffer with newly allocted memory of specified length
 * to the end of rtbuf_t's uv_bufs_t array
 * @internal
 */
static inline int
rtbuf_add_alloc_one(rtbuf_t *rb, size_t len)
{
	int err;
	uv_buf_t buf;
	buf.len = len;
	buf.base = je_malloc(len);
	if (!buf.base)
		return -ENOMEM;

	err = rtbuf_add(rb, &buf, 1);
	if (err)
		je_free(buf.base);
	return err;
}

/*
 * Add new buffers to the end of rtbuf_t's uv_buf_t array and mark
 * buffers as memory mapped to the other preexisting region
 * @internal
 */
static inline int
rtbuf_add_mapped(rtbuf_t *rb, uv_buf_t bufs[], size_t nbufs)
{
	int err;

	/* nothig to add */
	if (!bufs || !nbufs)
		return 0;

	err = rtbuf_add(rb, bufs, nbufs);
	if (err)
		return err;
	size_t i;
	for (i = rb->nbufs - nbufs; i < rb->nbufs; i++)
		rb->attrs[i] |= RTBUF_ATTR_MMAP;
	return 0;
}


/*
 * Check for override marker
 */
static inline int
rtbuf_is_override(const rtbuf_t *rb)
{
	if (!rb || !rb->nbufs)
		return 0;

	size_t last = rb->nbufs - 1;
	uint8_t *base = (uint8_t *)rtbuf(rb, last).base;
	size_t len = rtbuf(rb, last).len;

	if (base && len > override_marker_size && base[len - 1] == 0xff) {
		if (memcmp(base + (len - sizeof(override_marker)),
				override_marker, sizeof(override_marker)) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Calculate hash of all buffers
 * @internal
 */
static inline int
rtbuf_hash(const rtbuf_t *rb, crypto_hash_t hash_type, uint512_t *out)
{
	int err;

	crypto_state_t S;
	err = crypto_init_with_type(&S, hash_type);
	if (err)
		return err;
	size_t i;
	size_t last = rb->nbufs - 1;
	uint8_t *base;
	size_t len;
	for (i = 0; i < rb->nbufs; i++) {
		base = (uint8_t *)rtbuf(rb, i).base;
		len = rtbuf(rb, i).len;
		// Check for overwrite marker
		if (i == last && len > override_marker_size && base[len - 1] == 0xff) {
			if (memcmp(base + (len - sizeof(override_marker)),
				override_marker,  sizeof(override_marker)) == 0) {
				void *marker_start = base + len - override_marker_size;
				uint32_t lx;
				memcpy(&lx, marker_start, 4);
				len = lx;
			}
		}
		err = crypto_update(&S, base, len);
		if (err)
			return err;
	}
	err = crypto_final(&S, (uint8_t *)out);
	return err;
}

/*
 * Return total length of all the chained buffers
 * @internal
 */
static inline size_t
rtbuf_len(const rtbuf_t *rb)
{
	size_t len = 0;
	size_t i;
	for (i = 0; rb && i < rb->nbufs; i++)
		len += rb->bufs[i].len;
	return len;
}

static inline void
rtbuf_free_one(rtbuf_t *rb, int i)
{
	if (!rb->bufs[i].base)
		return;
	if (rb->attrs[i] & RTBUF_ATTR_MMAP)
		return;
	je_free(rb->bufs[i].base);
}

/*
 * Deallocate buffers but keep rtbuf_t and bufs
 * @internal
 */
__attribute__((always_inline)) static inline void
rtbuf_free(rtbuf_t *rb)
{
	size_t i;
	for (i = 0; i < rb->nbufs; i++) {
		rtbuf_free_one(rb, i);
	}
	rb->nbufs = 0;
}

/*
 * Deallocate buffers but keep rtbuf_t
 * @internal
 */
__attribute__((always_inline)) static inline void
rtbuf_free2(rtbuf_t *rb)
{
	rtbuf_free(rb);
	if (rb->bufs) {
		je_free(rb->bufs);
		rb->bufs = NULL;
	}
}

/*
 * Deallocate just rtbuf_t itself but keep buffers
 * @internal
 */
__attribute__((always_inline)) static inline void
rtbuf_clean(rtbuf_t *rb)
{
	if (rb->bufs) {
		je_free(rb->bufs);
		rb->bufs = NULL;
	}
	je_free(rb);
}

/*
 * Deallocate buffers and rtbuf_t itself
 * @internal
 */
static inline void
rtbuf_destroy(rtbuf_t *rb)
{
	rtbuf_free(rb);
	rtbuf_clean(rb);
}

/*
 * Deallocate buffers only if nbufs and rtbuf_t itself
 * @internal
 */
static inline void
rtbuf_destroy_safe(rtbuf_t *rb)
{
	int nbufs_saved = rb->nbufs;
	rtbuf_free(rb);
	if (rb->bufs && nbufs_saved)
		je_free(rb->bufs);
	je_free(rb);
}

/*
 * Deallocate buffers and rtbuf_t itself
 * @internal
 */
static inline void
rtbuf_flat_destroy(rtbuf_t *rb)
{
	je_free(rb);
}

/*
 * Delete a single element from the input rtbuf from position element
 * On return the output rtbuf* is allocated and the input rtbuf free'd
 * returns NULL on error
 * @internal
 */
static inline int
rtbuf_delete_element(rtbuf_t *input, size_t element)
{
	assert(input);
	if (input->nbufs == 0)
		return -ENOMEM;
	if (input->nbufs <= element)
		return -ENOMEM;

	/* Deleting the last element in the rtbuf */
	if (input->nbufs == 1) {
		rtbuf_free_one(input, 0);
		je_free(input->bufs);
		input->bufs = NULL;
		input->attrs = NULL;
		input->nbufs = 0;
		return 0;
	}

	/*
	 * Create a new rtbuf, output, which is input->nbufs-1 sized and
	 * simply copy the base pointers and lengths from input buffer,
	 * copy the input attrs as well.
	 */
	uv_buf_t *bufs_new = je_malloc((sizeof (uint8_t) +
		    sizeof (uv_buf_t)) * (input->nbufs - 1));
	if (!bufs_new)
		return -ENOMEM;
	uint8_t *attrs_new = (uint8_t *)bufs_new +
		((input->nbufs - 1) * sizeof (uv_buf_t));
	for (size_t i = 0, k = 0; k < input->nbufs; i++, k++) {
		if (i == element) {
			rtbuf_free_one(input, k);
			k++;
		}
		if (k == input->nbufs)
			break;
		bufs_new[i].base = input->bufs[k].base;
		bufs_new[i].len = input->bufs[k].len;
		attrs_new[i] = input->attrs[k];
	}

	je_free(input->bufs);
	input->bufs = bufs_new;
	input->attrs = attrs_new;
	input->nbufs--;
	return 0;
}

static inline int
iovec_len(struct iovec *iov, size_t iovcnt)
{
	size_t len = 0;
	size_t i;
	for (i = 0; i < iovcnt; i++)
		len += iov[i].iov_len;
	return len;
}

static inline rtbuf_t *
rtbuf_clone(rtbuf_t *rb)
{
	assert(rb);
	rtbuf_t *clone = je_calloc(1, sizeof (rtbuf_t));
	if (clone == NULL)
		return NULL;

	clone->bufs =
		je_malloc(rb->nbufs * (sizeof(uv_buf_t) + sizeof (uint8_t)));
	if (clone->bufs == NULL) {
		je_free(clone);
		return NULL;
	}
	memcpy(clone->bufs, rb->bufs, rb->nbufs * sizeof(uv_buf_t));
	clone->attrs = (uint8_t *)clone->bufs + (rb->nbufs * sizeof(uv_buf_t));
	memcpy(clone->attrs, rb->attrs, rb->nbufs * sizeof(uint8_t));
	clone->nbufs = rb->nbufs;

	return clone;
}

static inline int
rtbuf_copy_bufs(rtbuf_t *rb, uv_buf_t *bufs, int *nbufs_out)
{
	assert(rb && bufs);

	for (size_t i = 0; i < rb->nbufs; ++i) {
		bufs[i].base = je_malloc(rb->bufs[i].len);
		if (bufs[i].base == NULL) {
			size_t j;
			for (j = 0; j < i; ++j)
				je_free(bufs[j].base);
			return -ENOMEM;
		}
		memcpy(bufs[i].base, rb->bufs[i].base, rb->bufs[i].len);
		bufs[i].len = rb->bufs[i].len;
	}

	*nbufs_out = rb->nbufs;
	return 0;
}

static inline rtbuf_t *
rtbuf_clone_bufs(rtbuf_t *rb)
{
	assert(rb);
	rtbuf_t *clone = je_calloc(1, sizeof (rtbuf_t));
	if (clone == NULL)
		return NULL;

	clone->bufs = je_calloc(rb->nbufs, sizeof(uv_buf_t) + sizeof(uint8_t));
	if (clone->bufs == NULL) {
		je_free(clone);
		return NULL;
	}
	clone->attrs = (uint8_t *)clone->bufs + (rb->nbufs * sizeof(uv_buf_t));
	size_t i;
	for (i = 0; i < rb->nbufs; ++i) {
		clone->bufs[i].base = je_malloc(rb->bufs[i].len);
		if (clone->bufs[i].base == NULL) {
			size_t j;
			for (j = 0; j < i; ++j)
				je_free(clone->bufs[j].base);
			je_free(clone->bufs);
			je_free(clone);
			return NULL;
		}
		memcpy(clone->bufs[i].base, rb->bufs[i].base, rb->bufs[i].len);
		clone->bufs[i].len = rb->bufs[i].len;
		clone->attrs[i] =
			rb->attrs[i] & ~(RTBUF_ATTR_MMAP);
	}
	clone->nbufs = rb->nbufs;

	return clone;
}

static inline rtbuf_t *
rtbuf_flat(rtbuf_t *rb, size_t *sz)
{
	size_t i;

	assert(rb);

	*sz = 0;

	size_t total_len = sizeof(rtbuf_t);
	total_len += rb->nbufs * (sizeof(uv_buf_t) + sizeof(uint8_t));

	for (i = 0; i < rb->nbufs; ++i) {
		total_len += rb->bufs[i].len;
	}

	rtbuf_t * new_rb = je_calloc(1, total_len);

	if (!new_rb)
		return NULL;

	uv_buf_t * new_bufs = (uv_buf_t *) ((char *) new_rb + sizeof(rtbuf_t));
	uint8_t * new_attrs = (uint8_t *) ((char *) new_bufs + (rb->nbufs * sizeof(uv_buf_t)));
	uint8_t * new_base = (uint8_t *) ((char *) new_attrs + (rb->nbufs * sizeof(uint8_t)));

	*new_rb = *rb;
	new_rb->bufs = new_bufs;
	new_rb->attrs = new_attrs;

	for (i = 0; i < rb->nbufs; i++) {

		memcpy(new_base, rb->bufs[i].base, rb->bufs[i].len);
		new_bufs[i].base = (void *) new_base;
		new_bufs[i].len  = rb->bufs[i].len;
		new_attrs[i] = rb->attrs[i];

		new_base += rb->bufs[i].len;
	}

	*sz = total_len;
	return new_rb;
}

static inline rtbuf_t *
rtbuf_serialize(rtbuf_t *rb)
{
	size_t i;
	size_t total_len = 0;

	assert(rb);

	for (i = 0; i < rb->nbufs; ++i) {
		total_len += rb->bufs[i].len;
	}

	rtbuf_t *new_rb;
	new_rb = je_calloc(1, sizeof (rtbuf_t));
	if (!new_rb)
		return NULL;
	new_rb->bufs = je_calloc(1, sizeof (uv_buf_t) + sizeof (uint64_t));
	if (!new_rb->bufs) {
		je_free(new_rb);
		return NULL;
	}
	new_rb->attrs = (uint8_t *)new_rb->bufs + (1 * sizeof (uv_buf_t));
	new_rb->nbufs = 1;

	new_rb->bufs[0].len = total_len;
	new_rb->bufs[0].base = je_malloc(total_len);
	if (!new_rb->bufs[0].base) {
		je_free(new_rb->bufs);
		je_free(new_rb);
		return NULL;
	}

	char *new_base = new_rb->bufs[0].base;

	for (i = 0; i < rb->nbufs; i++) {
		memcpy(new_base, rb->bufs[i].base, rb->bufs[i].len);
		new_base += rb->bufs[i].len;
	}

	return new_rb;
}

static inline int
rtbuf_serialize_bufs(uv_buf_t *bufs, size_t nbufs, uv_buf_t *out_bufs)
{
	size_t i;
	size_t total_len = 0;
	char *out;

	assert(bufs);

	for (i = 0; i < nbufs; ++i) {
		total_len += bufs[i].len;
	}

	out = je_malloc(total_len);
	if (!out)
		return -ENOMEM;

	char *new_base = out;

	for (i = 0; i < nbufs; i++) {
		memcpy(new_base, bufs[i].base, bufs[i].len);
		new_base += bufs[i].len;
	}

	out_bufs->base = out;
	out_bufs->len = total_len;
	return 0;
}

/**
 */
static inline int
rtbuf_chop_mapped(rtbuf_t *rb, size_t len, rtbuf_t **head, rtbuf_t **tail)
{
	size_t i, head_len = 0;
	*tail = NULL;
	if (rtbuf_len(rb) <= len) {
		*head = rtbuf_init_mapped(rb->bufs, rb->nbufs);
		return 0;
	}
	for (i = 0; i < rb->nbufs && head_len <= len; ++i)
		head_len += rb->bufs[i].len;

	if (head_len > len) {
		--i;
		/* Special case: first buf is longer than len */
		if (i == 0) {
			/* Chop the buffer in two */
			*head = rtbuf_init_mapped(rb->bufs, 1);
			*tail = rtbuf_init_mapped(rb->bufs, rb->nbufs);
			if (*tail == NULL || *head == NULL)
				return -ENOMEM;
			(*head)->bufs[0].len = len;
			(*tail)->bufs[0].base += len;
			(*tail)->bufs[0].len = rb->bufs[0].len - len;
		} else {
			*head = rtbuf_init_mapped(rb->bufs, i);
			*tail = rtbuf_init_mapped(rb->bufs + i, rb->nbufs - i);
			if (*tail == NULL || *head == NULL)
				return -ENOMEM;
		}
	}
	return 0;
}

#ifdef	__cplusplus
}
#endif

#endif
