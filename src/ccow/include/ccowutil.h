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
#ifndef __CCOWUTIL_H__
#define __CCOWUTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <syscall.h>
#include <assert.h>
#include <uv.h>
#include <math.h>

#include "logger.h"
#include "ccow_err_inj.h"

#ifdef	__cplusplus
extern "C" {
#endif

void unload_crypto_lib();
void load_crypto_lib();

/*
 * Timing Macros
 */
#define TIMER_INIT()				\
	uint64_t _before = 0, _after = 0;

#define TIMER_START()				\
	_before = uv_hrtime();

#define TIMER_STOP(__num_tests, __str)					\
	_after = uv_hrtime();						\
	printf("%u %s:%d " #__str " ops:%lu %.2fus (%.3f us/op)\n", (uint32_t)pthread_self(), \
	    __func__, \
	    __LINE__, __num_tests, (_after - _before) / 1000.0,		\
	    (_after - _before) / (1000.0 * __num_tests ));		\
	fflush(stdout);

#define TIMER_RESTART()				\
	_after = 0;				\
	_before = uv_hrtime();
/*
 * Contexted Timing Macros
 */
#define TIMER_INIT_CTX		uint64_t _before, _after;

#define TIMER_START_CTX(__ctx_p)				\
	(__ctx_p)->_before = uv_hrtime();

#define TIMER_STOP_CTX(__ctx_p, __num_tests, __str)					\
	(__ctx_p)->_after = uv_hrtime();						\
	printf("%p %s:%d " #__str " ops:%lu %.2fus (%.3f us/op)\n", (__ctx_p), \
	    __func__, \
	    __LINE__, __num_tests, ((__ctx_p)->_after - (__ctx_p)->_before) / 1000.0,		\
	    ((__ctx_p)->_after - (__ctx_p)->_before) / (1000.0 * __num_tests ));

#define TIMER_RESTART_CTX(__ctx_p)				\
	(__ctx_p)->_after = 0;				\
	(__ctx_p)->_before = uv_hrtime();
/*
 * Slightly Threaded Macros.
 */
#define TIMER_INIT_PT()				\
	uint64_t _times[10];			\
	uint64_t _after;

#define TIMER_START_PT()			\
	_times[(uint32_t)pthread_self() % 10] = uv_hrtime();

#define TIMER_STOP_PT(__num_tests, __str)					\
	_after = uv_hrtime();						\
	printf("%u %s:%d " #__str " ops:%lu %.2fus (%.3f us/op)\n", (uint32_t)pthread_self(), \
	    __func__, \
	    __LINE__, __num_tests, (_after - _times[(uint32_t)pthread_self() % 10]) / 1000.0,		\
	    (_after - _times[(uint32_t)pthread_self() % 10]) / (1000.0 * __num_tests ));		\
	fflush(stdout);

#define TIMER_RESTART_PT()				\
	_times[(uint32_t)pthread_self() % 10] = uv_hrtime();

#ifdef NEDGE_NDEBUG
#define nassert(st) do { } while(0)
#else
#define nassert(st) assert(st)
#endif

static inline unsigned long ccow_gettid() {
	return syscall(SYS_gettid);
}


/*
 * uint64_t Hamming weight calculation
 * Borrowed from https://en.wikipedia.org/wiki/Hamming_weight
 */
#define M1 0x5555555555555555L
#define M2 0x3333333333333333L
#define M4 0x0f0f0f0f0f0f0f0fL
#define M8 0x00ff00ff00ff00ffL
#define M16 0x0000ffff0000ffffL
#define M32 0x00000000ffffffffL

static inline int uint64_hweight(uint64_t pv)
{
	pv = (pv & M1 ) + ((pv >>  1) & M1 );
	pv = (pv & M2 ) + ((pv >>  2) & M2 );
	pv = (pv & M4 ) + ((pv >>  4) & M4 );
	pv = (pv & M8 ) + ((pv >>  8) & M8 );
	pv = (pv & M16) + ((pv >> 16) & M16);
	pv = (pv & M32) + ((pv >> 32) & M32);
	return pv;
}

void uint64_to_hex(uint64_t n, char *s);

/*
 * uint128_t library
 * =================
 */
typedef struct { uint64_t u; uint64_t l; } uint128_t;
extern uint128_t uint128_null;
#define UINT128_BYTES sizeof (uint128_t)
#define UINT128_STR_BYTES (2 * UINT128_BYTES + 1)

#define uint128_lo(pv) ((pv)->l)
#define uint128_hi(pv) ((pv)->u)
static inline void uint128_set8(uint128_t *pv, uint8_t v[UINT128_BYTES]) {
	memcpy(pv, v, UINT128_BYTES);
}
static inline void uint128_set64(uint128_t *pv, uint64_t u, uint64_t l) {
	pv->u = u;
	pv->l = l;
}
static inline void uint128_set(uint128_t *pv1, uint128_t *pv2) {
	pv1->u = pv2->u;
	pv1->l = pv2->l;
}
static inline void uint128_xor(uint128_t *pv1, uint128_t *pv2) {
	pv1->u ^= pv2->u;
	pv1->l ^= pv2->l;
}
static inline int uint128_cmp(const uint128_t *pv1, const uint128_t *pv2) {
	if (pv1->u == pv2->u) {
		if (pv1->l == pv2->l)
			return 0;
		return pv1->l < pv2->l ? -1 : 1;
	}
	return pv1->u < pv2->u ? -1 : 1;
}
static inline uint128_t uint128_shiftl(uint128_t *pv, int shift) {
	uint128_t r = { 0, 0 };
	if (shift >= 128) {
		return r;
	} else if (shift == 64) {
		r.u = pv->l;
		return r;
	} else if (shift == 0) {
		return *pv;
	} else if (shift < 64) {
		r.u = (pv->u << shift) + (pv->l >> (64 - shift));
		r.l = pv->l << shift;
		return r;
	} else if ((128 > shift) && (shift > 64)) {
		r.u = pv->l << (shift - 64);
		return r;
	}
	return r;
}
static inline uint128_t uint128_shiftr(uint128_t *pv, int shift) {
	uint128_t r = { 0, 0 };
	if (shift >= 128) {
		return r;
	} else if (shift == 64) {
		r.l = pv->u;
		return r;
	} else if (shift == 0) {
		return *pv;
	} else if (shift < 64) {
		r.u = pv->u >> shift;
		r.l = (pv->u << (64 - shift)) + (pv->l >> shift);
		return r;
	} else if ((128 > shift) && (shift > 64)) {
		r.l = pv->u >> (shift - 64);
		return r;
	}
	return r;
}
static inline void uint128_dump(const uint128_t *pv, char *out, size_t len)
{
	assert(len >= UINT128_BYTES * 2 + 1);
	uint64_to_hex(uint128_hi(pv), &out[0]);
	uint64_to_hex(uint128_lo(pv), &out[16]);
}
#define uint128_logdump(l, desc, pv) do {				\
	if (unlikely(LOG_LEVEL_DUMP >= (l)->level)) {			\
		char out[UINT128_BYTES * 2 + 1];			\
		uint128_dump((pv), out, UINT128_BYTES * 2 + 1);		\
		log_debug((l), "%s: %s", (desc), out);			\
	}								\
} while(0)
static inline void uint128_fromhex(const char *in, size_t len, uint128_t *pv)
{
	char buf[17];
	buf[16] = 0;

	assert(len <= UINT128_BYTES * 2 + 1);
	memcpy(buf, in, 16);
	uint128_hi(pv) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 16, 16);
	uint128_lo(pv) = strtoull(buf, NULL, 16);
}

static inline void uint128_bset(uint128_t *pv, uint16_t pos)
{
	assert(pos < 8*UINT128_BYTES);
	if (pos >= 8*sizeof(uint64_t))
		pv->u |= 1L << (pos - 8*sizeof(uint64_t));
	else
		pv->l |= 1L << pos;
}

static inline int uint128_bcheck(const uint128_t *pv, uint16_t pos)
{
	assert(pos < 8*UINT128_BYTES);
	if (pos >= 8*sizeof(uint64_t))
		return pv->u & (1L << (pos - 8*sizeof(uint64_t)));
	else
		return pv->l & (1L << pos);
}

static inline int uint128_hweight(const uint128_t *pv)
{
	int rc = uint64_hweight(pv->l);
	if (rc == 8*sizeof(uint64_t))
		rc += uint64_hweight(pv->u);
	return rc;
}
#define UINT128_STR_BYTES	(2 * UINT128_BYTES + 1)

/*
 * uint256_t library
 * =================
 */
typedef struct { uint128_t u; uint128_t l; } uint256_t;
extern uint256_t uint256_null;
#define UINT256_BYTES sizeof (uint256_t)
#define uint256_lo(pv) ((pv)->l)
#define uint256_hi(pv) ((pv)->u)
static inline int uint256_cmp(const uint256_t *pv1, const uint256_t *pv2) {
	int ret = uint128_cmp(&pv1->u, &pv2->u);
	if (!ret)
		ret = uint128_cmp(&pv1->l, &pv2->l);
	return ret;
}
static inline void uint256_xor(uint256_t *pv1, uint256_t *pv2) {
	uint128_xor(&pv1->u, &pv2->u);
	uint128_xor(&pv1->l, &pv2->l);
}
static inline void uint256_dump(const uint256_t *pv, char *out, size_t len)
{
	assert(len >= UINT256_BYTES * 2 + 1);
	uint128_dump(&pv->u, out, UINT128_BYTES * 2 + 1);
	uint128_dump(&pv->l, out + UINT128_BYTES * 2, UINT128_BYTES * 2 + 1);
}

static inline void uint256_bset(uint256_t *pv, uint16_t pos)
{
	assert(pos < 8*UINT256_BYTES);
	if (pos >= 8*UINT128_BYTES)
		uint128_bset(&pv->u, pos - 8*UINT128_BYTES);
	else
		uint128_bset(&pv->l, pos);
}

static inline int uint256_bcheck(const uint256_t *pv, uint16_t pos)
{
	assert(pos < 8*UINT256_BYTES);
	if (pos >= 8*UINT128_BYTES)
		return uint128_bcheck(&pv->u, pos - 8*UINT128_BYTES);
	else
		return uint128_bcheck(&pv->l, pos);
}

static inline int uint256_hweight(const uint256_t *pv)
{
	int rc = uint128_hweight(&pv->l);
	if (rc == 8*UINT128_BYTES)
		rc += uint128_hweight(&pv->u);
	return rc;
}

/*
 * uint512_t library
 * =================
 */
typedef struct { uint256_t u; uint256_t l; } uint512_t;
extern uint512_t uint512_null;
#define UINT512_BYTES sizeof (uint512_t)
#define uint512_lo(pv) ((pv)->l)
#define uint512_hi(pv) ((pv)->u)
static inline int uint512_cmp(const uint512_t *pv1, const uint512_t *pv2) {
	/* cmp optimization for mostly non-equal comparisions */
	if (pv1->u.u.u != pv2->u.u.u)
		return pv1->u.u.u < pv2->u.u.u ? -1 : 1;
	int ret = uint256_cmp(&pv1->u, &pv2->u);
	if (!ret)
		ret = uint256_cmp(&pv1->l, &pv2->l);
	return ret;
}
static inline void uint512_xor(uint512_t *pv1, uint512_t *pv2) {
	uint256_xor(&pv1->u, &pv2->u);
	uint256_xor(&pv1->l, &pv2->l);
}
static inline void uint512_setstr(uint512_t *pv, char *s) {
	strcpy((char *)pv, s);
}
static inline void uint512_dump(const uint512_t *pv, char *out, size_t len)
{
	assert(len >= UINT512_BYTES * 2 + 1);
	uint256_dump(&pv->u, out, UINT256_BYTES * 2 + 1);
	uint256_dump(&pv->l, out + UINT256_BYTES * 2, UINT256_BYTES * 2 + 1);
}
#define uint512_logdump(l, desc, pv) do {				\
	if (unlikely(LOG_LEVEL_DUMP >= (l)->level)) {			\
		char out[UINT512_BYTES * 2 + 1];			\
		uint512_dump((pv), out, UINT512_BYTES * 2 + 1);		\
		log_debug((l), "%s: %s", (desc), out);			\
	}								\
} while(0)
static inline void uint512_fromhex(const char *in, size_t len, uint512_t *pv)
{
	char buf[17];
	buf[16] = 0;

	assert(len <= UINT512_BYTES * 2 + 1);
	memcpy(buf, in, 16);
	uint512_hi(&uint256_hi(&uint128_hi(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 16, 16);
	uint512_lo(&uint256_hi(&uint128_hi(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 32, 16);
	uint512_hi(&uint256_lo(&uint128_hi(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 48, 16);
	uint512_lo(&uint256_lo(&uint128_hi(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 64, 16);
	uint512_hi(&uint256_hi(&uint128_lo(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 80, 16);
	uint512_lo(&uint256_hi(&uint128_lo(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 96, 16);
	uint512_hi(&uint256_lo(&uint128_lo(pv))) = strtoull(buf, NULL, 16);
	memcpy(buf, in + 112, 16);
	uint512_lo(&uint256_lo(&uint128_lo(pv))) = strtoull(buf, NULL, 16);
}

#define UINT512_STR_BYTES	(2 * UINT512_BYTES + 1)

static inline uint64_t
get_time_ns(int clock_type) {
	struct timespec tp;

	(void)clock_gettime(clock_type, &tp);
	return ((tp.tv_sec * 1000000000) + tp.tv_nsec);
}

static inline uint64_t
get_realtime_ns() {
	return get_time_ns(CLOCK_REALTIME);
}

 static inline uint64_t get_timestamp_us() {
	return get_realtime_ns() / 1000;
}

static inline uint64_t get_timestamp_monotonic_us() {
	return get_time_ns(CLOCK_MONOTONIC) / 1000;
}

uint64_t nondecreasing_get_realtime_ns();

static inline uint64_t get_nondecreasing_timestamp_us() {
	return nondecreasing_get_realtime_ns() / 1000;
}

#ifdef USE_JE_MALLOC
#include <jemalloc/jemalloc.h>
static inline char *je_strndup(const char *s, int len) {
	if (!s || !len)
		return NULL;
	char *p = je_malloc(len + 1);
	*(p + len) = 0;
	return p ? strncpy(p, s, len) : NULL;
}

static inline char *je_strdup(const char *s) {
	if (!s)
		return NULL;
	size_t len = 1 + strlen(s);
	char *p = je_malloc(len);
	return p ? strncpy(p, s, len) : NULL;
}

static inline char *je_memdup(const char *s, size_t size) {
	if (!s || !size)
		return NULL;
	char *p = je_malloc(size);
	return p ? memcpy(p, s, size) : NULL;
}
#else
#define je_strdup      strdup
#define je_strndup     strndup

static inline char *je_memdup(const char *s, size_t size) {
	assert(s);
	assert(size);
	char *p = (char *)malloc(size);
	return p ? (char *)memcpy(p, s, size) : NULL;
}

#define je_free		free
#define je_malloc	malloc
#define je_calloc	calloc
#define je_realloc	realloc
#endif

static inline int memcmp_quick(const void *m1, size_t s1, const void *m2,
    size_t s2) {
	/*
	 * for performance reasons if we know src/dst length we just compare
	 * lengths and not touching memory. This however makes this function
	 * POSIX incompatible and therefore caller has to be aware of this.
	 */
	if (s1 != s2)
		return -1;
	return memcmp(m1, m2, s1);
}

static inline int memcmp_safe(const void *m1, size_t s1, const void *m2,
    size_t s2) {
	size_t min = s1 > s2 ? s2 : s1;
	return memcmp(m1, m2, min);
}


#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

#define panic(panicmsg...) do { \
	fprintf(stderr, panicmsg); \
	fflush(stderr); \
	abort(); \
} while (0)

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type,member) );})
#endif

/* uv-hpt interface */
#ifdef CCOW_USE_TIMERFD
#define UV_HPT_TIMER_T uv_poll_t
int uv_hpt_timer_start(int timerfd, UV_HPT_TIMER_T *req, uint64_t delay_us,
    uv_poll_cb poll_cb);
#define UV_HPT_TIMER_CB(_hpt_timer_cb, _req) \
	_hpt_timer_cb(uv_poll_t _req, int status, int events)
#else
#define UV_HPT_TIMER_T uv_timer_t
int uv_hpt_timer_start(int timerfd, UV_HPT_TIMER_T *req, uint64_t delay_us,
    uv_timer_cb poll_cb);
#define UV_HPT_TIMER_CB(_hpt_timer_cb, _req) \
	_hpt_timer_cb(uv_timer_t _req, int status)
#endif
int uv_hpt_timer_init(uv_loop_t *loop, UV_HPT_TIMER_T *req);
void uv_hpt_timer_stop(int timerfd, UV_HPT_TIMER_T *req);
void uv_hpt_timer_close(int timerfd, UV_HPT_TIMER_T *req);

/* netif utilities */
int ethtool_info(const char *ifname, uint32_t *speed_mbits, uint8_t *duplex,
    uint8_t *link_status, int *mtu);

int getifname(char *ipaddr, char *ifname);

int find_ipv6local(char *ifname, char *ip6addr);

void FNV_hash(const void *key, int length, uint32_t seed, void *out);

void tiny_hash(const void *key, int len, void *out);

void MurmurHash3_x64_128(const void *key, const int len, const uint32_t seed,
    void *out);

/* Generic json functions */
#define JSON_BUF_PAGE_SZ 4*1024		/* One Page size */

void json_file_buf_prepare();
void json_buf_put(FILE *fp, char *buf);
void json_buf_flush(FILE *fp);

#ifdef CCOW_VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

/* copy from linux/in6.h due to include issues */
#define IPV6_FLOWINFO_PRIORITY		0x0ff00000

#define HASHCALC(k, m)		((k)->u.u.u & (m))

static inline const char *
fmt(double d) {
	static char buf[1024];
	char *p = NULL;
	uint64_t v;

	memset(&buf[0], 0, sizeof (buf));
	if (p == NULL)
		p = buf;

	p += 31;

	if (p >= buf + sizeof (buf))
		return "<buffer too small>";

	v = (uint64_t)d;

	if (v == 0)
		*--p = '0';

	while (v) {
		if (v) *--p = '0' + (v % 10), v /= 10;
		if (v) *--p = '0' + (v % 10), v /= 10;
		if (v) *--p = '0' + (v % 10), v /= 10;
		if (v) *--p = ',';
	}

	return p;
}

/* Average time on a sub-set */
struct avg_ring {
#define AVG_RING_SIZE	64ULL
	uint32_t buffer[AVG_RING_SIZE];
	uint32_t oldest;
	uint64_t sum;
	uint64_t max;
	uint64_t mean;
	uint64_t mean_uncap;
};

/* If the max latency is higher, the drive is marked
 * degraded. We're trying to put a cap on the avg value
 * so error cases do not show up
 */
#define	AVG_RING_MAX_VAL	2000000UL

static inline uint64_t
avg_ring_update_limited(struct avg_ring *ring, uint64_t delta, uint64_t limit)
{
	/*
	 * Basic FIR ring buffer: keep a running buffer of the last N values,
	 * and a running SUM of all the values in the buffer. Each time a new
	 * sample comes in, subtract the oldest value in the buffer from SUM,
	 * replace it with the new sample, add the new sample to SUM,
	 * and output SUM/N.
	 */
	if (ring->sum > ring->buffer[ring->oldest])
		ring->sum -= ring->buffer[ring->oldest];
	else
		ring->sum = 0;
	ring->max = (ring->max > delta) ? ring->max : delta;
	ring->sum += delta;
	ring->buffer[ring->oldest] = delta;
	ring->oldest = (ring->oldest + 1) % AVG_RING_SIZE;
	ring->mean = ring->sum / AVG_RING_SIZE;
	if (!ring->mean) {
		ring->mean = 1;
	}
	ring->mean_uncap = ring->mean;
	if (limit && ring->mean > limit) {
		log_warn(lg, "avg %ld is now limited to %ld", ring->mean,
		    (long)limit);
		ring->mean = limit;
	}
	return ring->mean;
}

static inline uint64_t
avg_ring_update(struct avg_ring *ring, uint64_t delta)
{
	return avg_ring_update_limited(ring, delta, AVG_RING_MAX_VAL);
}


/*
 * variance^2 = Sum(Xi - Mean)/(NumElements - 1)
 * then
 * http://sphweb.bumc.bu.edu/otlt/MPH-Modules/BS/BS704_Probability/BS704_Probability10.html
 * do a table lookup for 90th and get 1.282
 *
 * 90th = (mean + (1.282 * variance))
 */

static inline uint64_t
avg_ring_90th(struct avg_ring *ring)
{
	uint64_t ssum= ring->max;
	uint32_t i;

	for (i = 0; i < AVG_RING_SIZE; i++) {
		int64_t mdiff = ring->buffer[i] - ring->mean;
		ssum += (mdiff * mdiff);
	}
	float variance = sqrt(ssum/(AVG_RING_SIZE - 1));
	return (uint64_t) (ring->mean + (1.282 * variance));
}

static inline double
avg_ring_std(struct avg_ring *ring)
{
	double std = 0.0;
	uint32_t i;

	for (i = 0; i < AVG_RING_SIZE; i++) {
		int64_t mdiff = ring->buffer[i] - ring->mean;
		std += (1.0 * mdiff * mdiff);
	}

	return sqrt(std / AVG_RING_SIZE);
}


char * b64_encode(const unsigned char* buffer, size_t length);

static inline void
strtohex(unsigned char *in, size_t insz, char *out, size_t outsz)
{
	unsigned char * pin = in;
	const char * hex = "0123456789ABCDEF";
	char * pout = out;
	for(; pin < in+insz; pout +=3, pin++){
		pout[0] = hex[(*pin>>4) & 0xF];
		pout[1] = hex[ *pin     & 0xF];
		pout[2] = ':';
		if ((size_t)(pout + 3 - out) > outsz){
			break;
		}
	}
	pout[-1] = 0;
}

static inline void
get_gwcache_addr(uint128_t *serverid, char listen_addr[],
		 size_t addr_len, char ifname[])
{
	assert(serverid != NULL);
	uint16_t addr_lobits = uint128_hi(serverid) & 0xffff;
	if (ifname && ifname[0] != '\0')
		snprintf(listen_addr, addr_len, "ff01::%x%%%s", addr_lobits, ifname);
	else
		snprintf(listen_addr, addr_len, "ff01::%x", addr_lobits);
}

int
serverid_init(uint128_t *serverid);

#define QUOTE(name) #name

#define KEY_BLOOM 25
#define KEY_BLOOM_BITLEN (1UL << KEY_BLOOM)
#define KEY_BLOOM_BYTELEN (KEY_BLOOM_BITLEN/8UL) + (((KEY_BLOOM_BITLEN%8UL)!=0UL) ? 1UL : 0UL)
#define KEY_BLOOM_BITSET(bv,idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define KEY_BLOOM_BITTEST(bv,idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))
#define KEY_BLOOM_ADD(tbl,hashv)                                                \
  KEY_BLOOM_BITSET((tbl), (hashv & (uint32_t)((1ULL << KEY_BLOOM) - 1U)))
#define KEY_BLOOM_TEST(tbl,hashv)                                               \
  KEY_BLOOM_BITTEST((tbl), (hashv & (uint32_t)((1ULL << KEY_BLOOM) - 1U)))

/* double-word - as in machine word - primitive
 * used for the double-compare-and-swap operations */
#ifdef __x86_64__
typedef __uint128_t DWORD;
#else
typedef __uint64_t DWORD;
#endif

#ifdef __x86_64__
#define SHIFT	  64
#define XADDx	  "xaddq"
#define CMPXCHGxB "cmpxchg16b"
#else
#define SHIFT	  32
#define XADDx	  "xaddl"
#define CMPXCHGxB "cmpxchg8b"
#endif
/* add-and-fetch: atomically adds @add to @mem
 *   @mem: pointer to value
 *   @add: value to add
 *
 *   returns: new value */
static inline unsigned int
atomic_aaf(volatile unsigned long *mem, unsigned long add)
{
	unsigned long __tmp = add;
	__asm__ __volatile__("lock " XADDx " %0,%1"
			:"+r" (add),
			"+m" (*mem)
			: : "memory");
	return add + __tmp;
}
#define atomic_inc(m) atomic_aaf(m, 1)
#define atomic_add(m,n) atomic_aaf(m, n)

/* add-negative: atomically adds @del to @mem
 *
 * @param mem pointer to value
 * @param mem value to substract
 * @returns true if
 */
static inline char
atomic_an(volatile unsigned long *mem, long del)
{
	char c = 0;
	__asm__ __volatile__("lock " XADDx " %2,%0; sets %1"
		     : "+m" (*mem), "=qm" (c)
		     : "r" (del) : "memory");
	return c;
}
#define atomic_dec(m) atomic_an(m, -1)
#define atomic_sub(m,n) atomic_an(m, (0-n))
/* compare-and-swap: atomically sets @mem to @new if value at @mem equals @old
 *
 * @mem: pointer to value
 * @old: old value
 * @new: new value
 * @returns: 0 on failure, non-zero on success
 */
static inline char
CAS(volatile unsigned long *mem, unsigned long old, unsigned long _new)
{
	unsigned long r;
	__asm__ __volatile__("lock cmpxchgl %k2,%1"
			: "=a" (r), "+m" (*mem)
			: "r" (_new), "0" (old)
			: "memory");
	return r == old ? 1 : 0;
}
/* double-compare-and-swap: atomically sets the two-word data at address @mem
 *                          to the two-word value of @new if value at @mem
 *                          equals @old
 *   @mem: pointer to value
 *   @old: old value
 *   @new: new value
 *
 *   returns: 0 on failure, non-zero on success */
static inline
char DWCAS(volatile DWORD *mem, DWORD old, DWORD _new)
{
#ifdef CCOW_VALGRIND
	extern uv_mutex_t valgrind_mutex;

	/*
	 * Valgrind do not support DWCAS yet, so we have to work around this
	 */
	if (RUNNING_ON_VALGRIND) {
		uv_mutex_lock(&valgrind_mutex);
		if (*mem == old) {
			*mem = _new;
			uv_mutex_unlock(&valgrind_mutex);
			return 1;
		}
		uv_mutex_unlock(&valgrind_mutex);
		return 0;
	}
#endif
	char r = 0;
	unsigned long old_h = old >> SHIFT, old_l = old;
	unsigned long new_h = _new >> SHIFT, new_l = _new;
	__asm__ __volatile__("lock; " CMPXCHGxB " (%6);"
		     "setz %7; "
		     : "=a" (old_l),
		       "=d" (old_h)
		     : "0" (old_l),
		       "1" (old_h),
		       "b" (new_l),
		       "c" (new_h),
		       "r" (mem),
		       "m" (r)
		     : "cc", "memory");
	return r;
}

static inline uint64_t
atomic_get_uint64(uint64_t* ptr) {
	return __sync_fetch_and_add(ptr,0);
}

static inline void
atomic_set_uint64(uint64_t* ptr, uint64_t value) {
	uint64_t aux = 0;
	do {
		aux = atomic_get_uint64(ptr);
	} while (!__sync_bool_compare_and_swap(ptr, aux, value));
}

#define atomic_dec64(ptr) (__sync_fetch_and_sub((ptr), 1))
#define atomic_inc64(ptr) (__sync_fetch_and_add((ptr), 1))
#define atomic_sub64(ptr, value) (__sync_fetch_and_sub((ptr), (value)))
#define atomic_add64(ptr, value) (__sync_fetch_and_add((ptr), (value)))

static inline char *
hash_id_to_buffer(uint512_t *hash_id, char *buf) {
	char hash[UINT512_BYTES*2+1];
	uint512_dump(hash_id, hash, UINT512_BYTES*2+1);
	memcpy(buf, hash, UINT512_BYTES*2+1);
	return buf;
}

static inline char *
uint128_to_buffer(uint128_t *u128, char *buf) {
	char str[UINT128_BYTES*2+1];
	uint128_dump(u128, str, UINT128_BYTES*2 + 1);
	memcpy(buf, str, UINT128_BYTES*2+1);
	return buf;
}


static inline char *
binary_to_hex(void *value, int length, char *buf, int len) {
	int num = length;
	if (num*2 > (len-1)) {
		num = (len - 1)/2;
	}
	char *cur = buf;
	for (int i=0; i < num; i++) {
		sprintf(cur,"%02x", *((uint8_t *)value + i));
		cur += 2;
	}
	*cur = 0;
	return buf;
}

static inline const char*
nedge_path() {
	static const char* pref = NULL;
	if (!pref) {
		pref = getenv("NEDGE_HOME");
		if (!pref)
			pref = "/opt/nedge";
	}
	return pref;
}

int pidfile_verify(char *pidfile, char *progname);

extern int ccow_embedded;

static inline int
is_embedded() {
	if (ccow_embedded < 0)
		ccow_embedded = getenv("CCOW_EMBEDDED") ? 1 : 0;
	return ccow_embedded;
}


/*
 * Make sure load_crypto_lib() is called prior ccow_calc_nhid()
 */
int
ccow_calc_nhid(const char* cid, const char* tid, const char* bid, const char* oid,
	uint512_t* nhid);
#ifdef	__cplusplus
}
#endif

#endif
