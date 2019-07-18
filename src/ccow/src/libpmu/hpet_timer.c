// hpet_timer.c
//
// This code is derived from BSD licensed code copyrighted by Intel as part
// of the DPDK project. It is therefore still under the the BSD License

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2012-2013 6WIND S.A.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyrightmma
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include "pmu_private.h"

#define DEV_HPET "/dev/hpet"

/* Maximum number of counters. */
#define HPET_TIMER_NUM 3

/* General capabilities register */
#define CLK_PERIOD_SHIFT     32 /* Clock period shift. */
#define CLK_PERIOD_MASK      0xffffffff00000000ULL /* Clock period mask. */

/**
 * HPET timer registers. From the Intel IA-PC HPET (High Precision Event
 * Timers) Specification.
 */
struct hpet_regs {
	/* Memory-mapped, software visible registers */
	uint64_t capabilities;      /**< RO General Capabilities Register. */
	uint64_t reserved0;         /**< Reserved for future use. */
	uint64_t config;            /**< RW General Configuration Register. */
	uint64_t reserved1;         /**< Reserved for future use. */
	uint64_t isr;               /**< RW Clear General Interrupt Status. */
	uint64_t reserved2[25];     /**< Reserved for future use. */
	union {
		uint64_t counter;   /**< RW Main Counter Value Register. */
		struct {
			uint32_t counter_l; /**< RW Main Counter Low. */
			uint32_t counter_h; /**< RW Main Counter High. */
		};
	};
	uint64_t reserved3;         /**< Reserved for future use. */
	struct {
		uint64_t config;    /**< RW Timer Config and Capability Reg. */
		uint64_t comp;      /**< RW Timer Comparator Value Register. */
		uint64_t fsb;       /**< RW FSB Interrupt Route Register. */
		uint64_t reserved4; /**< Reserved for future use. */
	} timers[HPET_TIMER_NUM]; /**< Set of HPET timers. */
};

/* Mmap'd hpet registers */
static volatile struct hpet_regs *hpet = NULL;

/* Period at which the HPET counter increments in
 * femtoseconds (10^-15 seconds). */
static uint32_t hpet_resolution_fs = 0;

/* Frequency of the HPET counter in Hz */
static uint64_t hpet_resolution_hz = 0;

/* Incremented 4 times during one 32bits hpet full count */
static uint32_t hpet_msb;


/* According to DPDK''s eal tiimer the HPET is configured as a 32-bit
 * device under linux by default. DPDK solved this by allocating a thread
 * to watch for turnover of the ls-half so it could promptly increment the
 * ms-half. That is overkill.
 * We expect to cat hpet_cycles 1000s of times a second, so we just figure
 * out if the ls-half has overflowed and if so incremetn the ms-hlaf. We assume
 * That this routine will be invoked often enough (i.e. only one overflow
 * of the ls-half0.
 */

static uint64_t prior_counter = 0ULL;

static void msb_inc_if_wrapped(void)
{
	// if (hpet->counter_l < prior_counter)
	if (hpet->counter_l < prior_counter)
		++hpet_msb;
	prior_counter = hpet->counter_l;
}

uint64_t hpet_hz(void)
{
	return hpet_resolution_hz;
}

uint64_t hpet_cycles(void)
{
	uint32_t t, msb;
	uint64_t ret;

	msb_inc_if_wrapped();
	t = hpet->counter_l;
	msb = hpet_msb;
	ret = (msb + 2 - (t >> 30)) / 4;
	ret <<= 32;
	ret += t;
	return ret;
}

/*
 * Open and mmap /dev/hpet (high precision event timer) that will
 * provide our time reference.
 */
int hpet_init(void)
{
	int fd;

	fd = open(DEV_HPET, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	hpet = mmap(NULL, 1024, PROT_READ, MAP_SHARED, fd, 0);
	assert(hpet != MAP_FAILED);
	close(fd);

	if (!hpet) {
		return -1;
	}

	hpet_resolution_fs = (uint32_t)((hpet->capabilities &
					CLK_PERIOD_MASK) >>
					CLK_PERIOD_SHIFT);

	hpet_resolution_hz = (1000ULL*1000ULL*1000ULL*1000ULL*1000ULL) /
		(uint64_t)hpet_resolution_fs;

	hpet_msb = (hpet->counter_l >> 30);

	return 0;
}

