//
// Copyright (c) 2015-2018 Nexenta Systems, inc.
//
// This file is part of EdgeFS Project
// (see https://github.com/Nexenta/edgefs).
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

/*
 * pktsend-uv.c
 *
 *  Created on: Aug 17, 2017
 *      Author: caitlin.bestler@nexenta.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <unistd.h>

#include "pmu.h"
#include "pmu_private.h"
#include "pmu_test.h"

#include "pmu_net.h"

extern netcfg_t *netcfg;

static unsigned n_uncompleted = 0;

#define MAX_PAYLOAD_FILL_PER_UDP (8*1024 - sizeof(frame_header_t) - sizeof(pmu_test_fixed_msg_t) - sizeof(unsigned)


typedef struct pending_chunk_ack {
	unsigned chunk_num;
	uint64_t queued_to_unpaced_at;
	uint64_t late;
} pending_chunk_ack_t;

#define N_CHUNK_ACK_TRACK_SLOTS 128

static pending_chunk_ack_t pending_chunk_acks[N_CHUNK_ACK_TRACK_SLOTS];

static void remember_pending_chunk_ack (unsigned chunk_num,uint64_t now,uint64_t late)
{
	pending_chunk_ack_t *p;

	for (p = pending_chunk_acks; p != &pending_chunk_acks[N_CHUNK_ACK_TRACK_SLOTS];++p) {
		if (p->chunk_num == 0   &&  p->queued_to_unpaced_at == 0L) {
			p->chunk_num = chunk_num;
			p->queued_to_unpaced_at = now;
			if (!p->queued_to_unpaced_at) p->queued_to_unpaced_at = 1L;
			p->late = late;
			return;
		}
	}
	log_error(lg, "pending_chunk_ack array full");
	return;
}


static void match_chunk_ack (unsigned chunk_num)
{
	pending_chunk_ack_t *p;

	for (p = pending_chunk_acks; p != &pending_chunk_acks[N_CHUNK_ACK_TRACK_SLOTS];++p) {
		if (p->chunk_num == chunk_num) {
			memset(p,0,sizeof(pending_chunk_ack_t));
			return;
		}
	}
	log_error(lg, "Unexpected chunk ack %u",chunk_num);
	return;
}


typedef struct pmu_test_alloc {
	paced_message_t paced; // This assumes at most 1 segment
	pmu_test_fixed_msg_t fixed;
	bool allocated;
} pmu_test_alloc_t;

static void paced_cb (const paced_message_t *msg,uint64_t deadline)
{
	unsigned n,len;;
	unsigned first = *(unsigned *)msg->payload[0].iov_base;
	unsigned last;
	pmu_test_fixed_msg_t *fixed = (pmu_test_fixed_msg_t *)msg->fixed_header;
	uint64_t now = hpet_cycles();
	uint64_t late = now - deadline;
	pmu_test_alloc_t *alloc_msg = (pmu_test_alloc_t *)msg;

	remember_pending_chunk_ack (fixed->chunk_num,now,late);
	for (n = len = 0; n != msg->payload_segments;++n) {
		const unsigned *p = msg->payload[n].iov_base;
		unsigned seg_len = msg->payload[n].iov_len;

		len += seg_len;
		last = p[seg_len/sizeof(unsigned)-1];
	}
	(void)first;
	(void)last;
	--n_uncompleted;
	assert(alloc_msg->allocated);
	alloc_msg->allocated = false;
}




#define MAX_PACED_BUFS 1000
static pmu_test_alloc_t paced_buf[MAX_PACED_BUFS];
static unsigned next_paced_buf = 0;

static void send_paced_chunk ( pmu_if_t *pi, unsigned chunk_num,\
				unsigned fill_size, struct sockaddr_in6 *dest)
{
	pmu_test_alloc_t *alloc = &paced_buf[next_paced_buf++];
	paced_message_t *paced_msg = &alloc->paced;
	pmu_test_fixed_msg_t *fixed = &alloc->fixed;
	static unsigned sequence_nums[1024];
	static unsigned payload[4*1024*1024];
	static bool first_time = true;
	unsigned i;

	assert(!alloc->allocated);
	alloc->allocated = true;
	paced_msg->payload_segments = 1;

	if (++next_paced_buf == MAX_PACED_BUFS) next_paced_buf = 0;

	if (first_time) {
		for (i = 0; i != (sizeof sequence_nums)/(sizeof sequence_nums[0]); ++i)
			sequence_nums[i] = i;
		for (i = 0; i != (sizeof payload)/(sizeof payload[0]);++i)
			payload[i] = htonl(i);
		first_time = false;
	}

	fixed->must_be_89abcdef = 0x89abcdef;
	fixed->chunk_num = chunk_num;
	fixed->seed = rand() % N_SEEDS;
	fixed->total_fill = fill_size;
	paced_msg->payload_per_datagram_len = 8000;
	fixed->n_datagrams = paced_msg->n_datagrams = (fill_size + paced_msg->payload_per_datagram_len - 1) /
			paced_msg->payload_per_datagram_len;
	fixed->reply_required = true; // TODO, make this configurable
	fixed->originated_ts = hpet_cycles();

	paced_msg->to = dest;
	paced_msg->source_port = ntohs(dest->sin6_port);
	paced_msg->fixed_header = fixed;
	paced_msg->fixed_header_size = sizeof(pmu_test_fixed_msg_t);

	paced_msg->per_datagram_hdr = sequence_nums;
	paced_msg->per_datagram_hdr_size = sizeof sequence_nums[0];

	paced_msg->payload[0].iov_base = payload;
	paced_msg->payload[0].iov_len = fill_size;
	paced_msg->payload_segments = 1;

	assert (fill_size <= sizeof payload);
	paced_msg->payload_per_datagram_len = 8000;

	while (!pmu_send_paced(pi,paced_msg,paced_cb)) {
		pmu_tx_kick(pi);
	}
}


static void send_unpaced_ping ( pmu_if_t *pi, const struct sockaddr_in6 *to)
{
	void *buf;
	frame_header_t *fh;
	uint64_t *timestamp;

	while (!pmu_allocate_unpaced (pi,&buf,1))
		pmu_tx_kick(pi);
	fh = buf;
	pmu_set_frame_header(pi,fh,to,&pi->derived.local_ipv6,ntohs(to->sin6_port),sizeof(uint64_t));
	timestamp = (uint64_t *)(fh + 1);
	*timestamp = hpet_cycles();
	pmu_commit_unpaced(pi);
}


xmit_tracker_t *xmit_track = NULL;

static void monitor_xmit_thread (void *arg)
{
	xmit_tracker_t *x = (xmit_tracker_t *)arg;
	xmit_track_t *p;

	assert (x);
	for (p = x->array;p != x->lim;++p) {
		while (p == x->next) ;
		while (*p->status != TP_STATUS_AVAILABLE) ;
		p->xmit_done = hpet_cycles();
	}
}

void do_send ( pmu_if_t *pi, unsigned n_send, size_t fill_size, struct sockaddr_in6 *dest)
{
	const void *latest;
	uint64_t duration_microsecs;
	uint64_t duration;
	unsigned i;
	struct sockaddr_in6 unpaced_dest;
	unsigned total_datagrams = n_send*((fill_size+7999)/8000);
	uv_thread_t monitor_xmit_thread_id;
	xmit_track_t *x;
	int err;
	uint64_t start;
	uint64_t hz = hpet_hz();


	dest->sin6_port = htons(7000);
	unpaced_dest = *dest;
	unpaced_dest.sin6_port = htons(7001);

	xmit_track = je_malloc(sizeof(xmit_tracker_t)+total_datagrams*sizeof(xmit_track_t));
	assert (xmit_track);
	xmit_track->next = xmit_track->next_tx = xmit_track->array;
	xmit_track->lim = xmit_track->next + total_datagrams;

	err = uv_thread_create(&monitor_xmit_thread_id,monitor_xmit_thread,xmit_track);
	assert(err == 0);

	start = hpet_cycles();
	for (i = 0;i < n_send;++i) {
		uint64_t this_send_start = hpet_cycles();
		uint64_t now;

		send_paced_chunk(pi,i,fill_size,dest);
		send_unpaced_ping(pi,&unpaced_dest);
		pmu_tx_kick(pi);
		++n_uncompleted;
		now = hpet_cycles();
		duration = now - this_send_start;
		log_notice(lg,"@%ld chunk %d duration %ld ticks",now,i,duration);
	}
	latest = pmu_latest_tx(pi);
	while (!pmu_tx_done(latest))
		pmu_tx_kick(pi);

	duration = hpet_cycles() - start;
	duration_microsecs = duration*1000*1000/hz;
	log_notice(lg,"aggregate send of %d chunks took %ld ticks %ld usecs",
			n_send,duration,duration_microsecs);

	if (xmit_track) {
		uint64_t prior_go = 0L;
		uint64_t prior_done = 0L;
		uint64_t time_zero = xmit_track->array[0].xmit_go;

		for (x = xmit_track->array;x != xmit_track->next; ++x) {
			if (!x->xmit_done) break;
			duration = x->xmit_done - x->xmit_go;
			duration_microsecs = duration*1000*1000/hz;
			log_debug(lg,"sized  %u @%ld-%ld-%ld duration %ld usecs delta prior %ld %ld usecs",
					x->size,x->xmit_go-time_zero,x->xmit_tx-time_zero,x->xmit_done-time_zero,
					duration_microsecs,
					(x->xmit_go - prior_go)*1000*1000/hz,(x->xmit_done - prior_done)*1000*1000/hz);
			prior_go = x->xmit_go;
			prior_done = x-> xmit_done;
		}
		uv_thread_join(&monitor_xmit_thread_id);
		je_free(xmit_track);
	}
}

static void process_ping_reply (frame_header_t *fh)
{
	(void)fh;
}



static void log_1000_replies (unsigned n_chunk_replies)
{
	static uint64_t prior = 0L;
	uint64_t now = hpet_cycles();

	if (prior) {
		log_notice(lg,"%d replies. %ld since prior.",n_chunk_replies,now-prior);
	}
	prior = now;
}

static void process_chunk_reply(frame_header_t *fh)
{
	pmu_test_reply_msg_t *reply = (pmu_test_reply_msg_t *)(fh+1);
	static unsigned n_chunk_replies = 0;

	assert (reply->must_be_01234567 == 0x01234567);
	if (reply->n_missing) {
		log_notice(lg, "Chunk %u had %u datagrams missing",reply->chunk_num,reply->n_missing);
	}
	match_chunk_ack(reply->chunk_num);
	if (++n_chunk_replies % 1000 == 0)
		log_1000_replies(n_chunk_replies);
}


void collect_replies_thread (void *arg)
{
	pmu_if_t *pi = arg;
	unsigned n_idle = 0;

	for (;;) {
		void *p;

		if (!pmu_receive(pi,&p,1))
			pmu_rx_kick(pi);
		else {
			frame_header_t *fh = p;

			if (fh->ipv6.nexthdr != IPPROTO_UDP)
				log_debug(lg,"Non-UDP Received");
			else if (fh->udp.dest != fh->udp.source)
				log_warn(lg,"Reply Port Mismatch");
			else if (fh->udp.dest == htons(7001)  &&  ntohs(fh->udp.len) == sizeof(uint64_t))
				process_ping_reply(fh);
			else if (fh->udp.dest == htons(7000)  &&  ntohs(fh->udp.len) == sizeof(pmu_test_reply_msg_t))
				process_chunk_reply(fh);
			else {
				log_warn(lg,"Unexpected port or udp length");
			}
			pmu_rx_frame_release(pi,p);
		}
	}
	assert(netcfg->collect_shutdown);
}

