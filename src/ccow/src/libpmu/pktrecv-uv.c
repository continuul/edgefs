
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

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include "pmu.h"
#include "pmu_private.h"
#include "pmu_lfq.h"
#include "pmu_test.h"

#include "pmu_vdev.h"
#include "pmu_net.h"

netcfg_t *netcfg;

//////////////////////////////////////
// Per Network Interface processing //
//////////////////////////////////////

#define N_CHUNK_TRACKS 5

static chunk_track_t *trk[N_CHUNK_TRACKS];

static void
release_chunk (chunk_track_t *t)
{
// release all frames held for  't', and then free() t itself

	unsigned i;
	assert(t);
	for (i = 0; i != PMU_TEST_MAX_DATAGRAMS;++i) {
		const frame_header_t *p = t->frame[i];
		if (p) {
			log_debug(lg,"frame_release chunk %d pos %d frame %p",
				  t->chunk_num,i,p);
			pmu_rx_frame_release(t->pi,p);
		}
	}
	je_free(t);
}


void
transaction_complete(void *p)
{
	static unsigned n_replies_sent = 0;
	chunk_track_t *t = (chunk_track_t *)p;
	pmu_test_reply_msg_t *reply;
	void *buf;
	frame_header_t *fh;
	char addr_buf[80];
	const char *ap;
	const frame_header_t *from = first_frame(t);

	ap = inet_ntop(AF_INET6,&from->ipv6.saddr,addr_buf,sizeof addr_buf);
	(void)ap;

	while (!pmu_allocate_unpaced (t->pi,&buf,1))
		pmu_tx_kick(t->pi);
	fh = buf;
	pmu_set_reply_header(t->pi,fh,first_frame(t),&t->pi->derived.local_ipv6,sizeof(pmu_test_reply_msg_t));
	reply = (pmu_test_reply_msg_t *)(fh + 1);
	reply->must_be_01234567 = 0x01234567;
	reply->chunk_num = t->chunk_num;
	reply->n_missing = t->n_datagrams - t->datagrams_seen;
	reply->originated_ts = t->latest_originated;
	reply->reply_ts = htole64(hpet_cycles());
	pmu_commit_unpaced(t->pi);
	if (++n_replies_sent % 10000 == 0)
		log_notice(lg, "Replies sent: %u. Latest chunk %d",n_replies_sent,t->chunk_num);

	release_chunk (t);
}


static chunk_track_t *
select_track (
	pmu_if_t *pi,
	unsigned chunk_num,
	unsigned num_datagrams,
	bool direct_completion
)
{
	chunk_track_t **tt = trk + chunk_num % N_CHUNK_TRACKS;
	chunk_track_t *t = *tt;
	unsigned int vdev;

	(void)pi;

	if (t) {
		if (t->chunk_num == chunk_num) {
			if (t->n_datagrams == 0)
				t->n_datagrams = num_datagrams;
			else
				assert(t->n_datagrams == num_datagrams);

			return t;
		}
		struct pmu_vdev *pmu_vdev = select_vdev(t->chunk_num);
		if (direct_completion)
			transaction_complete(t);
		else
			while (!pmu_lfq_produce(pmu_vdev->to_vdev,t));
		*tt = NULL;
	}
	t = je_malloc(sizeof(chunk_track_t));
	if (t) {
		memset(t,0,sizeof(chunk_track_t));
		t->pi = pi;
		t->chunk_num = chunk_num;
		t->n_datagrams = num_datagrams;
		t->first_seen = hpet_cycles();
	}
	*tt = t;
	return t;
}


static void
validate_datagram (pmu_if_t *pi,const frame_header_t *fp,bool direct_completion)
{
	const pmu_test_msg_datagram_t *msg = (const pmu_test_msg_datagram_t *)(fp+1);
	chunk_track_t *t = select_track(pi,msg->fixed.chunk_num,msg->fixed.n_datagrams,direct_completion);
	unsigned int vdev;

	assert (t);
	assert (msg->fixed.must_be_89abcdef == 0x89abcdef);
	assert (msg->fixed.n_datagrams == t->n_datagrams);
	assert (msg->fixed.chunk_num == t->chunk_num);
	assert (msg->datagram_num <= t->n_datagrams);
	t->latest_seen = hpet_cycles();
	t->latest_originated = msg->fixed.originated_ts;
	if (t->frame[msg->datagram_num]) {
		log_warn(lg, "Duplicate datagram %u of chunk %u",msg->datagram_num,t->chunk_num);
		log_warn(lg, "prior datagram %p new datagram %p",t->frame[msg->datagram_num],fp);
	}
	t->frame[msg->datagram_num] = fp;
	bmap_set(t->bitmap,msg->datagram_num);

	assert (t->datagrams_seen < t->n_datagrams);
	if (++t->datagrams_seen == t->n_datagrams) {

		chunk_track_t **tt = trk + t->chunk_num % N_CHUNK_TRACKS;
		struct pmu_vdev *pmu_vdev = select_vdev(t->chunk_num);

		if (direct_completion)
			transaction_complete(t);
		else
			while (!pmu_lfq_produce(pmu_vdev->to_vdev,t));
		*tt = NULL;
	}
}

void
signal_handler_uv(uv_signal_t* handle, int signum)
{
	if (signum == SIGINT) {
		uv_close((uv_handle_t*) handle, NULL);
		uv_close((uv_handle_t*) &netcfg->idle_handle, NULL);
		uv_stop(uv_default_loop());
		log_notice(lg, "RX thread stopped");
	}
}

void
net_show_pkthdr(const char *type,const frame_header_t *fp)
{
	char saddr_str[80];
	char daddr_str[80];
	const char *sap = inet_ntop(AF_INET6,&fp->ipv6.saddr,saddr_str,sizeof saddr_str);
	const char *dap = inet_ntop(AF_INET6,&fp->ipv6.daddr,daddr_str,sizeof daddr_str);

	log_debug(lg, "ipv6 saddr: <%s> daddr: <%s> payload_len: %d nexthdr: %d hoplimit: %d",
			saddr_str, daddr_str, ntohs(fp->ipv6.payload_len), fp->ipv6.nexthdr, fp->ipv6.hop_limit);
	log_debug(lg,"udp src %d dst %d len %d",ntohs(fp->udp.source),ntohs(fp->udp.dest),ntohs(fp->udp.len));
}

static void ping_reply( pmu_if_t *pi, const frame_header_t *fh)
{
	void *buf;
	frame_header_t *reply_fh;
	uint64_t *timestamp,*orig_ts;

	while (!pmu_allocate_unpaced (pi,&buf,1))
		pmu_tx_kick(pi);
	reply_fh = buf;
	pmu_set_reply_header(pi,reply_fh,fh,&pi->derived.local_ipv6,sizeof(uint64_t));
	timestamp = (uint64_t *)(reply_fh + 1);
	orig_ts = (uint64_t *)(fh+1);
	*timestamp = *orig_ts;
	net_show_pkthdr("Reply",reply_fh);

	pmu_commit_unpaced(pi);
	pmu_rx_frame_release(pi,(void *)fh);
}


void
net_check_udp(pmu_if_t *pi, const frame_header_t *fp, bool direct_completion)
{

	net_show_pkthdr("In",fp);

	if (fp->udp.dest != fp->udp.source) {
		net_show_pkthdr("Mismatched UDP Port",fp);
		pmu_rx_frame_release(pi,(void *)fp);
	}
	else if (fp->udp.dest == htons(7001))
		ping_reply(pi,fp);
	else if (fp->udp.dest == htons(7000))
		validate_datagram(pi,fp,direct_completion);
	else {
		net_show_pkthdr("Unexpected UDP Port",fp);
		pmu_rx_frame_release(pi,(void *)fp);
	}
}

void
net_process_frame(pmu_if_t *pi, const frame_header_t *fp, bool direct_completion)
{
	if (fp->ipv6.nexthdr == IPPROTO_UDP) {
		net_check_udp(pi, fp, direct_completion);
	} // else it is TCP . do nothing for now. 
}

void
net_loop (pmu_if_t *pi, uv_loop_t *ifloop, bool direct_completion)
{
	static void *frames[MAX_RECV_FRAMES];
	unsigned n,m;
	unsigned total = 0;
	static ticks_t prior_last_drop = 0;

	if (!ifloop) {
		log_error(lg, "No loop specified");
		return;
	}

	log_debug(lg, "Starting net_loop");
	while (uv_run(ifloop, UV_RUN_ONCE)) {

		n = pmu_receive(pi,frames,MAX_RECV_FRAMES);

		if ((total + n)/10000 != total/10000)
			log_notice(lg, "Total received %u",total+n);

		total += n;
		if (pi->last_drop_seen  && pi->last_drop_seen != prior_last_drop) {
			static uint64_t n_drops_seen = 0;
			log_notice(lg, "%u collected. last_drop_seen %lx. %lu total",n,pi->last_drop_seen,++n_drops_seen);
			prior_last_drop = pi->last_drop_seen;
		}
		if (n) {
			ticks_t start = hpet_cycles();
			ticks_t duration;

			for (m = 0; m != n; ++m) {
				const frame_header_t *fp = frames[m];
				net_process_frame(pi, fp, direct_completion);
			}

			duration = hpet_cycles() - start;
			log_debug(lg,"%d processed duration %ld",n,duration);

			pmu_tx_kick(pi);
		}
		pmu_rx_kick(pi);

		pmu_vdev_notify_all(pi);
	}

	log_trace(lg, "Done with net_loop uv_run");
}

void
pmu_main(pmu_if_t *pi, void *loop)
{
	net_loop(pi, (uv_loop_t *) loop, false);
}

void
net_loop_idle(uv_idle_t* handle, int status)
{
	assert(handle);
	assert(status == 0);
}

void
net_init(void)
{
	if (netcfg == NULL) {
		netcfg = je_malloc(sizeof(netcfg_t));
		assert(netcfg);
		memset(netcfg,0,sizeof(netcfg_t));
		// Note: netcfg's idle handle  must be initialized with uv_idle_init
		// before any uv callbacks can be enabled.
	}
}

void
net_close(void)
{
	if (netcfg) {
		je_free(netcfg);
		netcfg = NULL;
	}
}

