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
 * pmu_pktmmap.c - Implementation of pmu.h using AF_PACKET with mmapped rings
 *
 *  Created on: Jul 28, 2017
 *      Author: cait
 */

#include "pmu.h"
#include "pmu_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <poll.h>

static void
trace_frame(const char *type,
                const volatile struct tpacket_hdr *tp,
                const frame_header_t *fp)
{
	char saddr_str[80];
	char daddr_str[80];
	const char *sap = inet_ntop(AF_INET6,&fp->ipv6.saddr,saddr_str,sizeof saddr_str);
	const char *dap = inet_ntop(AF_INET6,&fp->ipv6.daddr,daddr_str,sizeof daddr_str);

	log_debug(lg,"type %s tp %p fp %p status %lx",type,tp,fp,tp->tp_status);
	log_debug(lg,"->len %x ->spaplen %x",tp->tp_len,tp->tp_snaplen);
	log_debug(lg,"->tp_mac %x tp_net %x",tp->tp_mac,tp->tp_net);
	log_debug(lg, "ipv6 saddr: <%s> daddr: <%s> payload_len: %d nexthdr: %d hoplimit: %d",
			saddr_str, daddr_str, ntohs(fp->ipv6.payload_len), fp->ipv6.nexthdr, fp->ipv6.hop_limit);
	log_debug(lg,"udp src %d dst %d len %d",ntohs(fp->udp.source),ntohs(fp->udp.dest),ntohs(fp->udp.len));
}



static unsigned ifindex_from_name (int socket,const char *name)
{
	struct ifreq r;
	unsigned ifindex;

	strncpy(r.ifr_name,name,sizeof r.ifr_name);
	ioctl(socket,SIOCGIFINDEX,&r);
	ifindex = r.ifr_ifindex;
	return ifindex;
}

static void bind_to_if (int fd,unsigned ifindex)
{
	struct sockaddr_ll bind_link;
	int err;

	bind_link.sll_family = AF_PACKET;
	bind_link.sll_protocol = htons(ETH_P_IPV6);
	bind_link.sll_ifindex = ifindex;
	err = bind (fd,(struct sockaddr *)&bind_link,sizeof(struct sockaddr_ll));
	if (err < 0) {
		log_error(lg,"failed to bind. errno %d",errno);
		assert (err == 0);
	}
}


static bool setup_ring (
		pmu_if_t *pi,
		unsigned ifindex,
		pmu_ring_t *ring,
		unsigned n_bufs,
		bool tx
)
{
	struct tpacket_req tpreq;
	unsigned size;
	void *mmap_ptr;
	int err;
	int option_set = 1;

	assert (pi);
	assert(ring);

	bind_to_if(ring->socket,ifindex);

	if (tx) {
		err = setsockopt(ring->socket,SOL_PACKET,PACKET_LOSS,(char*)&option_set,sizeof option_set);
		if (err < 0) {
			log_error(lg,"setsocket-PACKET_LOSS err %d errno %d",err,errno);
			close(ring->socket);
			return false;
		}
	}

	tpreq.tp_block_nr = tpreq.tp_frame_nr = n_bufs;
	tpreq.tp_block_size = tpreq.tp_frame_size = 8*1024;

	err = setsockopt(ring->socket,SOL_PACKET,tx ? PACKET_TX_RING : PACKET_RX_RING,&tpreq,sizeof tpreq);
	if (err < 0) {
		log_error(lg,"Setsockopt map %d errno %d",err,errno);
		close(ring->socket);
		return false;
	}
	size = n_bufs * tpreq.tp_frame_size;
	if (tx) {
		err = setsockopt(ring->socket,SOL_PACKET,SO_SNDBUF,(char*)&size,sizeof size);
		if (err < 0) {
			log_error(lg,"setsocket-PACKET_LOSS err %d errno %d",err,errno);
			close(ring->socket);
			return false;
		}
		err = setsockopt(ring->socket,SOL_PACKET,PACKET_QDISC_BYPASS,(char *)&option_set,sizeof option_set);
		if (err < 0) {
			log_error(lg,"setsocket-QDISC Bypass err %d errno %d",err,errno);
			close(ring->socket);
			return false;
		}
	}
	mmap_ptr = mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_LOCKED|MAP_POPULATE,ring->socket,0);
	if (mmap_ptr == MAP_FAILED) {
		log_error(lg,"mmap failed. errno %d",errno);
		close(ring->socket);
		return false;
	}

	ring->mmap_ptr = mmap_ptr;
	ring->frame_size = tpreq.tp_frame_size;
	ring->total_size = size;
	ring->total_nr = n_bufs;
	ring->next = 0;

	return true;
}


static void get_local_ipv6 (const char *name,struct in6_addr *in6)
{
	struct ifaddrs *al,*p;

	memset(in6,0,sizeof *in6);
	getifaddrs(&al);
	for (p = al; p != NULL; p = p->ifa_next) {
		const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)p->ifa_addr;

		if (p->ifa_addr->sa_family != AF_INET6) continue;
		if (0 != strcmp(p->ifa_name,name)) continue;
		/* the 0xfe address for ipv6 is ignored. */
		if (addr->sin6_addr.__in6_u.__u6_addr8[0] == 0xfe) continue;
		memcpy(in6->__in6_u.__u6_addr8,addr->sin6_addr.__in6_u.__u6_addr8,sizeof *in6);
		break;
	}
	freeifaddrs(al);
}

static ticks_t ticks_plus_bit_ticks (ticks_t base_time,bit_ticks_t delta)
{
	static uint64_t hz = 0;
	static uint64_t multiplier;
	static uint64_t divisor  = 10L*1000L*1000L*1000L;
	ticks_t t;

	if (!hz) {
		multiplier = hz = hpet_hz();
		// TODO: factor out gcd between multiplier and divisor.
		// This is not worthwhile for current HPETS, which have a hz of 59*242681
	}
	t = base_time + (delta * multiplier + divisor -1)/ divisor;

	return t;
}

#define PACKET_OFF      (TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + TPACKET_ALIGN(sizeof(struct sockaddr_ll)))

pmu_if_t *pmu_initialize_interface (const char *name,const pmu_cfg_t *cfg)
{
	pmu_if_t *pi;
	unsigned ifindex;

	// validate MTU
	// validate PAUSE or PFC enabled
	pi = je_malloc(sizeof(pmu_if_t));
	if (!pi) {
		log_error(lg,"allocation net_if_t faied");
		return NULL;
	}
	memset(pi,0,sizeof(pmu_if_t));
	memcpy(&pi->config,cfg,sizeof *cfg);

	get_local_ipv6(name,&pi->derived.local_ipv6);
	// validate IPv6 address assigned from MAC
	pi->derived.max_receive_hold = pi->config.max_frames_in_single_paced_xmit + 2;
	pi->derived.tx_offset = (TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct ethhdr));
	pi->derived.rx_offset = PACKET_OFF;

	pi->rx.socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IPV6));
	if (pi->rx.socket < 0) {
		log_error(lg,"PF_PACKET rx socket creation error %d",pi->rx.socket);
		return NULL;
	}
	ifindex = ifindex_from_name(pi->rx.socket,name);
	if (!setup_ring(pi,ifindex,&pi->rx,cfg->max_frames_in_single_paced_xmit * 2 + 18,false)) { // TODO: does not need 2x
		log_error(lg,"Cannot setup RX Ring");
		je_free(pi);
		return NULL;
	}
	pi->tx.socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IPV6));
	if (pi->tx.socket < 0) {
		log_error(lg,"PF_PACKET tx socket creation error %d",pi->rx.socket);
		return NULL;
	}
	if (!setup_ring(pi,ifindex,&pi->tx,64,true)) { // TODO: should be time-based
		log_error(lg,"Cannot setup TX Ring");
		close(pi->rx.socket);
		je_free(pi);
		return NULL;
	}
	pi->paced_next_xmit_time = hpet_cycles();
	return pi;
}

void pmu_close_interface (pmu_if_t *pi,bool force)
{
	const void *last;

	if (!force) {
		do {
			pmu_tx_kick(pi);
			pmu_rx_kick(pi);
		} while (pi->n_paced_buffers != 0);
		last = pmu_latest_tx (pi);
		while (!pmu_tx_done(last))
			pmu_tx_kick(pi);
	}
	munmap(pi->rx.mmap_ptr,pi->rx.total_size);
	close (pi->rx.socket);
	munmap(pi->tx.mmap_ptr,pi->tx.total_size);
	close (pi->tx.socket);
	je_free(pi);
}


unsigned long ring_frame_status (const ring_frame_t *p)
{
	struct tpacket_hdr *hp = (struct tpacket_hdr *)p;

	return hp->tp_status;
}


static unsigned wrong_format_errors = 0;


size_t pmu_allocate_unpaced (pmu_if_t *pi,void **bufs,size_t max_n)
{
	size_t n = 0;
	struct tpacket_hdr *tp;
	unsigned long status;
	unsigned next;

	if (max_n) do {
		next = (pi->next_unpaced_alloc + 1) % pi->tx.total_nr;
		if (next == pi->tx.next) {
			log_debug(lg, "unpaced full slot %u @%lx",next,hpet_cycles());
			break;
		}

		 tp = (struct tpacket_hdr *)(pi->tx.mmap_ptr + pi->tx.frame_size*pi->next_unpaced_alloc);
		 status = tp->tp_status;
		 if (status == TP_STATUS_SEND_REQUEST) {
			 // tx buffer is not yet transmitting
			 break;
		 }
		 else if (status & TP_STATUS_WRONG_FORMAT) {
			 assert ((status & TP_STATUS_WRONG_FORMAT) == 0);
			 ++wrong_format_errors;
			 tp->tp_status = TP_STATUS_AVAILABLE;
			__sync_synchronize();
		 }
		 else if (status & TP_STATUS_SENDING) {
			 // tx buffer is full need to wait for xmitter
			 break;
		 }
		 else if (status != TP_STATUS_AVAILABLE) {
			 log_debug(lg, "Cannot allocated unpaced. status 0x%lx",status);
			 break;
		 }
		 bufs[n] = ((void *)tp) + pi->derived.tx_offset;
		 tp->tp_net = pi->derived.tx_offset;
		 tp->tp_mac = tp->tp_net - sizeof(struct ethhdr);
		 pi->next_unpaced_alloc = next;
		 ++n;
	} while (--max_n);

	return n;
}


static void *next_frame (pmu_ring_t *ring)
{
	return ring->mmap_ptr + ring->next*ring->frame_size;
}

const void *pmu_latest_tx (pmu_if_t *pi)
{
	unsigned x = pi->tx.next ? (pi->tx.next-1) : (pi->tx.total_nr - 1);

	return (const void *)(pi->tx.mmap_ptr + x*pi->tx.frame_size);
}

bool pmu_tx_done (const void *p)
{
	const struct tpacket_hdr *tp = (const struct tpacket_hdr *)p;

	return tp->tp_status == TP_STATUS_AVAILABLE;
}


static void setl2mac (unsigned char *l2mac,const struct in6_addr *ip6addr)
{
	if (ip6addr->__in6_u.__u6_addr8[0] == 0xFF) { // multicast IPv6 address
		l2mac[0] = 0x33;
		l2mac[1] = 0x33;
		l2mac[2] = ip6addr->__in6_u.__u6_addr8[12];
		l2mac[3] = ip6addr->__in6_u.__u6_addr8[13];
		l2mac[4] = ip6addr->__in6_u.__u6_addr8[14];
		l2mac[5] = ip6addr->__in6_u.__u6_addr8[15];
	}
	// TODO: else if non-local subnetmake
	//	l2mac[0.5] to mac of egresss router
	else { // local unicast IPV6
		l2mac[0] = ip6addr->__in6_u.__u6_addr8[8];
		l2mac[1] = ip6addr->__in6_u.__u6_addr8[9];
		l2mac[2] = ip6addr->__in6_u.__u6_addr8[10];
		assert(ip6addr->__in6_u.__u6_addr8[11] == 0xFF);
		assert(ip6addr->__in6_u.__u6_addr8[12] == 0xFE);
		l2mac[3] = ip6addr->__in6_u.__u6_addr8[13];
		l2mac[4] = ip6addr->__in6_u.__u6_addr8[14];
		l2mac[5] = ip6addr->__in6_u.__u6_addr8[15];
	}
}



static struct ethhdr *get_eh(const pmu_if_t *pi,const frame_header_t *fh)

// Note that this is declared as 'struct ethhdr *' but it should retain any const modifier applied to 'fh'

{
	(void)pi;// TODO use info on whether this link is vlan tagged

	return (struct ethhdr *)(((void *)fh)-sizeof(struct ethhdr));
}

static void setl2hdr (const pmu_if_t *pi,frame_header_t *fh)

// set ethhdr immediately before fh headers based upon fh->ipv6
// TODO allow some interfaces to use VLAN tagged ethhdr

{
	struct ethhdr *eh = get_eh(pi,fh);
	setl2mac(eh->h_source,&fh->ipv6.saddr);
	setl2mac(eh->h_dest,&fh->ipv6.daddr);
	eh->h_proto = htons(ETH_P_IPV6);
}


void pmu_set_frame_header (
		const pmu_if_t *pi,
		frame_header_t *fh,
		const struct sockaddr_in6 *to,
		const struct in6_addr *source_ip,
		uint16_t source_port,
		size_t len
)
{
	assert (sizeof(frame_header_t) + sizeof(struct ethhdr) + len <= 8192);

	memset(fh,0,sizeof *fh);
	fh->ipv6.saddr = *source_ip;
	fh->ipv6.daddr = to->sin6_addr;
	fh->ipv6.hop_limit = 4; // TODO: use 1 if same subnnet, else use attribute of route
	fh->ipv6.priority = 3; // TODO: should be configurable.
	fh->ipv6.version = 6;
	fh->ipv6.nexthdr = IPPROTO_UDP;
	fh->ipv6.payload_len = htons(len+sizeof(struct udphdr));
	setl2hdr(pi,fh);
	fh->udp.source = htons(source_port);
	fh->udp.dest = to->sin6_port;
	fh->udp.len = htons(len);
}


void pmu_set_reply_header (
		const pmu_if_t *pi,
		frame_header_t *fh,
		const frame_header_t *in_reply_to,
		const struct in6_addr *unicast_source,
		size_t len
)
{
	struct ethhdr *eh = get_eh(pi,fh);
	const struct ethhdr *reh = get_eh(pi,in_reply_to);
	assert (sizeof(frame_header_t) + len + sizeof(struct ethhdr) <= 8192);

	memset(fh,0,sizeof *fh);
	memcpy(eh->h_dest,reh->h_source,sizeof eh->h_dest);
	eh->h_proto = reh->h_proto;
	fh->ipv6.daddr = in_reply_to->ipv6.saddr;

	if (fh->ipv6.saddr.__in6_u.__u6_addr8[0] == 0xFF) { // we were multicast to
		memcpy(&fh->ipv6.saddr,unicast_source,sizeof fh->ipv6.saddr);
		setl2mac(eh->h_source,unicast_source);
	}
	else {
		fh->ipv6.saddr = in_reply_to->ipv6.daddr;
		memcpy(eh->h_source,reh->h_dest,sizeof eh->h_source);
	}
	fh->ipv6.hop_limit = 4; // TODO: use 1 if same subnnet, else use attribute of route
	fh->ipv6.priority = in_reply_to->ipv6.priority;
	fh->ipv6.version = 6;
	fh->ipv6.nexthdr = IPPROTO_UDP;
	fh->ipv6.payload_len = htons(len+sizeof(struct udphdr));
	fh->udp.source = in_reply_to->udp.dest;
	fh->udp.dest = in_reply_to->udp.source;
	fh->udp.len = htons(len);
}


void pmu_commit_unpaced (pmu_if_t *pi)
{
	static uint64_t total_sent = 0;

	while (pi->tx.next != pi->next_unpaced_alloc) {
		volatile struct tpacket_hdr *ph = next_frame(&pi->tx);
		frame_header_t *fh = ((void *)ph) + ph->tp_net;

		assert (ph->tp_status == TP_STATUS_AVAILABLE);
		ph->tp_len = ntohs(fh->ipv6.payload_len) + sizeof(struct ipv6hdr) + sizeof(struct ethhdr);
				// TODO use sizeof ethhdr appropriate to the interface - which might be VLAN tagged.
		ph->tp_len += 4; // Debugging Kludge
		assert(ph->tp_len < 8*1024);
		ph->tp_snaplen = ph->tp_len;
		ph->tp_status = TP_STATUS_SEND_REQUEST;
		__sync_synchronize();
		++total_sent;
		if (++pi->tx.next == pi->tx.total_nr) {
			pi->tx.next = 0;
		}
		if (xmit_track  &&  xmit_track->next != xmit_track->lim) {
			xmit_track->next->xmit_go = hpet_cycles();
			xmit_track->next->size = ph->tp_len;
			xmit_track->next->status = &ph->tp_status;
			++xmit_track->next;
		}
	}
}


static unsigned paced_tx_avail (const pmu_if_t *pi)
{
	assert(pi->n_paced_buffers < PMU_N_PACED_SLOTS);

	return PMU_N_PACED_SLOTS - 1 - pi->n_paced_buffers;
}

#define ETH_PREAMBLE_BITS 64
#define ETH_CRC_BITS 32
#define INTER_PACKET_GAP 96
static bit_ticks_t transmit_bticks (unsigned bw,unsigned pkt_size)
{

	bit_ticks_t t = pkt_size*8 + ETH_PREAMBLE_BITS + ETH_CRC_BITS + INTER_PACKET_GAP;
	t = (t*10000L+bw-1)/bw;
	return t;
}


static bool later_than (uint64_t a,uint64_t b)

// return true if a is later than b, accounting for wrap-around

{
	return ((int64_t)(a - b)) > 0;
}


static int  place_payload_sgl (
		const_iovec_t *dest,
		uint16_t *n_dest_segments,
		const const_iovec_t *source,
		unsigned n_source_segments,
		unsigned *current_source,
		unsigned *current_consumed,
		unsigned payload_per_datagram,
		unsigned *payload_size
)

// Transcribe SGLs from 'source' to 'dest' for one datagram with 'pahyload_per_datagram' of user payload.
//
// dest has at most *'n_dest_segments' in it.
// *'n_dest_segments' is set to actual number of segments as output.
//
// 'source' is not modijfied,
// this routine 'consumes' the source by incrementing 'current_source'
// and currently_consumed.
// *current_sourceis the index of the current iovec in 'source'. It should be initialized to 0.
// *currently_consumed is the number of bytes in source[*courrent_source] that have been consumed.
// It should also be initialized to zero.
//
// if there are no error then *payload_size is set to the total payload referenced in dest segments
//
// functional return is zer0 or -EINVAL.
// EINVAL only occurs if there are too many dest segments, which means you needed more
// than 16 swegments for a single datagram. Coalesce your input first.
//
// This routine *plans* I/o, it does not perform it. Therefoer there are no other IO errors to report.

{
	unsigned len_placed = 0;
	unsigned n_dests_placed = 0;
	unsigned still_needed = payload_per_datagram;
	const_iovec_t *dest_lim;
	unsigned available;

	assert(payload_size);
	assert(n_dest_segments);
	assert(*n_dest_segments);
	dest_lim = dest + *n_dest_segments;

	if (*current_source < n_source_segments) while (still_needed != 0) {
		if (*current_consumed >= source[*current_source].iov_len) {
			assert (*current_consumed == source[*current_source].iov_len);
			*current_consumed = 0;
			if (++*current_source >= n_source_segments)
				break;
		}
		dest->iov_base = source[*current_source].iov_base + *current_consumed;

		available = source[*current_source].iov_len - *current_consumed;
		if (available > still_needed)
			available = still_needed;
		dest->iov_len = available;
		*current_consumed += available;
		len_placed += available;
		assert (available >= dest->iov_len);

		still_needed -= dest->iov_len;
		++n_dests_placed;
		if (*current_source + 1 == n_source_segments)
			break;
		if (++dest == dest_lim  &&  still_needed > 0) {
			*n_dest_segments = 0;
			*payload_size = 0;
			return -EINVAL;
		}
	}
	*n_dest_segments = n_dests_placed;
	*payload_size = len_placed;
	return 0;
}

unsigned pmu_send_paced (
		pmu_if_t *pi,
		const paced_message_t *msg,
		void (*complete_cb)(const paced_message_t*,uint64_t)
)

{
	unsigned n = msg->n_datagrams;
	const_iovec_t per_datagram_hdr_iov;
	paced_slot_u *p;
	unsigned total_payload;
	bit_ticks_t now;
	bit_ticks_t delta;
	unsigned current_source,current_consumed;
	unsigned next_slot = pi->next_paced_alloc; // tentative new value if entire call is successful
	unsigned n_paced_bufs = pi->n_paced_buffers; // tentative new value if entire call is successful
	bool success;
	static unsigned n_sent = 0;
	static unsigned n_late = 0;
	static uint64_t total_late = 0L;

	per_datagram_hdr_iov.iov_base = msg->per_datagram_hdr;
	per_datagram_hdr_iov.iov_len = msg->per_datagram_hdr_size;

	if (!n)
		return 0;
	if (n > pi->config.max_frames_in_single_paced_xmit) {
		log_notice(lg, "device configured for at mmost %u datagrams in one chunk",
				pi->config.max_frames_in_single_paced_xmit);
		return 0;
	}
	if (paced_tx_avail(pi) < n + 1) {
		log_debug(lg, "no paced slot avail @%lu",hpet_cycles());
		return 0;
	}

	now = hpet_cycles();
	if (later_than(now,pi->paced_next_xmit_time))
		pi->paced_next_xmit_time = now;
	else {
		total_late += (pi->paced_next_xmit_time - now);
		++n_late;
	}
	++n_sent;
	if (n_sent % 1000 == 0) {
		log_notice(lg, "Paced sent #%u. # late %u Aggregate late %lu",n_sent,n_late,total_late);
	}

	delta = 0;
	current_source=0;
	current_consumed=0;

	for (total_payload=0;;) {
		int err;
		unsigned payload_length;
		unsigned frame_length;
		bit_ticks_t bticks;
		p = &pi->paced_slot[next_slot];

		p->datagram.to = msg->to;
		p->datagram.source_port = msg->source_port;
		p->datagram.fixed_hdr.iov_base = msg->fixed_header;
		p->datagram.fixed_hdr.iov_len = msg->fixed_header_size;
		p->datagram.per_datagram_hdr = per_datagram_hdr_iov;
		p->datagram.earliest_xmit = ticks_plus_bit_ticks(pi->paced_next_xmit_time,delta);
		p->datagram.n_payload_segments = msg->payload_segments;

		err = place_payload_sgl (&p->datagram.per_datagram_payload[0],
								&p->datagram.n_payload_segments,
								msg->payload,msg->payload_segments,
								&current_source,&current_consumed,
								msg->payload_per_datagram_len,
								&payload_length);
		if (err) {
			log_error(lg, "Excessive segmentation for one datagram");
			return 0;
		}
		if (!payload_length) {
			success = true;
			break;
		}
		total_payload += payload_length;
		frame_length = payload_length + sizeof(frame_header_t) + sizeof(struct ethhdr) +
				msg->fixed_header_size + msg->per_datagram_hdr_size;
		bticks = transmit_bticks(pi->config.max_paced_bw,frame_length);
		delta += bticks;
		pi->total_xmit += bticks;
		per_datagram_hdr_iov.iov_base += per_datagram_hdr_iov.iov_len;
		++n_paced_bufs;
		if (++next_slot == PMU_N_PACED_SLOTS)
			next_slot = 0;
		if (n_paced_bufs == PMU_N_PACED_SLOTS) {
			success = false;
			break;
		}
	}
	if (success  && complete_cb) // check that there is room for one more slot
		success = (n_paced_bufs <= PMU_N_PACED_SLOTS - 1);
	if (!success)
		return 0;
	pi->next_paced_alloc = next_slot;
	pi->n_paced_buffers = n_paced_bufs;
	pi->paced_next_xmit_time = ticks_plus_bit_ticks(pi->paced_next_xmit_time,delta);
	if (complete_cb) {
		p = &pi->paced_slot[pi->next_paced_alloc];
		p->callback.must_be_null = NULL;
		p->callback.completion_cb = complete_cb;
		p->callback.msg_hdr = msg;
		++pi->n_paced_buffers;
		pi->next_paced_alloc = (pi->next_paced_alloc + 1) % PMU_N_PACED_SLOTS;
	}
	return msg->n_datagrams;
}


static void *memcpy_iov (void *dest,const const_iovec_t *iov)

// copy 'iov' to 'dest', return first byte after 'dest' not copied to

{
	memcpy(dest,iov->iov_base,iov->iov_len);
	return dest + iov->iov_len;
}


static bool move_paced_to_tx (pmu_if_t *pi,const paced_datagram_t *d)

// move paced datagram 'd' to the unpaced tx ring for pi immediately.
// return false if this cannot be done, true otherwise

{
	frame_header_t *tx;
	void *udp,*base_udp;
	unsigned n;
	size_t len;

	assert(d);
	len = d->fixed_hdr.iov_len + d->per_datagram_hdr.iov_len;

	assert(d->n_payload_segments <= MAX_PAYLOAD_SEGMENTS_PER_DATAGRAM);
	for (n = 0; n != d->n_payload_segments; ++n)
		len += d->per_datagram_payload[n].iov_len;

	n = pmu_allocate_unpaced(pi,(void **)&tx,1);
	if (!n) {
		return false;
	}

	base_udp = udp = tx+1; // UDP payload

	pmu_set_frame_header (pi,tx,d->to,&pi->derived.local_ipv6,d->source_port,len);
	udp = memcpy_iov (udp,&d->fixed_hdr);
	udp = memcpy_iov (udp,&d->per_datagram_hdr);
	for (n = 0; n != d->n_payload_segments; ++n)
		udp = memcpy_iov (udp,&d->per_datagram_payload[n]);

	assert(base_udp + len == udp);

	return true;
}


static void next_paced (pmu_if_t *pi)
{
	if (++pi->next_paced_xmit == PMU_N_PACED_SLOTS) {
		pi->next_paced_xmit = 0;
	}
	assert (pi->n_paced_buffers);
	--pi->n_paced_buffers;
}


static void pmu_transmit (pmu_if_t *pi)
{
	int wait_option,err;
	uint64_t now = hpet_cycles();
	uint64_t duration;
	unsigned n = 0;

	for (wait_option = MSG_DONTWAIT;;wait_option = 0) {
		err = send(pi->tx.socket,NULL,0,wait_option);
		if (err >= 0)
			break;
		if (errno == EAGAIN) {
			log_debug(lg,"EAGAIN");
			continue;
		}
		if (errno == ENOBUFS) {
			log_debug(lg,"ENOBUFS");
			continue;
		}

		log_error(lg,"tx_kick send error %d errno %d",err,errno);
		assert (err >= 0);
	}
	if (xmit_track) for (n = 0;xmit_track->next_tx != xmit_track->next;++n,++xmit_track->next_tx)
		xmit_track->next_tx->xmit_tx = now;

	duration = hpet_cycles() - now;
	log_debug (lg,"pmu_transmit kicked %d frames took %ld ticks",n,duration);
}


void pmu_tx_kick (pmu_if_t *pi)
{
	bool done = false;
	unsigned n_placed = 0;
	static unsigned total_placed = 0;
	volatile unsigned *paced_buffer_count = &pi->n_paced_buffers;
	unsigned original_paced_count = pi->n_paced_buffers;
	uint64_t prior_deadline = 0;

	do {
		while (*paced_buffer_count) {
			assert (*paced_buffer_count <= original_paced_count);
			paced_slot_u *s = &pi->paced_slot[pi->next_paced_xmit];
			uint64_t now = hpet_cycles();

			assert(pi->next_paced_xmit < PMU_N_PACED_SLOTS);

			if (s->callback.must_be_null == NULL) {
				if (!s->callback.completion_cb) {
					done = true;
				}
				else {
					s->callback.completion_cb(s->callback.msg_hdr,prior_deadline);
					done = false;
					next_paced(pi);
				}
			}
			else if (later_than(s->datagram.earliest_xmit,now)) {
				done = true;
			}
			else if (move_paced_to_tx(pi,&s->datagram)) {
				++n_placed;
				++total_placed;
				prior_deadline = s->datagram.earliest_xmit;
				done = false;
				next_paced(pi);
				pmu_commit_unpaced(pi);
			}
			else {
				done = false;
				break;
			}
		}
		pmu_transmit(pi);
	} while (!done &&  *paced_buffer_count);
}


unsigned pmu_receive (pmu_if_t *pi,void **frames,size_t max_n)
{
	volatile struct tpacket_hdr *tp;
	unsigned n;
	frame_header_t *fh;

	assert(pi);
	assert(frames);

	memset(frames,0,sizeof(void *)*max_n);

	for (n = 0;max_n;--max_n,++n) {
		tp = next_frame(&pi->rx);

		if (!(tp->tp_status & TP_STATUS_USER))
			break;
		if (tp->tp_status & TP_STATUS_LOSING) {
			pi->last_drop_seen = hpet_cycles();
			if (!pi->last_drop_seen) pi->last_drop_seen = 1;
			log_warn(lg,"dropn seen @%ld",pi->last_drop_seen);
		}
		if (tp->tp_status & (TP_STATUS_COPY|TP_STATUS_CSUMNOTREADY)) {
			log_warn(lg,"Bad status %lx",tp->tp_status);
			break;
		}


		assert((tp->tp_status & TP_STATUS_VLAN_VALID) == 0);

		if (tp->tp_net < sizeof(struct tpacket_hdr)) {
			log_debug(lg,"tp_net %d",tp->tp_net);
			assert(tp->tp_net >= sizeof(struct tpacket_hdr));
		}
		fh = frames[n] = ((void *)tp) + tp->tp_net;
		assert(tp->tp_mac + sizeof(struct ethhdr) == tp->tp_net);
		// TODO allow for difference to be either size of L2 header or L2 with VLAN header
		trace_frame("In",tp,fh);
		if (++pi->rx.next == pi->rx.total_nr)
			pi->rx.next = 0;
	}

	// TODO handle error statuses

	return n;
}

#define aligned_ptr(p,alignment) ((void *)(((unsigned long)(void *)p) & ~((alignment)-1)))

void pmu_rx_frame_release (pmu_if_t *pi,const void *p)
{
	struct tpacket_hdr *ph;
	frame_header_t *fh;

	assert(pi);
	assert(p);

	ph = (struct tpacket_hdr *)aligned_ptr(p,4*1024);
	fh = (frame_header_t *)(((void *)ph)+ph->tp_net);
	if (fh != p) {
		trace_frame("Prefail",ph,p);
		assert (fh == p);
	}
	ph->tp_status = TP_STATUS_KERNEL;
	__sync_synchronize();
};


void pmu_rx_kick (pmu_if_t *pi)
{
	struct pollfd pfd;
	int err;

	pfd.fd = pi->rx.socket;
	pfd.revents = 0;
	pfd.events = POLLIN|POLLRDNORM|POLLERR;

	for (;;) {
		err = poll(&pfd,1,0);
		if (err >= 0) break;
		if (err == -EAGAIN) continue;
		if (err == -EINTR) continue;
		log_error(lg, "rx_kick err %d",err);
		assert (err >= 0);
	}
}
