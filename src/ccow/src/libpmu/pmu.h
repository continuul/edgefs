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

#ifndef PMU_H_
#define PMU_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>


#include <string.h>
#include <ifaddrs.h>

#include "ccowutil.h"
#include <netinet/ether.h>

/*
 *
 PMU is a utility library designed to exploit direct memory mapped network IO interfaces in Linux,
 such as the Packet_MMAP capability of AF_PACKET sockets, or DPDK rings.

 The goal is to provide as close to zero-copy networking as possible and to support paced transmission
 of long messages. The utility is primarily designed to support UDP messaging, but can actually send
 any IP datagrams. However, it offers no support for transport layer logic. IF you want to send IP
 datagrams encoding TCP or SCTP then you application is responsible for implementing TCP or SCTP.

 Packet_MMAP provides "Zero copy" networking for Linux without any NIC model dependencies.
 Unfortunately tolhe "zero" involves some creative counting on the pafrt of Linux kernel developers,
 most folks would describe this as being at best a one copy solution.

 Aside from the counting issue, it is definitely one less copy for each datagram sent or received
 and the memory mapped rings can reduce the number of user/kernel interactions.

 DPDK rings provide true zero-copy networking, but require more reuqires complex logic configure NICs
 with model independence, and to process network exceptions ina model independent fashiop. The initial
 implementation of this package will not support DPDK devices initially, but the interfaces are designed
 to allow applications to utilize DPDKD once available wihout having to change the application layer.

*/

typedef void *ring_frame_t;	/* A frame buffer, with required headers, from the RX or TX ring
					For Packet MMAP this is the socket ring, not the actual hardware DMA rings. */

/* There are packet rings for both transmit and receive for each network interface t
 *
 */
typedef struct pmu_ring
{				// TODO: consider making this a pointer to an implementation dependent type
	int socket;		// socket to drive this ring (tx or rx)
	size_t next;		// index of next buffer for userland to reference
	ring_frame_t mmap_ptr;	// mmapped buffers
							// Each buffer contains a struct tpacket_hdr and an struct ethhdr before the frame_buffer.
							// Eventually the ethernnet header *might* be either a single L2 header or a VLAN tagged header.
	size_t frame_size;	// size of frame buffer (including non-transmitted header) in mapped buffer
				// This may be rounded up gto meet alignment requirements
				// This is size of struct that ring_frame_t points at, but C doesn't understand
				// variable sized arrays
	size_t	total_size;	// total size of mapped area
				// total_size % frame_size MUST == 0
	size_t	total_nr;	// .total_size / .frame_size
} pmu_ring_t;

/*
 Scatter gather list holding messages to be submitted to the TX packet ring under pace control
 This is used to send bulk payload at a pace which is typically just short of wire rate.
 Sending faster than the paced rate will merely invoke buffering, which is undesriable.

 This is a single-threaded library. For any given pmu_if_t it is intended to be called
 exclusively from a single thread. If is fully re-entrant *only* when pmu_if_t is different.
 */


typedef struct unpaced_buf
{			// buffer and length for one IP dagtagram.
	void	*buf;	// pointer to the payload portion of a socket TX Ring.
			// This is already past the tracking header. The payload
			// that must be filled in is either L2 on or L3 on.
	size_t len;	// When this is supplied it holds the maximum len allowed.
			// The user may shrink this to send a smaller size.
} unpaced_buf_t;

/*
 Paced Buffers are used to send large messages, such as a NexentaEdge Chunk at a fixed pace.
 This fixed pace is designed to come as close to fully utilizing reserved bandwidth without
 exceeding it. Bursting the frames at wire rate and periodically slowing down would rely on
 switch and/or target buffering to absorb excess frames. When the Ethernet Class of Service is
 shared with other traffic this can result in unpredictable delays for the other traffic.

 Paced output is designed to deliver each Ethernet Frame "just in time". This is done by attaching an
 earliest xmit time to each frame (where the "xmit" being timed is the submission to the MMAPped TX Ring.

*/

typedef struct const_iovec
{			// run-of-the-mill iovec struct, but with const pointer.
	const void *iov_base;
	size_t iov_len;
} const_iovec_t;

// typedef unsigned long int ticks_t;	// time from the hpet clock, hept_hz() ticks per second
typedef unsigned long int bit_ticks_t;	// time it takes to transmit 1 bit on a 10 GbE link.
					// This is only used to determine delata before scaling to ticks_t

#define MAX_PAYLOAD_SEGMENTS_PER_DATAGRAM 16
typedef struct paced_datagram
{
				// struct created in pmu_if_t to hold each datagram in paced messages
	const struct sockaddr_in6 *to;
	const_iovec_t fixed_hdr;
	const_iovec_t per_datagram_hdr;
	uint64_t earliest_xmit;
	uint16_t source_port;
	uint16_t n_payload_segments;
	const_iovec_t per_datagram_payload[MAX_PAYLOAD_SEGMENTS_PER_DATAGRAM];
} paced_datagram_t;


typedef struct paced_message
{	/*
	   defines a paced_message

	 A Paced message is a sequence of datagrams sent at a pace to a single UDP destination.
	 The datagram payload is divided between per-datagram headers and payload.
	 The per datagram headers is provided as an array of n-byte records (all the same size).

	 The content of the header is up to the application layer, but presumably serializes each
	 datagram within the paced message.

	 The payload is specified as a single vector, and the amount to be included in each datagram
	 (Although the last datagram will have 1..per_Datagram size dependent on the total_len).

	 All paced messages through a given pi will be paced not to exceed the configured max_paced_bw
	 This is done by calculating an earliest xmit_time for each paced packet which determines when
	 that packet can be submiotted to the packet tx ring. This is based on the prior earliest xmit
		time plus its transmission time (or now, whichever is later).

	*/

	const struct sockaddr_in6 *to;
	uint16_t source_port;		// source address is taken from the pmu_if_t
	const void *fixed_header;
	size_t fixed_header_size;
	const void *per_datagram_hdr;
	size_t n_datagrams;
	size_t per_datagram_hdr_size;
	size_t payload_per_datagram_len;
	unsigned payload_segments;
	const_iovec_t payload[1];	// actually [n_segments]
					// Any datagram must be built from at most  MAX_PAYLOAD_SEGMENTS_PER_DATAGRAM segments
					// Thisv is 8K over 16 segments, or 512 bytes each.
} paced_message_t;

typedef struct paced_callback
{
	const void *must_be_null;	// to differentiate from paced_datagram_t
	void (*completion_cb)(const struct paced_message *,uint64_t deadline);
	const struct paced_message *msg_hdr;
} paced_callback_t;

typedef union paced_slot
{
	paced_datagram_t datagram;
	paced_callback_t callback;
} paced_slot_u;


typedef struct pmu_cfg
{			// configuration items for a packet mmap device interface
	unsigned max_frames_in_single_paced_xmit;
	unsigned max_paced_bw;	// Mbits/sec
	unsigned max_unsolicited_burst;
} pmu_cfg_t;

typedef struct pmu_derived
{				// informational fieds set when packet device is initialized
	size_t tx_offset;	// offset of struct ethhdr in tx frame
	size_t rx_offset;	// offset of struct ethhdr in rx frame
	unsigned max_receive_hold;	// What is the longest that the application layer can hold a packet_mmmap_frame_t
					// without stalling the pipeline? This is expressed in the number of paced frames
					// that could have been received. This is minimal for Packet MMAP rings, and very
					// generous for DPDK rings.
	struct in6_addr local_ipv6;
} pmu_derived_t;

#define PMU_N_PACED_SLOTS 1024

typedef struct pmu_if
{
	unsigned ifindex;		// Unsigned identifier of the Ethernet device. Kernel ifindex for Packet_MMAP, own index of DPDK
					// name
					// the remaining fiels are PRIVATE. Ignore the fact that C forces them to be included in the
					// struct - they are off limits to non-PMU code.

	struct pmu_ring rx;		// socket used to receive IPV6 datagrams from this device.
	struct pmu_ring tx;		// handle used to submit datagrams for actual transmission.
	pmu_cfg_t	config;		// configuration of this itnerface
	pmu_derived_t	derived;	// values computed based on .config
	uint64_t	last_drop_seen;		// When device layer last reported a receive drop
						// recorded as 1 if clock was literally 0.
	unsigned next_paced_xmit;		// index of new paced_buf to be sent to the actual tx ring.
	unsigned next_unpaced_commit;	// index of next unpaced_buf to be committed
	unsigned next_paced_alloc;	// index of next paced buf to be allocated
	unsigned next_unpaced_alloc;	// index of next unpaced (socket tx ring) buffer to be allocated
						// This is advanced ahead of the tx.next pointer, which advances when
						// the buffers are cleared to be sent.
	uint64_t paced_next_xmit_time;	// transmission time based on last placed paced_Slot plus transmission time for it
					// at the configured max paced bandwidth.
	unsigned n_paced_buffers;	// number of paced messages in paced_slot[*] yet to be copied to the actual TX ring.
	uint64_t	total_xmit;	// total xmit time since last time user cleared this field.
					// Error-free transmission could not have occurrent in less time than this.
	paced_slot_u paced_slot[PMU_N_PACED_SLOTS];
} pmu_if_t;

extern pmu_if_t *pmu_initialize_interface (const char *name, const pmu_cfg_t *cfg);
extern void pmu_main(pmu_if_t *pmuif, void *loop);

/*
 set up a pmu sockeet pair to interface with the named device
 Supports frame_size, with an RX_RING of <n_rx> frames, tx_ring of tx_frames,
 and supporting up to <n_paced_xmit> paced transmissions
*/

extern void pmu_close_interface (pmu_if_t *pi, bool force); // close the interface, unless 'force' is true existing output will be allowed to complete

extern size_t pmu_allocate_unpaced (pmu_if_t *pi,void **bufs,size_t max_n);

/*

 Allocate up to N unpaced transmit buffers that should be sent
 almost immediately, and in order, using pmu_commit_unpaced()
 After they are filled in of course..

 All allocated buffers will have the size configured for pi.

 Do not call pmu_send_paced() or pmu_allocate_unpaced() again
 until this allocation has been pmu_commit()d

 */


typedef struct frame_header
{				// The header of a typical buffer
	struct ipv6hdr ipv6;
	struct udphdr udp;
} frame_header_t;

extern void pmu_set_frame_header (
		const pmu_if_t *pi,
		frame_header_t *fh,
		const struct sockaddr_in6 *to,
		const struct in6_addr *source_ip,
		uint16_t source_port,
		size_t len
);

/*
 Uitility function to fill in the L2 thorugh l4 portion of a frame buffer
 using traditionlal sockets parameters. The application can also fill these
 fields out itself.
*/
void pmu_set_reply_header (
		const pmu_if_t *pi,
		frame_header_t *fh,
		const frame_header_t *in_reply_to,
		const struct in6_addr *unicast_source,
		size_t len
);

/*
 Utility function to fill in the l2 through l4 header as a reply to another frame.
 A unicast source address must be provided if original packet was multicast since
 a multicast address cannot be used as the source of a packet.

 The length is the UDP length of the reply data.

*/

extern void pmu_commit_unpaced (pmu_if_t *pi);

/*
 mark the next 'n' allocated unpaced buffers for this device  as being transmittable.
 Lengths must have been sent in the L3/L4 headers, the frame length is derived from that.
 The initial version of this package only supports IPV6/UDP.
*/

extern unsigned pmu_send_paced (
		pmu_if_t *ni,
		const paced_message_t *msg,
		void (*complete_cb)(const paced_message_t*,uint64_t deadline)
);

/*
 Asynchronously schedule transmission of 'msg' on 'ni'.
 When the contents referenced in 'msg' are no longer needed (either because they have been
 transmitted or because they are fully copied to transmit buffers) the 'cb' callback will
 be made (Unless 'cb' is null).

 Functional return is zero (if buffering is not available now) or n_datagrams queued.
*/

extern void pmu_tx_kick (pmu_if_t *pi);

// trigger deferred tx activities, such as transferring paced datagrams to the TX ri
// and transferring from the socket TX ring to the hardware transmit buffers.




// RX Methods

extern unsigned pmu_receive (pmu_if_t *pi,void **frames,size_t max_n);

/*
 Receive pointers to up to n frames received on 'pi'
 These should be struct frame_headers, but filtering does not guarantee they are UDP,type
 Justy eth/IPV6.

 Functional return is # of frames (up to max_n) received, or 0- if none received.

 These buffers will be mapped for write access to enable returning them to the kernel.
 This is done by pmu_rx_frame_release() -- the caller of this function should not alter
 any of the delivered frames in any way.
 The status flag is the ONLY field that should be updated and only by the pmu library,
 but the MMU doesn't grant permissions with the needed granularity.

 An IP datagram can be found in each at frames[n] + pi->derived.rx_l3_offset.

 These buffers must be returned to pmu before they are needed for the next set of inbound frames.
 The Packet_mmap system uses the RX RING as a strict ring, so there will be severe head-of-line blocking
 if the application layers takes a long time to process these frames. DO NOT do further Io on these buffers
 unless you are positive that the IO will complete long before the ring wrap time (it probably will not).

*/



typedef struct xmit_track {
	uint64_t xmit_go; // When slot was enabled for transmit
	uint64_t xmit_tx; // when the socket send() call was made after the slot was enabled.
	uint64_t xmit_done;	// when the slot was detected as being returned by the kernel
	unsigned size;
	volatile unsigned long *status;
} xmit_track_t;

typedef struct xmit_tracker {
	xmit_track_t *next,*next_tx,*lim;
	xmit_track_t array[0];
} xmit_tracker_t;

extern xmit_tracker_t *xmit_track;


extern void pmu_rx_frame_release (pmu_if_t *pi,const void *p);

// Release the userland claim on 'p' so that it can be used to receive another frame
// p must have been supplied previously by pmu_receive

extern void pmu_rx_kick (pmu_if_t *pi);

// trigger deferred rx processing, such as transferring from hardware receive buffers.
// to the Socket RX ring.

extern const void *pmu_latest_tx (pmu_if_t *pi);

// Obtain token referring to the latest tx frame submitted.
// This can be used to test whether said frame has been transmitted

extern bool pmu_tx_done (const void *p);

/*

 returns true if 'p' (obtained from pmu_latest_tx has been transmitted.
 Note that this references a slot in a transmit ring, so eventually a
 slot can be re-used for a later transmission.

*/

// Timer routines
extern int hpet_init (void);		// Initialize hpet timer
extern uint64_t hpet_hz (void);		// # of HPET ticks per second
extern uint64_t hpet_cycles (void);	// # of HPET ticks since whenever (module 64 bits)




#endif /* PMU_H_ */
