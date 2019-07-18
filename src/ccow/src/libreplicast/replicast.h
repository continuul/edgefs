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
#ifndef __REPLICAST_H__
#define __REPLICAST_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "lfq.h"

#include "queue.h"
#include "ccowutil.h"
#include "state.h"
#include "msgpackalt.h"
#include "rtbuf.h"
#include "hashtable.h"
#include "uthash.h"

#define UDP_HDR_ROOM (48 + 26)
#define REPLICAST_DGRAM_MAXLEN		(uint16_t)(IP_MAXPACKET - UDP_HDR_ROOM)

#define REPLICAST_GETS_MAX		1024
#define REPLICAST_STR_MAXLEN		1024
#define REPLICAST_OBJPATH_MAXLEN	(REPLICAST_STR_MAXLEN*4 + 1)
#define REPLICAST_CHUNKMAP_MAXLEN	64
#define REPLICAST_CHUNK_SIZE_MIN	256
#define REPLICAST_CHUNK_SIZE_MAX	(8 * 1024 * 1024)
#define REPLICAST_DGRAM_MAX		(int)(1 + (REPLICAST_CHUNK_SIZE_MAX / 65536))
#define REPLICAST_REPLICATION_COUNT_MIN	1
#define REPLICAST_REPLICATION_COUNT_MAX	8 /* minimal number of design. vdevs */
#define REPLICAST_SYNC_PUT_MAX		4
#define REPLICAST_SELECT_POLICY_MAX	8
#define REPLICAST_PROPOSALS_MAX		64
#define REPLICAST_SRV_INTERFACES_MAX	16
#define REPLICAST_DEVROW_MAX		64

/* reserved system object and metadata key names */
#define REPLICAST_SYSKEY_MAXLEN		64

#define REPLICAST_UDP6_SEND_RETRY	5

/* reserved system values */
#define RT_SYSVAL_TENANT_ADMIN			"root"
#define RT_SYSVAL_TENANT_SVCS			"svcs"
#define RT_SYSVAL_REPLICATION_COUNT		3
#define RT_SYSVAL_SYNC_PUT			0
#define RT_SYSVAL_SYNC_PUT_NAMED		3
#define RT_SYSVAL_SYNC_PUT_ACK_MIN		0
#define RT_SYSVAL_SYNC_PUT_DEDUP_MIN		0
#define RT_SYSVAL_SYNC_PUT_EXTRA		0
#define RT_SYSVAL_SYNC_PUT_EXTRA_WAIT		20
#define RT_SYSVAL_SYNC_PUT_FD_MIN		2
#define RT_SYSVAL_SYNC_PUT_COMMIT_WAIT		1
#define RT_SYSVAL_SELECT_POLICY			4 /* default is QDEPTH */
#define RT_SYSVAL_EXPUNGE_ONSPLIT		0 /* default is "false" */
#define RT_SYSVAL_CHUNKMAP_BTREE		"btree_map"
#define RT_SYSVAL_CHUNKMAP_FIXED		"fixed_map"
#define RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX	"btree_key_val"
#define RT_SYSVAL_CHUNKMAP_CHUNK_SIZE		(1024 * 1024)
#define RT_SYSVAL_CHUNKMAP_BTREE_ORDER_NFSDIR	96
#define RT_SYSVAL_CHUNKMAP_BTREE_ORDER_TSOBJ	256
#define RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K	48
#define RT_SYSVAL_CHUNKMAP_BTREE_ORDER_DEFAULT	192
#define RT_SYSVAL_CHUNKMAP_BTREE_ORDER_MAX	640
#define RT_SYSVAL_CHUNKMAP_BTREE_MARKER_DEFAULT	0
#define RT_SYSVAL_CHUNKMAP_FIXED_DEPTH_DEFAULT	1
#define RT_SYSVAL_CHUNKMAP_FIXED_DEPTH_MAX	2
#define RT_SYSVAL_CHUNKMAP_FIXED_WIDTH_DEFAULT	512
#define RT_SYSVAL_CHUNKMAP_FIXED_WIDTH_MAX	650
#define RT_SYSVAL_JOIN_DELAY			35000
#define RT_SYSVAL_NUMBER_OF_VERSIONS_DEFAULT	1
#define RT_SYSVAL_EC_ENABLED			0
#define RT_SYSVAL_EC_DATA_MODE			0x20602 /* 6:2:rs */
#define RT_SYSVAL_EC_TRG_POLICY			((4*3600) << 4);
#define RT_SYSVAL_FILE_OBJECT_TRANSPARANCY			0
#define RT_SYSVAL_OBJECT_DELETE_AFTER			0
#define RT_SYSVAL_FOT_INODE2OID			".nexenta_inode2oid"
#define RT_SYSVAL_USER_SHARD_COUNT			8
#define RT_SYSVAL_USER_SHARD		"users"
#define RT_SYSVAL_ACL_SHARD_COUNT          8
#define RT_SYSVAL_ACL_SHARD        "acl"
#define RT_SYSVAL_SERVERLIST_GET_TIMEOUT	2000

#define RT_SYSKEY_HEADER			"replicast-header"
#define RT_SYSKEY_HEADER_FLAGS			0
#define RT_HDR_JUMPTBL_SIZE			35

/* version manifest section indexes */
#define RT_SYSKEY_HEADER_SECTIDX		0
#define RT_SYSKEY_METADATA_SECTIDX		1
#define RT_SYSKEY_ACL_LIST_SECTIDX		2
#define RT_SYSKEY_CUSTOM_METADATA_SECTIDX	3
#define RT_SYSKEY_REFERENCE_LIST_SECTIDX	4

enum vmkeys_idx {
	RT_SYSKEY_HEADER_IDX,
	RT_SYSKEY_METADATA_IDX,
	RT_SYSKEY_CLUSTER_IDX,
	RT_SYSKEY_TENANT_IDX,
	RT_SYSKEY_BUCKET_IDX,
	RT_SYSKEY_OBJECT_IDX,
	RT_SYSKEY_NAME_HASH_ID_IDX,
	RT_SYSKEY_CLUSTER_HASH_ID_IDX,
	RT_SYSKEY_PARENT_HASH_ID_IDX,
	RT_SYSKEY_TENANT_HASH_ID_IDX,
	RT_SYSKEY_BUCKET_HASH_ID_IDX,
	RT_SYSKEY_OBJECT_HASH_ID_IDX,
	RT_SYSKEY_VERSION_LIST_IDX,
	RT_SYSKEY_ACL_LIST_IDX,
	RT_SYSKEY_REFERENCE_LIST_IDX,
	RT_SYSKEY_OBJECT_DELETED_IDX,
	RT_SYSKEY_UVID_TIMESTAMP_IDX,
	RT_SYSKEY_TX_GENERATION_ID_IDX,
	RT_SYSKEY_CREATION_TIME_IDX,
	RT_SYSKEY_UVID_SRC_COOKIE_IDX,
	RT_SYSKEY_UVID_SRC_GUID_IDX,
	RT_SYSKEY_TENANT_CTYPE_IDX,
	RT_SYSKEY_CHUNKMAP_TYPE_IDX,
	RT_SYSKEY_CHUNKMAP_CHUNK_SIZE_IDX,
	RT_SYSKEY_CHUNKMAP_BTREE_ORDER_IDX,
	RT_SYSKEY_LOGICAL_SIZE_IDX,
	RT_SYSKEY_PREV_LOGICAL_SIZE_IDX,
	RT_SYSKEY_OBJECT_COUNT_IDX,
	RT_SYSKEY_TENANT_STATUS_IDX,
	RT_SYSKEY_CUSTOM_METADATA_IDX,
	RT_SYSKEY_INLINE_DATA_FLAGS_IDX,
	RT_SYSKEY_REPLICATION_COUNT_IDX,
	RT_SYSKEY_ESTIMATED_USED_IDX,
	RT_SYSKEY_HASH_TYPE_IDX,
	RT_SYSKEY_COMPRESS_TYPE_IDX,
	RT_SYSKEY_FAILURE_DOMAIN_IDX,
	RT_SYSKEY_SYNC_PUT_IDX,
	RT_SYSKEY_SELECT_POLICY_IDX,
	RT_SYSKEY_NUMBER_OF_VERSIONS_IDX,
	RT_SYSKEY_TRACK_STATISTICS_IDX,
	RT_SYSKEY_CHUNKMAP_BTREE_MARKER_IDX,
	RT_SYSKEY_IOPS_RATE_LIM_IDX,
	RT_SYSKEY_EC_ENABLED_IDX,
	RT_SYSKEY_EC_DATA_MODE_IDX,
	RT_SYSKEY_EC_TRG_POLICY_IDX,
	RT_SYSKEY_FILE_OBJECT_TRANSPARANCY_IDX,
	RT_SYSKEY_OBJECT_DELETE_AFTER_IDX,

	/* client side only, used by iterator */
	RT_SYSKEY_VM_CONTENT_HASH_ID_IDX
};

enum replicast_opcode {
	RT_ERROR,
	RT_SERVER_LIST_GET,
	RT_SERVER_LIST_RESPONSE,
	RT_NAMED_CHUNK_GET,
	RT_NAMED_CHUNK_GET_RESPONSE,
	RT_UNNAMED_CHUNK_GET,
	RT_UNNAMED_CHUNK_GET_RESPONSE,
	RT_RECOVERY,
	RT_RECOVERY_ACK,
	RT_NAMED_CHUNK_PUT_PROPOSAL,
	RT_UNNAMED_CHUNK_PUT_PROPOSAL,
	RT_NAMED_PAYLOAD_ACK,
	RT_UNNAMED_PAYLOAD_ACK,
	RT_ACCEPT_PROPOSED_RENDEZVOUS,
	RT_GET_ACCEPT_PROPOSED_RENDEZVOUS,
	RT_ACCEPT_CONTENT_ALREADY_STORED,
	RT_ACCEPT_NOT_NOW,
	RT_RENDEZVOUS_TRANSFER,
	RT_GET_RENDEZVOUS_TRANSFER,
	RT_RENDEZVOUS_ACK,			/* aka Relayed ACK */
	RT_RENDEZVOUS_NACK,
	RT_PINGPONG,
	RT_PINGPONG_ACK,
	RT_NGREQUEST,
	RT_NGREQUEST_ACK,
	RT_NGREQUEST_COUNT,
	RT_NGREQUEST_COUNT_ACK,
	RT_NGREQUEST_PURGE,
	RT_NGREQUEST_PURGE_ACK,
	RT_NGREQUEST_LOCATE,
	RT_NGREQUEST_LOCATE_ACK,
	RT_BLOB_LOOKUP,
	RT_BLOB_LOOKUP_ACK,
	RT_BLOB_LOOKUP_RESULT,
	RT_ENCODE_ACK,
	RT_INIT_TCP_CONNECT,
	RT_TCP_CONNECT_SUCCESS,
	RT_PAYLOAD_RCVD,
	RT_CLIENT_NOTIFICATION,
	RT_SG_LOOKUP,
	RT_SG_LOOKUP_RESPONSE,
	RT_SG_CHUNKPUT,
	RT_SG_CHUNKPUT_RESPONSE,
	RT_SG_VMPUT,
	RT_SG_VMPUT_RESPONSE,
	RT_SG_SSPUT,
	RT_SG_SSPUT_RESPONSE,
	RT_OPP_STATUS,
	RT_OPP_STATUS_ACK,
	RT_ROWEVAC,
	RT_ROWEVAC_ACK,
	RT_SG_PING_PONG,
	RT_SG_PING_PONG_RESPONSE,
	RT_SG_EXPUNGE,
	RT_SG_EXPUNGE_RESPONSE,
	RT_SG_DYN_FETCH,
	RT_SG_DYN_FETCH_RESP,
	RT_RES_GET,
	RT_RES_GET_RESPONSE,
	RT_SG_CHUNKGET,
	RT_SG_CHUNKGET_RESPONSE,
	RT_ONDEMAND_POLICY_ACK,
	RT_END
};

extern char *replicast_opcode_str[];
extern char *replicast_error_str[];

enum replicast_delete_type {
	RT_DELETED_NOT,
	RT_DELETED_LOGICALLY,
	RT_DELETED_EXPUNGED,
	RT_DELETED_EXPUNGED_VERSION,
	RT_DELETED_VERSION,
	RT_DELETED_END
};

enum replicast_failure_domain {
	FD_ANY_FIRST,
	FD_SERVER,
	FD_ZONE,
	FD_END
};

enum replicast_ec_algorithm {
	ECA_NONE = 0,
	ECA_XOR,
	ECA_RS,
	ECA_RS_CAUCHY,
	ECA_END
};

static char *ec_algorithm_name[] = {
	"ECA_NONE",
	"ECA_XOR",
	"ECA_RS",
	"ECA_RS_CAUCHY",
	"ECA_INVALID"
};

#define ECW_MAX			26
#define ECP_MAX			6

#define FLEXCOUNT_KEY_LENGTH	10
#define FLEXCOUNT_TAB_LENGTH	(1 << FLEXCOUNT_KEY_LENGTH)

#define DEFAULT_VBUF_TOTAL	(950 * 1024 * 1024LU)	/* 950MB */

struct cl_vdev {
	uint128_t vdevid;	/* unique id for this device */
	uint16_t port;		/* port for listening on the traffic */
	uint64_t size;		/* total size of the device */
	uint64_t avail;		/* available free space */
	uint64_t logical_used;	/* logicalk used space */
	uint16_t activerows;	/* number of active rows */
	uint16_t numrows;	/* number of rows in hashcount */
	uint8_t  state;
	uint16_t hashcount[FLEXCOUNT_TAB_LENGTH];
};				/* hashcount array for this device */

enum cl_node_state {
	CL_NODE_NEW,
	CL_NODE_QUERY_ISSUED,
	CL_NODE_QUERY_FAILED,
	CL_NODE_QUERY_SUCCESS,
	CL_NODE_JOINED,
};

struct cl_node {
	uint128_t serverid;	/* unique id for this server */
	uint128_t addr;		/* ipv6 address for this server */
				/* For local use, ignored by remote node */
	enum cl_node_state state;
	uint16_t port;		/* listen port for the server */
	uint16_t zone;		/* logical failure domain */
	uint32_t nr_vdevs;	/* number of vdevs attached to this server */
	struct cl_vdev *vdevs;	/* list of vdevs */
	uint8_t	gateway;	/* gateway only node as specified */
	uint8_t fdmode;         /* failure domain this cl_node came from */
	uint8_t ckpread;	/* this node was read from a checkpoint */
};

/* our extensions to msgpackalt */
int replicast_pack_uint128(msgpack_p *p, const uint128_t *v);
int replicast_unpack_uint128(msgpack_u *u, uint128_t *v);
int replicast_pack_uint512(msgpack_p *p, const uint512_t *v);
int replicast_unpack_uint512(msgpack_u *u, uint512_t *v);


int replicast_pack_repvdev(msgpack_p *p, struct cl_vdev *vdevs,
    uint32_t nr_vdevs, int validhc);
int replicast_unpack_repvdev(msgpack_u *u, struct cl_vdev *vdevs,
    uint32_t nr_vdevs, int validhc);

struct replicast_transaction_id {
	enum replicast_opcode opcode;
	uint16_t protocol_version;
	uint16_t fhrow;
	uint64_t txcookie;
	uint32_t sequence_num;
	uint32_t sub_sequence_num;
	uint128_t source_addr;
	uint16_t source_port;
};

/* TODO: Should we add magic number in the header? */
struct replicast_datagram_hdr {
	struct replicast_transaction_id transaction_id;
	struct replicast_transaction_id orig_id;
	uint16_t datagram_num;
#define RD_ATTR_RETRY                   0x00000001
#define RD_ATTR_QUERY                   0x00000002
#define RD_ATTR_TRLOG_SOP               0x00000004
#define RD_ATTR_NO_OVERWRITE            0x00000008
#define RD_ATTR_LOGICAL_DELETE          0x00000010
#define RD_ATTR_OBJECT_REPLACE          0x00000020
#define RD_ATTR_VERSIONS_QUERY          0x00000040
#define RD_ATTR_DELETE_OBJECT_VERSION	0x00000080
#define RD_ATTR_CHUNK_MANIFEST          0x00000100
#define RD_ATTR_CHUNK_PAYLOAD           0x00000200
#define RD_ATTR_VERIFY_PAYLOAD          0x00000400
#define RD_ATTR_REPLICATE_PAYLOAD       0x00000800
#define RD_ATTR_VERSION_MANIFEST        0x00001000
#define RD_ATTR_EXPUNGE_OBJECT          0x00002000
#define RD_ATTR_CHUNK_ZEROBLOCK         0x00004000
#define RD_ATTR_SYNC_PUT                0x00008000
#define RD_ATTR_COMPOUND                0x00010000
#define RD_ATTR_PSEUDO_GET              0x00020000
#define RD_ATTR_UNICAST_UDP             0x00040000
#define RD_ATTR_UNICAST_TCP             0x00080000
#define RD_ATTR_VM_MARKER               0x00100000
#define RD_ATTR_UNICAST_SERVER          0x00200000
#define RD_ATTR_UNICAST_GATEWAY         0x00400000
#define RD_ATTR_NCOMP                   0x00800000 /* operation without (de)compression */
#define RD_ATTR_TARGETED                0x01000000 /* operation is performed on a target vdev */
#define RD_ATTR_PARITY_MAP              0x02000000
#define RD_ATTR_PARITY_ENCODE           0x04000000
#define RD_ATTR_MC_LAZY_JOIN		0x08000000
#define RD_ATTR_TARGETED_DELETE         0x10000000
#define RD_ATTR_SERIAL_OP		0x20000000
#define RD_ATTR_NO_TRLOG                0x40000000
#define RD_ATTR_EXPUNGE_OBJECT_VERSION  0x80000000
#define RD_ATTR_CM_LEAF_WRITE		0x0000000100000000
#define RD_ATTR_OBJECT_REPLACE_INSERT   0x0000000200000000
#define RD_ATTR_GET_CONSENSUS           0x0000000400000000
#define RD_ATTR_EPHEMERAL_VERSION	0x0000000800000000
#define RD_ATTR_PARITY_MAP_VM           0x0000001000000000
#define RD_ATTR_RECOVERY_LAST           0x0000002000000000
#define RD_ATTR_UNICAST_UDP_MCPROXY     0x0000004000000000
#define RD_ATTR_RETRY_FAILFAST          0x0000008000000000
#define RD_ATTR_UNICAST_UNIXSOCK        0x0000010000000000
#define RD_ATTR_MULTISITE               0x0000020000000000
#define RD_ATTR_COMPOUND_TARGETED       0x0000040000000000 /* Secondary compound transfer to a tgt VDEV */
#define RD_ATTR_EVENTUAL_SOP            0x0000080000000000
#define RD_ATTR_GET_ANY                 0x0000100000000000UL
#define RD_ATTR_ISGW_TRLOG              0x0000200000000000UL
#define RD_ATTR_ISGW_ONDEMAND           0x0000400000000000UL /* The object belongs to an on-demand ISGW fetch bucket */
#define RD_ATTR_ONDEMAMD_PIN            0x0000800000000000UL /* Pin a cacheable object */
#define RD_ATTR_ONDEMAND_UNPIN          0x0001000000000000UL /* Unpin a cacheable object*/
#define RD_ATTR_ONDEMAND_PERSIST        0x0002000000000000UL /* Make a cacheable object persistent */
#define RD_ATTR_ONDEMAND_CLONE          0x0004000000000000UL /* Put a cloned object as local */
#define RD_ATTR_ONDEMAND_PREFETCH       0x0008000000000000UL /* A get operation is triggered in order to pre-fetch a cacheable object from remote */
#define RD_ATTR_CHUNK_LOOKUP            0x0010000000000000UL /* A chunk lookup request */
        uint64_t attributes;
        uint8_t hash_type;                /* payload hash type */
	uint64_t fh_genid;		/* flexhash genid */
	uint32_t data_len;		/* For TCP - length of data */
	uv_pipe_t *peer_sock;		/* For unix - socket, to store socket from which data has been received */
};

#define REPLICAST_PROTOCOL_VERSION	0x0001

#define REPLICAST_UNICAST_UDP		1
#define REPLICAST_UNICAST_TCP		2
#define REPLICAST_UNICAST_UDP_MCPROXY	3

#define REPLICAST_TCP_KEEPALIVE		10 /* in secs */

struct replicast_rendezvous_proposal {
	uint64_t start_time;		/* time when the client can start */
	uint64_t delta_time;		/* delta time for the requested size */
	uint64_t weight_io;		/* weight based on disk qdepth, network qdepth */
	uint64_t avail_space;		/* current free space available in % * 1000000 */
};

struct replicast_object_name {
	uint512_t name_hash_id;
	uint512_t parent_hash_id;
	uint64_t uvid_timestamp;
	uint64_t generation;
	uint64_t vmm_gen_id;
	uint64_t version_uvid_timestamp;
};

/*
 * Storage for Replicast message. Will guarantee that it will fit in
 * all types of messages. Used for efficient unpacking on receive.
 */
enum {E_REPMSG_DETAILS_SIZE = 512};

struct repmsg {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint8_t details[E_REPMSG_DETAILS_SIZE];
};
#define REPMSG_SIZEOF_CHECK(st) \
    static_assert(sizeof (st) < sizeof (struct repmsg), "sizeof error " #st)

struct repmsg_generic {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
};
REPMSG_SIZEOF_CHECK(struct repmsg_generic);
int replicast_pack_generic(msgpack_p *p, struct repmsg_generic *msg,
    uint32_t *datagram_num_byte, uint32_t *num_datagrams_byte);
int replicast_unpack_generic(msgpack_u *u, struct repmsg_generic *msg);

#define MAX_DGRAM_RETRY	3	/* max num of retries on a single udp send */
#define HDR_GEN_SIZE	(int)(sizeof (struct repmsg))
#define BUF_CHUNK_SIZE	(int)(REPLICAST_DGRAM_MAXLEN - HDR_GEN_SIZE)
#define MAX_DGRAM_COUNT 256	/* 256 * 64K = 16MB is the max you can txfr */

struct repmsg_ngrequest {
	uint16_t fhrow;
	uint32_t message_size;
	void *message;
	// data array follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_ngrequest);

struct repmsg_ngrequest_count {
	int32_t count;
	uint128_t vdev;
	uint64_t generation;
	uint512_t chid;
	uint512_t nhid;
	uint8_t hash_type;
	int32_t chunk_type;
};
REPMSG_SIZEOF_CHECK(struct repmsg_ngrequest_count);

struct repmsg_ngrequest_locate {
	uint16_t seq_num;
	uint16_t op_mode;
	uint64_t nvbrs_max;
	uint16_t fhrow;
	uint128_t vdev;
	uint32_t n_chids;
	uint512_t* chids;
	uint8_t* count;
	uint8_t* hash_type;
	uint8_t* chunk_type;
	uint64_t* n_vbrs;
	uint8_t* flags;
	int *chid_status;
	/* The fields below are used for a VBR lookup */
	uint512_t name_hash_id;
	uint512_t ref_chid;
	uint64_t generation;
	uint64_t uvid_timestamp;
	uint8_t ref_type;
	uint8_t ref_hash;
	uint8_t rep_count;
	uint64_t attr_mask;
	uint64_t attr_value;

};
REPMSG_SIZEOF_CHECK(struct repmsg_ngrequest_locate);


struct repmsg_ngrequest_purge {
	uint512_t nhid;
	uint64_t hi_version;
	uint64_t low_version;
	uint64_t version_uvid_timestamp;
	uint8_t is_trlog_obj;
	uint8_t hash_type;
	int32_t status;
};
REPMSG_SIZEOF_CHECK(struct repmsg_ngrequest_purge);

struct repmsg_pingpong {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint32_t message_size;
	void *message;
	// data array follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_pingpong);
int replicast_pack_pingpong(msgpack_p *p, struct repmsg_pingpong *msg);
int replicast_unpack_pingpong(msgpack_u *u, struct repmsg_pingpong *msg);

struct repmsg_blob_lookup {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t chid;
	uint8_t	  ttag;
	uint8_t	  hash_type;
};
REPMSG_SIZEOF_CHECK(struct repmsg_blob_lookup);
int replicast_pack_blob_lookup(msgpack_p *p, struct repmsg_blob_lookup *msg);
int replicast_unpack_blob_lookup(msgpack_u *u, struct repmsg_blob_lookup *msg);

struct repmsg_blob_lookup_result {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint8_t ndevs;
};
REPMSG_SIZEOF_CHECK(struct repmsg_blob_lookup_result);
int replicast_pack_blob_lookup_result(msgpack_p *p, struct repmsg_blob_lookup_result *msg);
int replicast_unpack_blob_lookup_result(msgpack_u *u, struct repmsg_blob_lookup_result *msg);

struct repmsg_blob_lookup_ack {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint8_t ndevs;
};
REPMSG_SIZEOF_CHECK(struct repmsg_blob_lookup_ack);
int replicast_pack_blob_lookup_ack(msgpack_p *p, struct repmsg_blob_lookup_ack *msg);
int replicast_unpack_blob_lookup_ack(msgpack_u *u, struct repmsg_blob_lookup_ack *msg);

int replicast_pack_uvbuf_vdevs(msgpack_p *p, uint128_t *vdevs, int n_vdevs);
int replicast_unpack_uvbuf_vdevs(msgpack_u *u, int n_vdevs, uint128_t *vdevs);

struct repmsg_opps {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t vmchid;
	uint512_t nhid;
	int32_t flags;
};
REPMSG_SIZEOF_CHECK(struct repmsg_opps);
int replicast_pack_opp_status(msgpack_p *p, struct repmsg_opps *msg);
int replicast_unpack_opp_status(msgpack_u *u, struct repmsg_opps *msg);

struct repmsg_opps_result {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int16_t	status;
	uint512_t vmchid;
	uint64_t  n_cp; /* Number of payload chunks in the object */
	uint64_t  n_cpar; /* Number of parity chunks in the object */
	uint64_t  n_cm_zl; /* Number of zero-level CM the object has */
	uint64_t  n_cm_tl; /* Number of top-level chunk manifests */
	uint64_t  n_cm_zl_pp; /* number of parity protected zero-level CM */
	uint64_t  n_cm_zl_verified; /* number of verified chunk manifests */
	uint64_t  n_cm_tl_verified; /* number of verified chunk manifests */
	size_t  n_cm_zl_1vbr; /* number of ZL manifests that have at least 1 vbr */
	size_t  n_cm_tl_1vbr; /* number of TL verified that have at least 1 vbr */
	size_t  n_cp_1vbr; /* Number of payload chunks that have at least 1 vbr*/
	uint64_t  n_cp_verified; /* Number of verified payload chunks */
	uint64_t  n_cpar_verified; /* Number of verified parity chunks */
	uint64_t  n_cm_zl_lost; /* Number of lost zero-level parity manifests */
	uint64_t  n_cm_tl_lost; /* Number of lost parity manifests */
	uint64_t  n_cm_zl_erc_err; /* Number of ZL CM with wrong ERC */
	uint64_t  n_cm_tl_erc_err; /* Number of TL CM with wrong ERC */
	uint64_t  n_cp_lost; /* Number of lost chunk payloads */
	uint64_t  n_cpar_lost; /* Number of lost chunk parity */
	uint128_t hostid; /* Information collected on this host */
	uint16_t n_vdevs; /* Number of vdevs on this host */
	uint64_t* vdevs_usage; /* Array of VDEVs disk usage, %*100 */
	uint16_t pp_algo;
	uint16_t pp_data_number;
	uint16_t pp_parity_number;
	uint16_t pp_domain;
};
REPMSG_SIZEOF_CHECK(struct repmsg_opps_result);
int replicast_pack_opp_status_result(msgpack_p *p, struct repmsg_opps_result *msg);
int replicast_unpack_opp_status_result(msgpack_u *u, struct repmsg_opps_result *msg);


struct repmsg_rowevac {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint8_t	opcode; /* Evacuation operation code */
	uint64_t id; /* Job ID */
	uint64_t flags; /* Evacuation options */
	uint64_t amount; /* Number of %/MBytes to be moved */
	uint128_t src_vdev; /* Evacuate a row from this VDEV */
	uint128_t dest_vdev; /* EVacuate a row to this VDEV */
	uint16_t row; /* Index of a row to be evacuted */
	/* Filled in response to the request */
	int8_t status;
};
REPMSG_SIZEOF_CHECK(struct repmsg_rowevac);
int replicast_pack_rowevac(msgpack_p *p, struct repmsg_rowevac *msg);
int replicast_unpack_rowevac(msgpack_u *u, struct repmsg_rowevac *msg);


/*
 * num_datagrams MUST be 1
 */
struct repmsg_error {
	struct replicast_datagram_hdr hdr;
	uint128_t vdevid;
	uint16_t num_datagrams;
	int error;
	uint16_t ngcount;
	uint8_t is_gwcache;
	int fddelta;
};
REPMSG_SIZEOF_CHECK(struct repmsg_error);
int replicast_pack_error(msgpack_p *p, struct repmsg_error *msg);
int replicast_unpack_error(msgpack_u *u, struct repmsg_error *msg);

struct repmsg_recovery {
	struct replicast_datagram_hdr hdr;
	uint512_t content_hash_id;
	uint512_t name_hash_id;
};

REPMSG_SIZEOF_CHECK(struct repmsg_recovery);
int replicast_pack_recovery(msgpack_p *p, struct repmsg_recovery *msg);
int replicast_unpack_recovery(msgpack_u *u, struct repmsg_recovery *msg);

struct repmsg_recovery_ack {
	struct replicast_datagram_hdr hdr;
	uint512_t content_hash_id;
	uint128_t vdevid;
	int32_t status;
	int32_t ngcount;
};

REPMSG_SIZEOF_CHECK(struct repmsg_recovery_ack);
int replicast_pack_recovery_ack(msgpack_p *p, struct repmsg_recovery_ack *msg);
int replicast_unpack_recovery_ack(msgpack_u *u, struct repmsg_recovery_ack *msg);


struct repmsg_payload_rcvd {
	struct replicast_datagram_hdr hdr;
	uint16_t ngcount;
	uint128_t vdevid;
	int fddelta;
	uint64_t put_delta;
};

REPMSG_SIZEOF_CHECK(struct repmsg_payload_rcvd);
int replicast_pack_payload_rcvd(msgpack_p *p, struct repmsg_payload_rcvd *msg);
int replicast_unpack_payload_rcvd(msgpack_u *u, struct repmsg_payload_rcvd *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_server_list_get {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t parent_serverid;
	uint32_t maximum_immediate_content_size;
	uint32_t maximum_number_of_delegated_gets;
	uint32_t reception_window;
	uint128_t sender_serverid;
	uint128_t sender_recv_addr;
	uint16_t sender_recv_port;
	uint32_t sender_flags;
#define	SLG_SENDER_SERVER	0x01
#define SLG_SENDER_DEBUG	0x02
#define	SLG_SENDER_GETCHECKPOINT	0x04
	uint32_t nr_vdevs;
	void *vdevs;
	uint16_t zone;
};

REPMSG_SIZEOF_CHECK(struct repmsg_server_list_get);
int replicast_pack_server_list_get(msgpack_p *p,
	struct repmsg_server_list_get *msg);
int replicast_unpack_server_list_get(msgpack_u *u,
	struct repmsg_server_list_get *msg);

struct repmsg_server_list_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint16_t mcbase_port;
	uint128_t mcbase_ip6addr;
	uint128_t parent_serverid;
	uint32_t checkpoint_numdevices;
	uint8_t ckpread;
	uint32_t nr_members;
	void *members;
	// serialized array follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_server_list_response);
int replicast_pack_server_list_response(msgpack_p *p,
	struct repmsg_server_list_response *msg);
int replicast_unpack_server_list_response(msgpack_u *u,
	struct repmsg_server_list_response *msg);

void replicast_free_repnodelist(struct cl_node *node, int numnodes);
void replicast_free_repvdevlist(struct cl_vdev *vdev, int numvdevs);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_named_chunk_get {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	struct replicast_object_name object_name;
	uint32_t maximum_immediate_content_size;
	uint32_t maximum_number_of_delegated_gets;
	uint32_t reception_window;
	uint128_t receive_tenant_addr;
	uint16_t receive_tenant_port;
	uint64_t genid_delta;
	uint64_t select_time_avg;
	uint64_t avg_put_latency;
	uint64_t avg_get_latency;
	uint64_t put_iops;
	uint64_t get_iops;
	uint64_t put_bw;
	uint64_t get_bw;
	uint512_t svcinfo;
};
REPMSG_SIZEOF_CHECK(struct repmsg_named_chunk_get);
int replicast_pack_named_chunk_get(msgpack_p *p,
	struct repmsg_named_chunk_get *msg);
int replicast_unpack_named_chunk_get(msgpack_u *u,
	struct repmsg_named_chunk_get *msg);

struct repmsg_named_chunk_get_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t vdevid;
	uint512_t content_hash_id;
	struct replicast_object_name object_name;
	uint32_t delivery_rate;
	uint32_t content_length;
	uint32_t immediate_content_length;
	struct replicast_rendezvous_proposal rendezvous_proposal;
	uint16_t ngcount;
	int fddelta;
	// immediate content follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_named_chunk_get_response);
int replicast_pack_named_chunk_get_response(msgpack_p *p,
	struct repmsg_named_chunk_get_response *msg);
int replicast_unpack_named_chunk_get_response(msgpack_u *u,
	struct repmsg_named_chunk_get_response *msg);

struct repmsg_unnamed_chunk_get_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t vdevid;
	uint512_t content_hash_id;
	uint32_t delivery_rate;
	uint32_t content_length;
	uint32_t immediate_content_length;
	uint16_t ngcount;
	uint8_t is_gwcache;
	struct replicast_rendezvous_proposal rendezvous_proposal;
	// immediate content follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_unnamed_chunk_get_response);
int replicast_pack_unnamed_chunk_get_response(msgpack_p *p,
	struct repmsg_unnamed_chunk_get_response *msg);
int replicast_unpack_unnamed_chunk_get_response(msgpack_u *u,
	struct repmsg_unnamed_chunk_get_response *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_unnamed_chunk_get {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t content_hash_id;
	uint32_t maximum_immediate_content_size;
	uint32_t reception_window;
	struct replicast_object_name object_name;
	uint128_t receive_tenant_addr;
	uint16_t receive_tenant_port;
	uint64_t genid_delta;
	uint64_t select_time_avg;
	uint64_t chunk_offset;	/* For Gateway Cache */
};
REPMSG_SIZEOF_CHECK(struct repmsg_unnamed_chunk_get);
int replicast_pack_unnamed_chunk_get(msgpack_p *p,
	struct repmsg_unnamed_chunk_get *msg);
int replicast_unpack_unnamed_chunk_get(msgpack_u *u,
	struct repmsg_unnamed_chunk_get *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_res_get {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	struct replicast_object_name object_name;
	uint128_t tgt_vdevid;
	uint16_t res_maj_id;
	uint16_t res_min_id;
	uint32_t immediate_content_length;
};
REPMSG_SIZEOF_CHECK(struct repmsg_res_get);
int replicast_pack_resget(msgpack_p *p, struct repmsg_res_get *msg);
int replicast_unpack_resget(msgpack_u *u, struct repmsg_res_get *msg);

struct repmsg_res_get_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	struct replicast_object_name object_name;
	uint16_t res_maj_id;
	uint16_t res_min_id;
	uint32_t immediate_content_length;
	// immediate content follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_res_get_response);
int replicast_pack_resget_response(msgpack_p *p,
	struct repmsg_res_get_response *msg);
int replicast_unpack_resget_response(msgpack_u *u,
	struct repmsg_res_get_response *msg);

struct repmsg_named_chunk_put_proposal {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t content_hash_id;
	struct replicast_object_name object_name;
	uint32_t content_length;
	uint32_t immediate_content_length;
	uint32_t override_content_length;
	uint64_t genid_delta;
	uint64_t select_time_avg;
	uint8_t ec_algorithm;
	uint8_t ec_width;
	uint8_t ec_parity;
	uint8_t ec_domain;
};

REPMSG_SIZEOF_CHECK(struct repmsg_named_chunk_put_proposal);
int replicast_pack_named_chunk_put_proposal(msgpack_p *p,
	struct repmsg_named_chunk_put_proposal *msg);
int replicast_unpack_named_chunk_put_proposal(msgpack_u *u,
	struct repmsg_named_chunk_put_proposal *msg);

struct repmsg_unnamed_chunk_put_proposal {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t content_hash_id;
	struct replicast_object_name object_name;
	uint32_t content_length;
	uint32_t immediate_content_length;
	uint32_t reserved;
	uint64_t genid_delta;
	uint64_t select_time_avg;
	uint128_t vdev;
};
REPMSG_SIZEOF_CHECK(struct repmsg_unnamed_chunk_put_proposal);
int replicast_pack_unnamed_chunk_put_proposal(msgpack_p *p,
	struct repmsg_unnamed_chunk_put_proposal *msg);
int replicast_unpack_unnamed_chunk_put_proposal(msgpack_u *u,
	struct repmsg_unnamed_chunk_put_proposal *msg);

struct repmsg_named_payload_ack {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t content_hash_id;
	uint128_t vdevid;
	struct replicast_object_name object_name;
};
REPMSG_SIZEOF_CHECK(struct repmsg_named_payload_ack);
int replicast_pack_named_payload_ack(msgpack_p *p,
	struct repmsg_named_payload_ack *msg);
int replicast_unpack_named_payload_ack(msgpack_u *u,
	struct repmsg_named_payload_ack *msg);

struct repmsg_unnamed_payload_ack {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t content_hash_id;
	uint128_t vdevid;
};
REPMSG_SIZEOF_CHECK(struct repmsg_unnamed_payload_ack);
int replicast_pack_unnamed_payload_ack(msgpack_p *p,
	struct repmsg_unnamed_payload_ack *msg);
int replicast_unpack_unnamed_payload_ack(msgpack_u *u,
	struct repmsg_unnamed_payload_ack *msg);

struct repmsg_rendezvous_transfer {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t group_members[REPLICAST_REPLICATION_COUNT_MAX];
	uint32_t delivery_rate;
	uint512_t content_hash_id;
	uint32_t content_length;
	// remaining content not included in the original put proposal follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_rendezvous_transfer);
int replicast_pack_rendezvous_transfer(msgpack_p *p,
	struct repmsg_rendezvous_transfer *msg);
int replicast_unpack_rendezvous_transfer(msgpack_u *u,
	struct repmsg_rendezvous_transfer *msg);

struct repmsg_rendezvous_ack {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t rendezvous_group;
	uint128_t group_members[REPLICAST_REPLICATION_COUNT_MAX];
	uint512_t content_hash_id;
	uint32_t join_delay;
};
REPMSG_SIZEOF_CHECK(struct repmsg_rendezvous_ack);
int replicast_pack_rendezvous_ack(msgpack_p *p,
	struct repmsg_rendezvous_ack *msg);
int replicast_unpack_rendezvous_ack(msgpack_u *u,
	struct repmsg_rendezvous_ack *msg);

struct repmsg_rendezvous_nack {
	struct replicast_datagram_hdr hdr;
	uint512_t content_hash_id;
};
REPMSG_SIZEOF_CHECK(struct repmsg_rendezvous_nack);
int replicast_pack_rendezvous_nack(msgpack_p *p,
	struct repmsg_rendezvous_nack *msg);
int replicast_unpack_rendezvous_nack(msgpack_u *u,
	struct repmsg_rendezvous_nack *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_accept_proposed_rendezvous {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint128_t vdevid;
	struct replicast_rendezvous_proposal rendezvous_proposal;
	uint32_t content_length;
	uint16_t ngcount;
	uint256_t dgram_idx;
};
REPMSG_SIZEOF_CHECK(struct repmsg_accept_proposed_rendezvous);
int replicast_pack_accept_proposed_rendezvous(msgpack_p *p,
	struct repmsg_accept_proposed_rendezvous *msg);
int replicast_unpack_accept_proposed_rendezvous(msgpack_u *u,
	struct repmsg_accept_proposed_rendezvous *msg);
int replicast_pack_rendezvous_proposal(msgpack_p *p,
	struct replicast_rendezvous_proposal *msg);
int replicast_unpack_rendezvous_proposal(msgpack_u *u,
	struct replicast_rendezvous_proposal *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_accept_content_already_stored {
	struct replicast_datagram_hdr hdr;
	uint128_t vdevid;
	uint16_t num_datagrams;
	uint16_t ngcount;
};
REPMSG_SIZEOF_CHECK(struct repmsg_accept_content_already_stored);
int replicast_pack_accept_content_already_stored(msgpack_p *p,
	struct repmsg_accept_content_already_stored *msg);
int replicast_unpack_accept_content_already_stored(msgpack_u *u,
	struct repmsg_accept_content_already_stored *msg);


/*
 * num_datagrams MUST be 1
 */
struct repmsg_persistency_ack {
	struct replicast_datagram_hdr hdr;
	uint128_t vdevid;
	uint16_t ngcount;
	int32_t error;
};
REPMSG_SIZEOF_CHECK(struct repmsg_persistency_ack);

int replicast_pack_persistency_ack(msgpack_p *p,
	struct repmsg_persistency_ack *msg);

int replicast_unpack_persistency_ack(msgpack_u *u,
	struct repmsg_persistency_ack *msg);

/*
 * num_datagrams MUST be 1
 */
struct repmsg_accept_not_now {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	struct timeval earliest_suggested_retry;
	uint16_t ngcount;
	int error;
	uint128_t vdevid;
};
REPMSG_SIZEOF_CHECK(struct repmsg_accept_not_now);
int replicast_pack_accept_not_now(msgpack_p *p,
	struct repmsg_accept_not_now *msg);
int replicast_unpack_accept_not_now(msgpack_u *u,
	struct repmsg_accept_not_now *msg);

struct repmsg_notification {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t  error;
	uint8_t  major_opcode;
	uint8_t  minor_opcode;
	uint64_t io_cookie;
};
int replicast_pack_notification(msgpack_p *p,
	struct repmsg_notification *msg);
int replicast_unpack_notification(msgpack_u *u,
	struct repmsg_notification *msg);

int replicast_pack_accept_not_now(msgpack_p *p,
	struct repmsg_accept_not_now *msg);
int replicast_unpack_accept_not_now(msgpack_u *u,
	struct repmsg_accept_not_now *msg);

struct repmsg_sg_lookup {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t chid;
	uint512_t nhid;
	uint32_t attr;
};

struct repmsg_sg_lookup_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint32_t present;
	uint64_t genid;
	int32_t status;
	uint512_t vmchid;
};

struct repmsg_sg_chunkput {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t chid;
	uint32_t attr;
};

struct repmsg_sg_chunkput_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
};

struct repmsg_sg_chunkget {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t chid;
	uint32_t attr;
};

struct repmsg_sg_chunkget_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
};

struct repmsg_sg_vmput {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint512_t phid;
	uint512_t nhid;
	uint512_t vmchid;
	uint64_t timestamp;
	uint64_t generation;
};
REPMSG_SIZEOF_CHECK(struct repmsg_sg_vmput);

struct repmsg_sg_vmput_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
};

struct repmsg_sg_ssput {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint32_t magic;
};

struct repmsg_sg_ssput_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
};

struct repmsg_sg_expunge {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint32_t magic;
};

struct repmsg_sg_expunge_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
};

struct repmsg_sg_dynfetch {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint8_t version;
};

struct repmsg_sg_dynfetch_resp {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int64_t status;
};

struct repmsg_sg_ping_pong {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	uint32_t attr;
	uint32_t message_size;
	void *message;
	// data array follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_sg_ping_pong);

struct repmsg_sg_ping_pong_response {
	struct replicast_datagram_hdr hdr;
	uint16_t num_datagrams;
	int32_t status;
	uint32_t message_size;
	void *message;
	// data array follows
};
REPMSG_SIZEOF_CHECK(struct repmsg_sg_ping_pong_response);

int replicast_pack_sg_ping_pong(msgpack_p *p, struct repmsg_sg_ping_pong *msg);
int replicast_unpack_sg_ping_pong(msgpack_u *u, struct repmsg_sg_ping_pong *msg);

int replicast_pack_sg_ping_pong_response(msgpack_p *p, struct repmsg_sg_ping_pong_response *msg);
int replicast_unpack_sg_ping_pong_response(msgpack_u *u, struct repmsg_sg_ping_pong_response *msg);

int replicast_pack_sg_expunge(msgpack_p *p, struct repmsg_sg_expunge *msg);
int replicast_unpack_sg_expunge(msgpack_u *u, struct repmsg_sg_expunge *msg);

int replicast_pack_sg_expunge_response(msgpack_p *p, struct repmsg_sg_expunge_response *msg);
int replicast_unpack_sg_expunge_response(msgpack_u *u, struct repmsg_sg_expunge_response *msg);

int replicast_pack_sg_dynfetch(msgpack_p *p, struct repmsg_sg_dynfetch* msg);
int replicast_unpack_sg_dynfetch(msgpack_u *u, struct repmsg_sg_dynfetch* msg);

int replicast_pack_sg_dynfetch_response(msgpack_p *p, struct repmsg_sg_dynfetch_resp* msg);
int replicast_unpack_sg_dynfetch_response(msgpack_u *u, struct repmsg_sg_dynfetch_resp* msg);


/*
 * Common version manifest metadata
 */
struct vmmetadata {
	char *cid;
	char *tid;
	char *bid;
	char *oid;
	size_t cid_size;
	size_t tid_size;
	size_t bid_size;
	size_t oid_size;
	uint512_t nhid;			/* name hash id */
	uint512_t chid;			/* cluster hash id */
	uint512_t phid;			/* parent hash id */
	uint512_t thid;			/* tenant hash id */
	uint512_t bhid;			/* bucket hash id */
	uint512_t ohid;			/* object hash id */
	uint128_t uvid_src_guid;
	uint64_t logical_size;
	uint64_t prev_logical_size;
	uint64_t object_count;
	uint64_t estimated_used;
	uint32_t uvid_src_cookie;
	uint64_t uvid_timestamp;
	uint64_t txid_generation;
	uint64_t creation_time;
	uint16_t inline_data_flags;
	uint8_t object_deleted;
	uint8_t replication_count;
	uint8_t sync_put;
	uint8_t select_policy;
	uint8_t hash_type;
	uint8_t compress_type;
	uint16_t number_of_versions;
	uint32_t chunkmap_chunk_size;
	uint8_t chunkmap_fixed_depth;
	uint8_t failure_domain;
	uint16_t chunkmap_fixed_width;
	uint16_t chunkmap_btree_order;
	uint8_t chunkmap_btree_marker;
	uint16_t track_statistics;
	uint32_t iops_rate_lim;
	uint8_t ec_enabled;
	uint32_t ec_data_mode;
	uint64_t ec_trg_policy;
	uint8_t file_object_transparency;
	uint64_t object_delete_after;
	char chunkmap_type[REPLICAST_CHUNKMAP_MAXLEN];
};
int replicast_unpack_vmmetadata(msgpack_u *u, struct vmmetadata *md);

/*
 * Version List Entry
 */
struct vlentry {
	uint64_t uvid_timestamp;
	uint128_t uvid_src_guid;
	uint32_t uvid_src_cookie;
	uint64_t generation;
	uint512_t content_hash_id;
	uint64_t logical_size;
	uint8_t object_deleted;
	uint32_t vm_packed_length;
};
int replicast_pack_vlentry(msgpack_p *p, struct vlentry *ent);
int replicast_unpack_vlentry(msgpack_u *u, struct vlentry *ent);

/*
 * ACL List Entry
 */
struct aclentry {
	uint8_t acl_type;
	uint64_t permissions;
};
int replicast_pack_aclentry(msgpack_p *p, struct aclentry *ent);
int replicast_unpack_aclentry(msgpack_u *u, struct aclentry *ent);

enum ref_type {
	RT_REF_TYPE_NORMAL = 1,
	RT_REF_TYPE_MANIFEST,
	RT_REF_TYPE_ZEROBLOCK,
	RT_REF_TYPE_INLINE_PAYLOAD,	/* content_hash_id is NULL */
	RT_REF_TYPE_INLINE_VERSION,	/* content_hash_id points to VM */
	RT_REF_TYPE_INLINE_MANIFEST	/* content_hash_id points to CM */
};

/*
 * Chunk Reference List Entry
 */
struct refentry {

/*
 * ref_attr organized in this:
 *
 *	[12:15] - encryption type (WEAK, NSA, etc..)
 *	[8:11] - hash type (BLAKE2B, SHA512, etc..)
 *	[7:4] - compression type (LZ4, SNAPY, etc..)
 *	[3:0] - reference type (NORMAL, MANIFEST, etc..)
 */

#define RT_REF_TYPE(_re) ((_re)->ref_attr & 0xF)
#define RT_REF_TYPE_SET(_re, _type) \
	(_re)->ref_attr = (((_re)->ref_attr & 0xFFF0) | (_type))

#define RT_REF_COMPRESS_TYPE(_re) (((_re)->ref_attr >> 4) & 0xF)
#define RT_REF_COMPRESS_TYPE_SET(_re, _compress_type) \
	(_re)->ref_attr = (_compress_type) << 4 | ((_re)->ref_attr & 0xFF0F)

#define RT_REF_HASH_TYPE(_re) (((_re)->ref_attr >> 8) & 0xF)
#define RT_REF_HASH_TYPE_SET(_re, _hash_type) \
	(_re)->ref_attr = (_hash_type) << 8 | ((_re)->ref_attr & 0xF0FF)

#define RT_REF_ENCRYPT_TYPE(_re) ((_re)->ref_attr >> 12)
#define RT_REF_ENCRYPT_TYPE_SET(_re, _encryption_type) \
	(_re)->ref_attr = (_encryption_type) << 12 | ((_re)->ref_attr & 0x0FFF)

#define RT_REF_TYPE_INLINE(ent) ( \
    RT_REF_TYPE(ent) == RT_REF_TYPE_INLINE_PAYLOAD || \
    RT_REF_TYPE(ent) == RT_REF_TYPE_INLINE_MANIFEST || \
    RT_REF_TYPE(ent) == RT_REF_TYPE_INLINE_VERSION)

/*
 * NB: the following macro has to be identical to
 * BT_REF_MOD and BT_REF_LEAF defined in btreecom.h
 */
#define RT_REF_MOD(_re) (((_re)->map_attr & 0x40) >> 6)
#define RT_REF_MOD_SET(_re, _mod) \
	(_re)->map_attr = (((_re)->map_attr & (~0x40)) | _mod << 6)

#define RT_REF_LEAF(_re) (((_re)->map_attr & 0x80) >> 7)
#define RT_REF_LEAF_SET(_re, _leaf) \
	(_re)->map_attr = (((_re)->map_attr & 0x7F) | _leaf << 7)

	uint16_t ref_attr;
	uint8_t map_attr;
	uint64_t offset;
	uint64_t length;
	uint64_t compressed_length;
	uint512_t content_hash_id;
	uint512_t name_hash_id;
	uint8_t *data;
	// inline content follows
};
int replicast_pack_refentry(msgpack_p *p, struct refentry *ent);
int replicast_unpack_refentry(msgpack_u *u, struct refentry *ent);

int replicast_pack_refentry_dfetch(msgpack_p *p, struct refentry *ent);
int replicast_unpack_refentry_dfetch(msgpack_u *u, struct refentry *ent);

void refentry_dump(Logger l, char *debug_desc, struct refentry *ent);

struct replicast;
struct repwqe;

/* Forward declaration */
typedef struct rt_tcp_s rt_tcp_t;
typedef void (*rt_connect_cb)(void *, int);

/*
 * Replicast messaging context. Organization:
 *
 *	CTX ==(1:N)==> WQE ==(1:1)==> REQ
 *
 *	CTX	Working context, holds 1+ WQEs
 *	WQE	Working Queue Entry/Element, holds pointer to REQ
 *	REQ	Protocol specific request
 */
struct repctx {
	QUEUE wq;
	struct state *state;
	uint32_t sequence_cnt;
	uint32_t sub_sequence_cnt;
	uint64_t txcookie;
	uint64_t ctxid;
	struct replicast *robj;
	int sender;
	int dropped;

	/* filled in on receive */
	struct repwqe *wqe_in;
	struct state state_in;
	uint32_t *stat_cnt;
        uint64_t attributes;
	rt_tcp_t *tcp_handle;
	int opcode_in;
	UT_hash_handle hh;
};

/*
 * Replicast work queue entry (WQE). Holds pointer to the outstanding
 * request. WQE will be matched against context WQ i.e. to associate
 * UDP dgram with. Matched WQE will be filled in with validated protocol
 * header and associated buffer(s) information
 */
struct repwqe {
	QUEUE item;
	QUEUE recv_item;
	QUEUE recv_wq;
	struct replicast_transaction_id id, orig_id;
	void *data;
	struct repctx *ctx;
	uint32_t sub_sequence_cnt;

	/* filled in on receive */
	struct repmsg_generic *msg;
	msgpack_u *u;
	ssize_t nread;
};
static inline void *
repwqe_payload(struct repwqe *wqe)
{
	return (char *)wqe->u->buffer + msgpack_unpack_getpos(wqe->u);
}

static inline uint32_t
repwqe_payload_len(struct repwqe *wqe)
{
	return (wqe->nread - msgpack_unpack_getpos(wqe->u));
}

#define VBUF_STAT_TRUE  1
#define VBUF_STAT_FALSE 0

struct repvbuf {
	uint64_t		total;		/* total initialized for this port */
	volatile uint64_t	queued;		/* currently queued */
	volatile uint64_t	reserved;	/* currently allocated */
};

typedef struct ifvbuf_ {
	int if_count;
	struct repvbuf pvbuf[REPLICAST_SRV_INTERFACES_MAX];
} ifvbuf_t;


typedef int (*repstate_init_func_t)(struct replicast *robj,
    struct repctx *ctx, struct state *state);

typedef int (*replicast_mcproxy_func_t)(struct replicast *robj, uint16_t fhrow,
    const uv_buf_t buf, ssize_t nread, char *sender);

struct replicast_stats {
	uint32_t namedget_active;		/* Currently in flight NG */
	uint32_t namedput_active;		/* Currently in flight NP */
	uint32_t unnamedget_active;		/* Currently in flight UG */
	uint32_t unnamedput_active;		/* Currently in flight UP */
	uint32_t cacheget_active;		/* Currently in flight CG */
	uint32_t ngrequest_purge_active_srv;	/* Currently in flight NGRP */
	uint32_t ngrequest_purge_active;	/* Currently in flight NGRP */
	uint32_t ngrequest_send_active;		/* Currently in flight NGRS */
	uint32_t ngrequest_count_active;	/* Currently in flight NGRC */
	uint32_t ngrequest_locate_active;	/* Currently in flight NGRC */
	uint32_t ngrequest_active;		/* Currently in flight NGR */
	uint32_t recovery_active;		/* Currently in flight recovery*/
	uint32_t rowevac_active;		/* Currently in flight row evacuation requests */
	uint32_t opp_status_active;		/* Currently in flight parity protection status*/
	uint32_t resget_active;		/* Currently in flight parity protection status*/
	uint64_t last_send_time;        /* The last successful send time */
	uint64_t last_receive_time;      /* The last successful receive time */
};

struct replicast_mcproxy_call {
	QUEUE item;
	void (*method)(struct replicast_mcproxy_call *c);
	void *args[8];
	void *done;
	int rc;
};

void replicast_mcproxy_recv(struct replicast_mcproxy_call *c);

#define REPLICAST_NAME_MAXSIZE	128
struct replicast {
	struct repctx *ctxq;		/* sender matching context */
	struct repctx *ctxq_recv;	/* receiver matching context */
	char name[REPLICAST_NAME_MAXSIZE];
	uv_loop_t *loop;
	unsigned long loop_thrid;	/* context specific loop thread id */
	int mc_ttl;
	uint16_t mc_recv_port;
	hashtable_t *mc_recv_sockets;	/* map mcgrp to uv_udp_t sockets */
	hashtable_t *unix_socket_hash;
	uv_connect_t unixsock_req;
	uv_pipe_t unixsock;
	char *listen_unixsock;
	uv_udp_t recv_socket;
	uv_udp_t send_socket;
	uv_tcp_t recv_tcp_socket;
	rt_tcp_t    *tcp_handles;
	uv_async_t mcproxy_async;	/* trigger async mcproxy call */
	uv_mutex_t mcproxy_mutex;	/* to protect async mcproxy call arguments */
	QUEUE mcproxy_queue;		/* incoming queue of mcproxy calls */
	replicast_mcproxy_func_t mcproxy_func;
	void *priv_data;
	struct sockaddr_in6 recv_addr;
	struct sockaddr_in6 msg_origin_tcpaddr; /* Used in message header */
	struct sockaddr_in6 msg_origin_udpaddr; /* Used in message header */
	repstate_init_func_t repstate_init_func[RT_END];
	uint32_t sequence_cnt;
	uint16_t udp_recv_port;	/* UDP listen port */
	uint16_t tcp_recv_port;	/*
				 * TCP listen port (usually has same value as
				 * udp_recv_port)
				 */
	void *server_ctx; /* set to the server context only for a server */
	void *client_ctx; /* set to the client context for a client */
	void *dev_ctx; /* set to the device context by a cache device */
	struct replicast_stats stats;
	struct repvbuf rvbuf;
	struct sockaddr_in server_addr;
	int ipv4;
	QUEUE rtsock_queue;
};

typedef void (*replicast_send_cb)(void *data, int status, int ctx_valid);
typedef void (*replicast_send_free_cb)(void *data, int status, int ctx_valid);

/*
 * Replicast Object API
 */
struct replicast *replicast_init(const char *name, uv_loop_t *loop,
    const char *listen_addr, const uint16_t listen_port, const char *listen_unixsock,
    const char *msg_origin_addr, const char *mc_addr,
    const uint16_t mc_port, const int mc_ttl, void *data);
int replicast_destroy(struct replicast *robj);
void replicast_finish_destroy(struct replicast *robj);
int replicast_join(struct replicast *robj, const char *mcgrp,
    uint32_t if_index);
int replicast_leave(struct replicast *robj, const char *mcgrp,
    uint32_t if_index);
int replicast_tcp_connect(struct replicast *robj, struct sockaddr_in6 *to_addr,
    rt_connect_cb cb, void *cb_data);
int replicast_send(struct replicast *robj, struct repctx *ctx,
	enum replicast_opcode opcode, struct repmsg_generic *msg,
	struct repmsg_generic *origmsg, const uv_buf_t bufs[], unsigned int nbufs,
	struct sockaddr_in6 *send_addr, replicast_send_cb cb, void *data,
	uint256_t *dgram_idx);
int replicast_udp_send(struct replicast *robj, struct repctx *ctx,
    enum replicast_opcode opcode, struct repmsg_generic *msg,
    struct repmsg_generic *omsg, const uv_buf_t bufs[],
    unsigned int nbufs, struct sockaddr_in6 *to_addr, int to_addr_arrlen,
    replicast_send_cb cb, replicast_send_free_cb free_cb,
    void *data, uint256_t *dgram_idx, uint16_t fhrow);
void replicast_state_init(struct replicast *robj, enum replicast_opcode opcode,
    repstate_init_func_t func);
void replicast_mcproxy_init(struct replicast *robj, replicast_mcproxy_func_t func);

int replicast_tcp_socket_init(uv_tcp_t *handle, uv_os_sock_t *sock,
    uv_loop_t *loop, int domain);
void replicast_tcp_get_addr(rt_tcp_t *rtsock, char *src, char *dst,
    int *src_port, int *dst_port, int *scopeid);
uv_buf_t alloc_buffer(uv_handle_t *UNUSED(handle), size_t suggested_size);

/*
 * Replicast Context API
 */
static inline struct repwqe *
repctx_wqe_init(struct repctx *ctx, struct replicast_transaction_id *id,
    struct replicast_transaction_id *orig_id, void *data)
{
	struct repwqe *wqe = je_calloc(1, sizeof (*wqe));
	if (!wqe)
		return NULL;
	QUEUE_INIT(&wqe->item);
	QUEUE_INIT(&wqe->recv_item);
	QUEUE_INIT(&wqe->recv_wq);
	wqe->id = *id;
	if (orig_id)
		wqe->orig_id = *orig_id;
	wqe->data = data;
	wqe->sub_sequence_cnt = ctx->sub_sequence_cnt++;
	QUEUE_INSERT_TAIL(&ctx->wq, &wqe->item);
	return wqe;
}

static inline struct repwqe *
repctx_wqe_recv(struct repctx *ctx, struct replicast_transaction_id *id,
    struct replicast_transaction_id *orig_id, void *data)
{
	struct repwqe *wqe = je_calloc(1, sizeof (*wqe));
	if (!wqe)
		return NULL;
	QUEUE_INIT(&wqe->item);
	QUEUE_INIT(&wqe->recv_item);
	QUEUE_INIT(&wqe->recv_wq);
	wqe->id = *id;
	if (orig_id)
		wqe->orig_id = *orig_id;
	wqe->data = data;
	wqe->sub_sequence_cnt = ctx->sub_sequence_cnt++;
	return wqe;
}

static inline void
repctx_wqe_destroy(struct repwqe *wqe)
{
	if (wqe->u) {
		if (wqe->u->buffer) {
			je_free(wqe->u->buffer);
			wqe->u->buffer = NULL;
		}
		msgpack_unpack_free(wqe->u);
		wqe->u = NULL;
	}
	if (wqe->ctx && wqe->ctx->wqe_in == wqe)
		wqe->ctx->wqe_in = NULL;
	if (!QUEUE_EMPTY(&wqe->recv_item))
		QUEUE_REMOVE(&wqe->recv_item);
	QUEUE_REMOVE(&wqe->item);
	je_free(wqe);
}

static inline struct repctx *
repctx_init(struct replicast *robj)
{
	nassert(robj->loop_thrid == uv_thread_self());
	struct repctx *ctx = je_calloc(1, sizeof (*ctx));
	if (!ctx)
		return NULL;
	QUEUE_INIT(&ctx->wq);
	ctx->sender = 1;
	ctx->robj = robj;
	ctx->txcookie = uv_hrtime();
	ctx->sequence_cnt = robj->sequence_cnt++;
	ctx->sub_sequence_cnt = 1;
	ctx->ctxid = ctx->sequence_cnt ^ ctx->txcookie;
	HASH_ADD_INT64(robj->ctxq, ctxid, ctx);
	return ctx;
}

static inline struct repctx *
repctx_recv(struct replicast *robj, struct replicast_transaction_id *msg_id)
{
	nassert(robj->loop_thrid == uv_thread_self());
	struct repctx *ctx = je_calloc(1, sizeof (*ctx));
	if (!ctx)
		return NULL;
	QUEUE_INIT(&ctx->wq);
	ctx->robj = robj;
	ctx->txcookie = uv_hrtime();
	ctx->sequence_cnt = robj->sequence_cnt++;
	ctx->sub_sequence_cnt = 1;
	ctx->ctxid = msg_id->sequence_num ^ msg_id->txcookie;
	HASH_ADD_INT64(robj->ctxq_recv, ctxid, ctx);
	return ctx;
}

static inline int
repctx_is_ctx_valid(struct replicast *robj, struct repctx *ctx)
{
	nassert(robj->loop_thrid == uv_thread_self());
	struct repctx *ctx_next = NULL;
	uint64_t ctxid = ctx->sequence_cnt ^ ctx->txcookie;
	HASH_FIND_INT64(robj->ctxq, &ctxid, ctx_next);
	return ctx_next != NULL;
}

static inline void
repctx_drop(struct repctx *ctx)
{
	nassert(ctx->robj->loop_thrid == uv_thread_self());
	if (ctx->robj->ctxq_recv && !ctx->sender && !ctx->dropped) {
		HASH_DEL(ctx->robj->ctxq_recv, ctx);
		ctx->dropped = 1;
	}
	if (ctx->robj->ctxq && ctx->sender && !ctx->dropped) {
		HASH_DEL(ctx->robj->ctxq, ctx);
		ctx->dropped = 1;
	}
}

static inline void
repctx_reset(struct repctx *ctx)
{
	repctx_drop(ctx);
	ctx->txcookie = uv_hrtime();
	ctx->ctxid = ctx->sequence_cnt ^ ctx->txcookie;
	ctx->dropped = 0;
	HASH_ADD_INT64(ctx->robj->ctxq, ctxid, ctx);
}

static inline void
repctx_wqe_reset(struct repctx *ctx)
{
	while (!QUEUE_EMPTY(&ctx->wq)) {
		QUEUE *s = QUEUE_HEAD(&ctx->wq);
		struct repwqe *wqe_sent = QUEUE_DATA(s, struct repwqe, item);

		while (!QUEUE_EMPTY(&wqe_sent->recv_wq)) {
			QUEUE *r = QUEUE_HEAD(&wqe_sent->recv_wq);
			struct repwqe *wqe_recv =
					QUEUE_DATA(r, struct repwqe, recv_item);
			repctx_wqe_destroy(wqe_recv);
		}
		repctx_wqe_destroy(wqe_sent);
	}
}

static inline void
repctx_remove(struct repctx *ctx)
{
	repctx_wqe_reset(ctx);
	repctx_drop(ctx);
}

static inline void
repctx_destroy(struct repctx *ctx)
{
	repctx_remove(ctx);
	je_free(ctx);
}

#define REP_IS_4OVER6(a6) ( \
    (a6)->sin6_addr.s6_addr32[0] == 0 && \
    (a6)->sin6_addr.s6_addr32[1] == 0 && \
    (a6)->sin6_addr.s6_addr32[2] == 0xFFFFFFFF)

static inline void
replicast_ip4_encap(struct sockaddr_in *a4, struct sockaddr_in6 *a6)
{
	a6->sin6_addr.s6_addr32[0] = 0;
	a6->sin6_addr.s6_addr32[1] = 0;
	a6->sin6_addr.s6_addr32[2] = 0xFFFFFFFF;
	a6->sin6_addr.s6_addr32[3] = ntohl(a4->sin_addr.s_addr);
	a6->sin6_family = AF_INET6;
}

static inline void
replicast_ip4_decap(struct sockaddr_in6 *a6, struct sockaddr_in *a4)
{
	a4->sin_addr.s_addr = htonl(a6->sin6_addr.s6_addr32[3]);
	a4->sin_family = AF_INET;
}

int
replicast_unpack_datagram_hdr(msgpack_u *u, struct replicast_datagram_hdr *msg);

/*
 * Object accessors
 */
int replicast_get_refs(rtbuf_t *in, rtbuf_t **out, int keep_mod_bit);
int replicast_unpack_cm_refs(rtbuf_t *in, rtbuf_t **out, int keep_mod_bit);
int replicast_get_metadata(rtbuf_t *in, struct vmmetadata *out);
int replicast_get_custom_metadata(rtbuf_t *in, rtbuf_t **out);
int replicast_object_cloud_provider_metadata(rtbuf_t *in, char **provider_type,
    char **provider_origin, char **user_key, char **provider_region);
int replicast_object_metadata(rtbuf_t *in, char **etag, char **content_type, uint64_t *multipart_size, char **owner, char **srcip);
int replicast_object_metadata_field(rtbuf_t *in, char *name, uint64_t *res);
int replicast_get_acls(rtbuf_t *in, rtbuf_t **out);

/*
 * Interfaces to create listener and multicast join.
 */
int replicast_start_listener(uv_udp_t *handle, struct replicast *robj,
			     const char *listen_addr,
			     const uint16_t listen_port, int if_index,
			     const int ttl);
int replicast_socket_join(uv_udp_t *socket, const char *mcgrp, uint32_t if_index,
    struct sockaddr_in6 *recv_addr);
int replicast_socket_leave(uv_udp_t *socket, const char *mcgrp,uint32_t if_index,
    struct sockaddr_in6 *recv_addr);
int replicast_getaddrinfo(const char *addr, struct sockaddr_in6 *inaddr,
		      uint32_t flag);
void replicast_process_recv(struct replicast *robj, const uv_buf_t buf,
				ssize_t nread, char *sender, rt_tcp_t *tcp_handle, uv_pipe_t *peer_sock);
int replicast_join_throttle(void *data);
void replicast_join_cache_update(void *data, char *mcgrp, uint32_t if_index);
void replicast_join_cache_cleanup(void *data);

/*
 * vbuf allocations and frees
 */
void replicast_vbuf_init(struct repvbuf *vbuf, uint32_t if_speed);
void replicast_vbuf_link_update(struct repvbuf *vbuf, uint32_t if_speed);
int replicast_alloc_vbuf(struct repvbuf *vbuf, uint64_t req_len, int stat);
void replicast_free_vbuf(struct repvbuf *vbuf, uint64_t req_len);
int replicast_alloc_vbuf_queued(struct repvbuf *vbuf, uint64_t req_len);
void replicast_free_vbuf_queued(struct repvbuf *vbuf, uint64_t req_len);

uint64_t replicast_get_avail_vbuf(struct repvbuf *vbuf);
uint64_t replicast_get_reserved_vbuf(struct repvbuf *vbuf);
int replicast_check_avail_vbuf(struct repvbuf *vbuf, uint64_t req_len);

int replicast_pack_repnode(msgpack_p *p, struct cl_node *node);
int replicast_unpack_repnode(msgpack_u *u, struct cl_node **rnode);

int replicast_pack_uvbuf_nodes(struct cl_node *members, uint32_t nr_members,
    uv_buf_t *payload, rtbuf_t *checkpoint_payload);
int replicast_unpack_uvbuf_nodes(uv_buf_t *payload, uint32_t nr_members,
    struct cl_node **members, char *checkpoint, int checkpoint_len);

int replicast_uvbuf_integrate(uv_buf_t *buf, int nbufs, uv_buf_t *onebuf);
ifvbuf_t *replicast_ifvbuf_init(ifvbuf_t *ifvbuf, uint32_t if_speeds[],
    int if_count);

struct rt_bulk_list * replicast_unpack_bulk_list(msgpack_u *u);
msgpack_p * replicast_pack_bulk_list(struct rt_bulk_list *bl);

int replicast_pack_uvbuf(msgpack_p *p, uv_buf_t *ub);
int replicast_unpack_uvbuf(msgpack_u *u, uv_buf_t *ub);
int replicast_pack_rtbuf(msgpack_p *p, rtbuf_t *rb);
int replicast_unpack_rtbuf(msgpack_u *u, rtbuf_t **rbuf);

int replicast_pack_sg_lookup(msgpack_p *p, struct repmsg_sg_lookup *msg);
int replicast_unpack_sg_lookup(msgpack_u *u, struct repmsg_sg_lookup *msg);
int replicast_pack_sg_lookup_response(msgpack_p *p, struct repmsg_sg_lookup_response *msg);
int replicast_unpack_sg_lookup_response(msgpack_u *u, struct repmsg_sg_lookup_response *msg);

int replicast_pack_sg_chunkput(msgpack_p *p, struct repmsg_sg_chunkput *msg);
int replicast_unpack_sg_chunkput(msgpack_u *u, struct repmsg_sg_chunkput *msg);
int replicast_pack_sg_chunkput_response(msgpack_p *p, struct repmsg_sg_chunkput_response *msg);
int replicast_unpack_sg_chunkput_response(msgpack_u *u, struct repmsg_sg_chunkput_response *msg);

int replicast_pack_sg_vmput(msgpack_p *p, struct repmsg_sg_vmput *msg);
int replicast_unpack_sg_vmput(msgpack_u *u, struct repmsg_sg_vmput *msg);
int replicast_pack_sg_vmput_response(msgpack_p *p, struct repmsg_sg_vmput_response *msg);
int replicast_unpack_sg_vmput_response(msgpack_u *u, struct repmsg_sg_vmput_response *msg);

int replicast_pack_sg_ssput(msgpack_p *p, struct repmsg_sg_ssput *msg);
int replicast_unpack_sg_ssput(msgpack_u *u, struct repmsg_sg_ssput *msg);
int replicast_pack_sg_ssput_response(msgpack_p *p, struct repmsg_sg_ssput_response *msg);
int replicast_unpack_sg_ssput_response(msgpack_u *u, struct repmsg_sg_ssput_response *msg);

int replicast_pack_sg_chunkget(msgpack_p *p, struct repmsg_sg_chunkget *msg);
int replicast_unpack_sg_chunkget(msgpack_u *u, struct repmsg_sg_chunkget *msg);
int replicast_pack_sg_chunkget_response(msgpack_p *p, struct repmsg_sg_chunkget_response *msg);
int replicast_unpack_sg_chunkget_response(msgpack_u *u, struct repmsg_sg_chunkget_response *msg);

#ifdef	__cplusplus
}
#endif

#endif
