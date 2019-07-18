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
#ifndef SRC_LIBCCOW_EC_COMMON_H_
#define SRC_LIBCCOW_EC_COMMON_H_

typedef enum {
        EC_DOMAIN_VDEV,
        EC_DOMAIN_HOST,
        EC_DOMAIN_ZONE,
        EC_DOMAIN_LAST
} ec_domain_t;

static char *ec_domain_name[] = {
	"EC_DOMAIN_VDEV",
	"EC_DOMAIN_HOST",
	"EC_DOMAIN_ZONE",
	"EC_DOMAIN_INVALID"
};

/**
 * Known codec IDs
 */
typedef enum {
	EC_CID_NONE = 0,
	EC_CID_FIRST = 1,
	EC_CID_XOR = EC_CID_FIRST,
	EC_CID_RS,
	EC_CID_RS_CAUCHY,
	EC_CID_TOTAL
} ec_codec_id;

static char *ec_codec_name[] = {
	"none",
	"xor1",
	"rs",
	"cauchy",
	"invalid"
};

/**
 * Encoding formats
 */

typedef enum {
	EC_FORMAT_D3P2 = (3 << 8) | 2,	/* 3 data -> 2 parity */
	EC_FORMAT_D4P2 = (4 << 8) | 2,	/* 4 data -> 2 parity */
	EC_FORMAT_D5P2 = (5 << 8) | 2,	/* 5 data -> 2 parity */
	EC_FORMAT_D6P2 = (6 << 8) | 2,	/* 6 data -> 2 parity */
	EC_FORMAT_D7P2 = (7 << 8) | 2,	/* 7 data -> 2 parity */
	EC_FORMAT_D8P2 = (8 << 8) | 2,	/* 8 data -> 2 parity */
	EC_FORMAT_D9P2 = (9 << 8) | 2,	/* 9 data -> 2 parity */
	EC_FORMAT_D10P2 = (10 << 8) | 2,/* 10 data -> 2 parity */
	EC_FORMAT_D2P1 = (2 << 8) | 1,  /* 2 data -> 1 parity */
	EC_FORMAT_D3P1 = (3 << 8) | 1,  /* 3 data -> 1 parity */
	EC_FORMAT_D4P1 = (4 << 8) | 1,  /* 4 data -> 1 parity */
	EC_FORMAT_D5P1 = (5 << 8) | 1,  /* 5 data -> 1 parity */
	EC_FORMAT_D6P1 = (6 << 8) | 1,  /* 6 data -> 1 parity */
	EC_FORMAT_D7P1 = (7 << 8) | 1,  /* 7 data -> 1 parity */
	EC_FORMAT_D8P1 = (8 << 8) | 1,  /* 8 data -> 1 parity */
	EC_FORMAT_D9P1 = (9 << 8) | 1,  /* 9 data -> 1 parity */
	EC_FORMAT_D10P1 = (10 << 8) | 1,  /* 10 data -> 1 parity */
	EC_FORMAT_D2P2 = (2 << 8) | 2, /* 2 data -> 2 parity */
	EC_FORMAT_D2P3 = (2 << 8) | 3, /* 2 data -> 3 parity */
	EC_FORMAT_D3P3 = (3 << 8) | 3, /* 3 data -> 3 parity */
	EC_FORMAT_D4P3 = (4 << 8) | 3, /* 4 data -> 3 parity */
	EC_FORMAT_D5P3 = (5 << 8) | 3, /* 5 data -> 3 parity */
	EC_FORMAT_D6P3 = (6 << 8) | 3, /* 6 data -> 3 parity */
	EC_FORMAT_D7P3 = (7 << 8) | 3, /* 7 data -> 3 parity */
	EC_FORMAT_D8P3 = (8 << 8) | 3, /* 8 data -> 3 parity */
	EC_FORMAT_D9P3 = (9 << 8) | 3, /* 9 data -> 3 parity */
	EC_FORMAT_D10P3 = (10 << 8) | 3, /* 10 data -> 3 parity */
} ec_codec_format;

#define CCOW_RECOVERY_RETRY_CNT 30
#define CCOW_RECOVERY_BUSY_CNT	100
#define CCOW_EC_CONSENSUS_TIMEOUT_MS	1000
#define CCOW_EC_RECOVERY_TIMEOUT_MS	10000
#define CCOW_EC_GET_RETRY_MAX		2

typedef enum  {
	MANIFEST_PROCESSING,
	MANIFEST_RECOVERY_BUSY,
	MANIFEST_RECOVERY_SUCCESS,
	MANIFEST_RECOVERY_PART,
	MANIFEST_RECOVERY_FAILED,
	MANIFEST_RECOVERY_UNENCODE_SUCCESS,
	SCRUBBER_DONE,
	ENCODING_DONE,
	SPACE_RECLAIM_DONE,
	ROW_EVAC_DONE,
	REPLICATION_DONE
} manifest_lock_status_t;

struct flexhash;
/**
 * EC mode at client's level is defined as a bitfield:
 *
 * bits[7..0] number of parity bits, min.1 ,max depends on a codec
 * bits[15..8] number of data bits, range depends on a codec
 * bits[19..16] codec ID, one from enum ec_codec_id. In fact, only 3 codecs
 * 		are supported in v2.x.
 *
 * Use ec_mode_check() for validation.
 */

#define FROM_CODECFMT(id, n, m) (n=((id) >> 8) & 0xFF, m = id & 0xFF)
#define TO_CODECFMT(n, m) ((n)<<8 | m)
#define GET_CODECID(mode) (((mode) >> 16) & 0x0f)
#define SET_CODECID(mode, cid) ((mode) = ((cid) << 16) | (mode))

static inline int
ec_mode_check(volatile struct flexhash* fh, ec_domain_t fd, uint32_t mode_id) {
	int n_data = 0, n_parity = 0;
	ec_codec_id cid = EC_CID_NONE;
	int fd_tgts_total = 0;

	assert(fh);
	FROM_CODECFMT(mode_id, n_data, n_parity);
	cid = (ec_codec_id)GET_CODECID(mode_id);
	/* Check if the mode ID isn't a garbage */
	if (!n_data || !n_parity || !cid || cid >= EC_CID_TOTAL) {
		return -EINVAL;
	}
#if 0
	/* Estimate number of targets and check if parity set fits into them */
	switch (fd) {
		case FD_SERVER:
			fd_tgts_total = fh->servercount;
			break;
		case FD_ZONE:
			fd_tgts_total= fh->zonecount;
			break;
		case FD_ANY_FIRST:
			fd_tgts_total = fh->numdevices;
			break;
		default:
			return -EFAULT;
	}

	if (n_data + n_parity > fd_tgts_total) {
		return -ERANGE;
	}
#endif
	/* TODO:
	 * Put EC codecs to a dedicated library, so both client and server
	 * can share it. Then we can check formats in an unified way using
	 * the codec abstraction layer.
	 */
	int err = 0;
	switch (cid) {
		case EC_CID_XOR:
			if (n_parity > 1 || n_data < 2 || n_data > 20)
				err = -ENOENT;
			break;

		case EC_CID_RS:
			if (n_data < 2 || n_data > 10 || n_parity > 3)
				err = -ENOENT;
			break;

		case EC_CID_RS_CAUCHY:
			if (n_data < 2 || n_data > 10 || n_parity > 3)
				err = -ENOENT;
			break;

		default:
			err = -ENOENT;
			break;
	}
	return err;
}

/**
 * EC triggering policy defines a condition which triggers the object encoding
 * process.
 *
 * It's stored in object's metadata as a 64-bits value whose meaning defined below:
 *
 * bits[3..0] - triggering policy type, defined in enum ec_trg_policy_t
 * bits[63..4] - triggering policy value.
 * For EC_TRG_POLICY_TIMEOUT the value is a timeout in seconds after which
 *	object is considered "cold" and can be safely encoded.
 *
 * TODO: add per-policy value description
 */
typedef enum {
	EC_TRG_POLICY_TIMEOUT, /* Trigger object encoding by timeout */
	EC_TRG_POLICY_MD, /* Trigger encoding by object metadata(size/type/etc)*/
	EC_TRG_POLICY_CONDITION, /* Trigger encoding by certain condition */
	EC_TRG_POLICY_LAST
} ec_trg_policy_t;

#define TO_TRG_POLICY(type, value) (((value) << 4 ) | (type & 0x0F))
#define GET_TRG_POLICY_TYPE(val) ((val) & 0x0F)
#define GET_TRG_POLICY_VALUE(val) ((ec_trg_policy_t)((val) >> 4))
#define EC_UNENCODE_AHEAD_DELAY	5*60

static inline int
ec_check_trg_policy(uint64_t value) {
	ec_trg_policy_t type = GET_TRG_POLICY_TYPE(value);
	if (type < 0 || type >= EC_TRG_POLICY_LAST)
		return -EINVAL;
	return 0;
}

#endif /* SRC_LIBCCOW_EC_COMMON_H_ */
