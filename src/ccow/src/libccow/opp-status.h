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
/*
 * (O)bject (P)arity (P)rotection Status request.
 */

#ifndef SRC_LIBCCOW_OPP_STATUS_H_
#define SRC_LIBCCOW_OPP_STATUS_H_

#ifdef	__cplusplus
extern "C" {
#endif

#define OPP_STATUS_MAX_RETRY			5
#define OPP_STATUS_TIMEOUT_MS			60000
#define OPP_STATUS_FLAG_VERIFY			(1<<0)
#define OPP_STATUS_FLAG_ERC			(1<<1)
#define OPP_STATUS_FLAG_CPAR			(1<<2) /*Consider also parity chunks */
#define OPP_STATUS_FLAG_LERR			(1<<3) /* Log errors */
#define OPP_STATUS_FLAG_LACKVBR			(1<<4) /* Log CHID if at least one replica doen't have a VBR*/
#define OPP_STATUS_FLAG_MISSVBR			(1<<5) /* Log CHID if neither of replicas have a VBR*/
#define OPP_STATUS_FLAG_NOPM			(1<<6) /* Log CHID of leaf manifest without PM*/

typedef struct opp_status {
	int	status; /* Operation status. 0 - done, an error otherwise */
	size_t  n_cpar; /* Number of parity chunks */
	size_t  n_cp; /* Number of payload chunks in the object */
	size_t	n_cm_zl; /* Number of zero-level CM the object has */
	size_t  n_cm_tl; /* Number of top-level chunk manifests */
	size_t  n_cm_zl_pp; /* number of parity protected zero-level CM */
	size_t  n_cm_zl_verified; /* number of verified ZL chunk manifests */
	size_t  n_cm_tl_verified; /* number of verified TL chunk manifests */
	size_t  n_cp_verified; /* Number of verified payload chunks */
	size_t  n_cpar_verified; /* Number of verified parity chunks */
	size_t  n_cm_zl_1vbr; /* number of ZL manifests that have at least 1 vbr */
	size_t  n_cm_tl_1vbr; /* number of TL verified that have at least 1 vbr */
	size_t  n_cp_1vbr; /* Number of payload chunks that have at least 1 vbr*/
	size_t  n_cm_zl_lost; /* Number of lost zero-level parity manifests */
	size_t  n_cm_tl_lost; /* Number of lost parity manifests */
	size_t  n_cp_lost; /* Number of lost chunk payloads */
	size_t  n_cpar_lost; /* Number of lost parity chunks */
	size_t  n_cm_zl_erc_err; /* number of verified ZL with wrong ERC */
	size_t  n_cm_tl_erc_err; /* number of verified TL with wrong ERC */
	uint128_t hostid; /* Information collected on this host */
	size_t n_vdevs; /* Number of vdevs on this host */
	uint64_t* vdevs_usage; /* Array of VDEVs disk usage, %*100 */
	int pp_algo; /* Parity protection algorithm number */
	int pp_data_number; /* Number of data chunks per parity set */
	int pp_parity_number; /* Number of parity chunks per a set */
	int pp_domain; /* Protection domain */
} opp_status_t;

int ccow_opp_satus_request(struct ccow *tc, const uint512_t* vmchid,
	const uint512_t* nhid, struct ccow_completion *c, int flags,
	opp_status_t* pp_status);

#ifdef	__cplusplus
}
#endif



#endif /* SRC_LIBCCOW_OPP_STATUS_H_ */
