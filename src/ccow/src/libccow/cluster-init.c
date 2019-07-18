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
#include "ccowutil.h"
#include "ccow-impl.h"

static void
ccow_get_system_guid(char *guid)
{
	srand((uint32_t)get_timestamp_us());
	int t = 0;
	char *szTemp = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
	char *szHex = "0123456789ABCDEF-";
	int nLen = strlen (szTemp);

	for (t = 0; t < nLen + 1; t++)
	{
		int r = rand () % 16;
		char c = ' ';

		switch (szTemp[t])
		{
		case 'x' : { c = szHex [r]; } break;
		case 'y' : { c = szHex [(r & 0x03) | 0x08]; } break;
		case '-' : { c = '-'; } break;
		case '4' : { c = '4'; } break;
		}

		guid[t] = ( t < nLen ) ? c : 0x00;
	}
}


/*
 * Initiate attempt to read OID 0x0 (CCOW system object of cluster or root)
 */
int
ccow_cluster_create(ccow_t tctx, const char *cid, size_t cid_size,
    ccow_completion_t c_in)
{
	int err;
	struct ccow *tc = tctx;
	char buf[CCOW_CLUSTER_CHUNK_SIZE];
	struct iovec iov = { .iov_base = buf };
	int iovcnt;

	assert(cid && cid_size > 0);
	assert(tc->cid && tc->cid_size > 0);

	if (memcmp_quick(tc->tid, tc->tid_size, RT_SYSVAL_TENANT_ADMIN,
		    strlen(RT_SYSVAL_TENANT_ADMIN) + 1) != 0) {
		log_error(lg, "Operation not permitted");
		log_hexdump(lg, "TID:", tc->tid, tc->tid_size);
		return -EPERM;
	}

	if (cid_size > REPLICAST_STR_MAXLEN) {
		log_error(lg, "CID length is greater then %d", REPLICAST_STR_MAXLEN);
		return -EINVAL;
	}

	if (tc->cid != NULL)
		je_free(tc->cid);
	tc->cid = je_memdup(cid, cid_size);
	if (!tc->cid) {
		return -ENOMEM;
	}
	tc->cid_size = cid_size;

	if (*cid) {

		err = crypto_hash_with_type(HASH_TYPE_DEFAULT, (uint8_t *)tc->cid,
		    cid_size, (uint8_t *)&tc->cluster_hash_id);
		if (err) {
			log_error(lg, "Error while calculating cluster hash "
			    "value: %d", err);
			je_free(tc->cid);
			tc->cid = NULL;
			return err;
		}
	}

	ccow_completion_t get_comp;
	err = ccow_create_completion(tc, NULL, NULL, 1, &get_comp);
	if (err)
		return err;

	err = ccow_tenant_get(tc->cid, tc->cid_size, "", 1, "", 1, "", 1,
	    get_comp, NULL, 0, 0, CCOW_GET, NULL);
	if (err) {
		ccow_release(get_comp);
		return err;
	}

	err = ccow_wait(get_comp, 0);
	if (err != -ENOENT) {
		if (err == 0)
			return -EEXIST;
		return err;
	}

	/* object not found - create new cluster sysobj or root */

	ccow_completion_t put_comp;
	err = ccow_create_completion(tc, NULL, NULL, 1, &put_comp);
	if (err)
		return err;

	err = ccow_attr_modify_default(put_comp, CCOW_ATTR_CHUNKMAP_TYPE,
	    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
	if (err) {
		ccow_release(put_comp);
		return err;
	}

	/* default is 1 */
	uint16_t num_vers = 1;
	err = ccow_attr_modify_default(put_comp, CCOW_ATTR_NUMBER_OF_VERSIONS,
	    (void *)&num_vers, NULL);
	if (err) {
		ccow_release(put_comp);
		return err;
	}

	/* 48 entries max of ~ 1K per entry */
	uint16_t order = RT_SYSVAL_CHUNKMAP_BTREE_ORDER_1K;
	err = ccow_attr_modify_default(put_comp, CCOW_ATTR_BTREE_ORDER, &order, NULL);
	if (err) {
		ccow_release(put_comp);
		return err;
	}

	if (c_in) {
		err = ccow_copy_inheritable_md(c_in, put_comp);
		if (err) {
			ccow_release(put_comp);
			return err;
		}
	}

	if (*cid == 0) {
		/*
		 * For root object only, initialize X-system-guid
		 */
		char *guid_key = RT_SYSKEY_SYSTEM_GUID;
		char guid_value[41] = { 0 };
		ccow_get_system_guid(&guid_value[0]);
		err = ccow_attr_modify_custom(put_comp, CCOW_KVTYPE_STR, guid_key,
		    strlen(guid_key) + 1, guid_value, strlen(guid_value) + 1, NULL);
		if (err) {
			ccow_release(put_comp);
			return err;
		}
		/*
		 * System object has to be created w/o replication bg job
		 */
		put_comp->sync_put = 0;

		/* this TC isn't yet has root object created, but it is
		 * already active. As a result, we have to assign this new guid */
		ccow_assign_this_guid(tc, guid_value, strlen(guid_value) + 1);
	}

	/*
	 * Assumption 1:
	 *
	 * Put the new cluster or sys object and insert "root" in it at the
	 * same time.
	 *
	 * Insert "root" admin tenant, but do not create associated
	 * object. This required for any cluster objects, not just system..
	 */
	strcpy(iov.iov_base, RT_SYSVAL_TENANT_ADMIN);
	iov.iov_len = strlen(RT_SYSVAL_TENANT_ADMIN) + 1;
	iovcnt = 1;
	err = ccow_tenant_put(tc->cid, tc->cid_size, "", 1, "", 1, "", 1,
		put_comp, &iov, iovcnt, 0, CCOW_INSERT_LIST, NULL, 0);
	if (err) {
		ccow_release(put_comp);
		return err;
	}

	err = ccow_wait(put_comp, 0);
	if (err) {
		return err;
	}

	/* was it root init? - finalize it */
	if (*cid == 0) {

		/*
		 * Assumption 2:
		 *
		 * Create SVCS object, but do not insert it into the sysobj
		 */
		ccow_completion_t svcs_comp;
		err = ccow_create_completion(tc, NULL, NULL, 1, &svcs_comp);
		if (err)
			return err;

		err = ccow_attr_modify_default(svcs_comp, CCOW_ATTR_CHUNKMAP_TYPE,
		    RT_SYSVAL_CHUNKMAP_BTREE_NAME_INDEX, NULL);
		if (err) {
			ccow_release(svcs_comp);
			return err;
		}

		/* default is 1 */
		uint16_t num_vers = 1;
		err = ccow_attr_modify_default(svcs_comp, CCOW_ATTR_NUMBER_OF_VERSIONS,
		    (void *)&num_vers, NULL);
		if (err) {
			ccow_release(svcs_comp);
			return err;
		}

		err = ccow_tenant_put("", 1, RT_SYSVAL_TENANT_SVCS,
			sizeof (RT_SYSVAL_TENANT_SVCS), "", 1, "", 1, svcs_comp,
			NULL, 0, 0, CCOW_PUT, NULL, 0);
		if (err) {
			ccow_release(svcs_comp);
			return err;
		}

		err = ccow_wait(svcs_comp, 0);
		if (err) {
			return err;
		}

		log_debug(lg, "System root object created successfully");
		return 0;
	}

	/* add cluster sysobj to the system root object */

	err = ccow_create_completion(tc, NULL, NULL, 1, &put_comp);
	if (err)
		return err;

	memcpy(iov.iov_base, cid, cid_size);
	iov.iov_len = cid_size;
	iovcnt = 1;
	err = ccow_container_update_list("", 1, "", 1, "", 1, "", 1,
				 put_comp, &iov, iovcnt, CCOW_INSERT_LIST);
	if (err) {
		ccow_release(put_comp);
		return err;
	}

	err = ccow_wait(put_comp, 0);
	if (err) {
		return err;
	}
	return 0;
}

int
ccow_system_init(ccow_t tctx)
{
	return ccow_cluster_create(tctx, "", 1, NULL);
}
