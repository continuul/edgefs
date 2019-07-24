/*
 * ccow-dynamic-fetch.h
 *
 *  Created on: Mar 27, 2019
 *      Author: root
 */

#ifndef SRC_LIBCCOW_CCOW_DYNAMIC_FETCH_H_
#define SRC_LIBCCOW_CCOW_DYNAMIC_FETCH_H_

#define ISGW_PROTO_VERSION 1

enum eIsgwDynamicFetchType {
	/*
	 * The service can handle only MDonly objects
	 */
	eIsgwFTypeMDOnly = 0,
	/*
	 * The service can handle both MDonly objects
	 * and an emergency chunk lookup
	 */
	eIsgwFTypeFull = 1
};

struct iswg_addr_item {
	QUEUE item;
	char  addr[64]; // IP of an ISGW server
	uint64_t seg_uid;  // Segment UID
	enum eIsgwDynamicFetchType mode; /* Dynamic fetch mode: MDonly or MDonly + emergency lookup */
};

typedef void (*ccow_isgw_proto_cb_t) (void *data, int status, void *rsp);

/**
 * dynfetch_data::flags:
 * Bits:
 * 0..3  request sub-type, see enum eIsgwSubType
 *
 * dynfetch_data::obj_path and object path in format <cid>/<tid>/<bid>/<oid>
 * dynfetch_data::ref is a payload refentry from its parent manifest
 * dynfetch_data::n_chid  number of CHIDs in current request
 * dynfetch_data::chids pointer to array of CHIDs the requests consists
 */

enum eIsgwSubType {
	/*
	 * A single payload fetch request. 2 or 3 CHIDs will be provided.
	 *
	 * dynfetch_data::chids[0] VM manifest CHID
	 * dynfetch_data::chids[1] object NHID
	 * Optional:obj_path[] is a path to an object the data chunk belongs to
	 *                     Format: <cid>/<tid>/<bid>/<oid>
	 * dynfetch_data::chids[2] object CM CHID to be used to invoke
	 *          an EC recovery requests on a remote site (if required).
	 */
	eIsgwReqPayload,
	/**
	 * Multiple payload fetch request.
	 * TBD.
	 */
	eIsgwReqComposite,
	/**
	 *  Request to fetch all payloads that belong to the provided CM/VM.
	 *  TBD.
	 */
	eIsgwReqManifest
};

struct dynfetch_data {
	uint64_t flags;
	char obj_path[PATH_MAX]; /* object path within cluster */
	struct refentry ref;
	uint16_t n_chids; /* Number of CHIDs */
	uint512_t* chids;
};

/**
 * Create a process-wide ISGW2bucket hash table
 */
int
ccow_isgw_service_create(ccow_t tc);

/**
 * Update the ISGW2bucket table. Needs to be called periodically
 */
int
ccow_isgw_service_update(ccow_t tc);

/**
 * Destroy the ISGW2bucket table
 */
void
ccow_isgw_service_destroy();


/**
 * Lookup for inter-segment gateways which are serving the bucket.
 * Only for "the MDOnly" service type.
 *
 * @param cid [in] cluster ID string
 * @apram tid [in] tenant ID string
 * @param bid [in] bucket ID string
 * @param res [in/out] pointer to a queue of struct iswg_addr_item.
 *             Set only if bucket is found in the ISGW service table and function
 *             returned 0. Queue's items have to be freed be the caller.
 *             Can be set to NULL is unused.
 * @returns  0 on success, error code otherwise.
 *          -ENOENT if bucket not found or service table is empty
 *          -ENOMEM out of memory
 */
int
ccow_bucket_isgw_lookup(const char* cid, const char* tid, const char* bid,
	QUEUE* res);

/**
 * Send a dynamic payload fetch request. Async function. The integrated FSM is
 * executed in context of a dedicated tenant context initialized upon
 * the first invocation.
 *
 * @param isgw_addr [in] an ISGW IPv4 address string
 * @param msg       [in] a payload lookup request formed as described above
 * @param cb        [in] a callback function to be called on fetch failure or success
 * @param cb_data   [in] dedicated callback data
 * @param handle    [out] a request handle which can be used to cancel the request
 */
int
ccow_isgw_dynamic_fetch_init(const char *isgw_addr, const struct dynfetch_data* msg,
	ccow_isgw_proto_cb_t cb, void *cb_data, void** handle);

/**
 * Cancel an in-progress ISGW request
 */
void
ccow_isgw_dynamic_fetch_cancel(void* handle);

/**
 * Check if ISGW's offline condition detected
 */
int
ccow_isgw_is_offline(const char* srv, int* offline);

#endif /* SRC_LIBCCOW_CCOW_DYNAMIC_FETCH_H_ */
