/*
 * ccow-dynamic-fetch.c
 *
 *  Created on: Mar 27, 2019
 *      Author: root
 */
#include <uv.h>
#include <pthread.h>
#include <ccow-impl.h>
#include <ccow-dynamic-fetch.h>
#include <connbroker.h>
#include <ccowutil.h>


#define ISGW_PORT 49678

#define ISGW_CONNECT_TIMEOUT	(15*1000UL*1000UL)
#define ISGW_REPLY_TIMEOUT	(45*1000UL*1000UL)

struct isgw_service_entry {
	char* bucketID;
	QUEUE  isgw_addr_queue; // A queue of iswg_addr_entry entries
	UT_hash_handle hh;
};

struct isgw_connbroker_entry {
	char key[64];
	struct connbroker cbr;
	int offline;
	uint64_t seg_uid;
	uint64_t ts;
	UT_hash_handle hh;
};

static ccow_t isgw_tc = NULL;
static pthread_mutex_t isgw_tc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t isgw_tc_cond = PTHREAD_COND_INITIALIZER;
static int isgw_tc_refcount = 0;
static uv_rwlock_t isgw_table_lock;
static uint64_t mtc_iswg_table_ts = 0;
static uint64_t mtc_connbrok_table_ts = 0;
static struct isgw_service_entry* iswg_service_table = NULL;
static struct isgw_connbroker_entry* isgw_broker_table = NULL;

static int
host_to_ip(char *hostname, char *ip, int *domain)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *h;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0) {
		log_error(lg, "Cannot get IP address from %s: %s",
		    hostname, gai_strerror(rv));
		return -1;
	}

	// loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		h = (struct sockaddr_in *)p->ai_addr;
		*domain = p->ai_family;
		strcpy(ip, inet_ntoa(h->sin_addr));
		break;
	}

	freeaddrinfo(servinfo); // all done with this structure
	return 0;
}


static int
ccow_isgw_broker_table_update() {
	assert(isgw_tc);
	struct isgw_service_entry *e, *tmp;
	if (mtc_connbrok_table_ts == mtc_iswg_table_ts)
		return 0;
	mtc_connbrok_table_ts = mtc_iswg_table_ts;
	uv_rwlock_rdlock(&isgw_table_lock);
	HASH_ITER(hh, iswg_service_table, e, tmp) {
		QUEUE* q = NULL;
		QUEUE_FOREACH(q, &e->isgw_addr_queue) {
			struct iswg_addr_item* ae = QUEUE_DATA(q, struct iswg_addr_item, item);
			struct isgw_connbroker_entry *pe = NULL;
			HASH_FIND_STR(isgw_broker_table, ae->addr, pe);
			if (!pe) {
				pe = je_malloc(sizeof(*pe));
				if (!pe) {
					uv_rwlock_rdunlock(&isgw_table_lock);
					return -ENOMEM;
				}
				memcpy(pe->key, ae->addr, sizeof(pe->key));
				pe->seg_uid = ae->seg_uid;

				int err = cbr_init(&pe->cbr, isgw_tc->loop, "ccow-isgw", NULL);
				if (err) {
					uv_rwlock_rdunlock(&isgw_table_lock);
					log_error(lg, "ISGW connection broker create error: %d", err);
					return err;
				}
				char hostname[1024];
				int port = ISGW_PORT;
				sscanf(ae->addr, "%256[^:]:%d", hostname, &port);
				char addr[1024];
				int domain = AF_INET;

				int a[4];
				if (sscanf(hostname, "%3d.%3d.%3d.%3d", &a[0], &a[1], &a[2], &a[3]) != 4) {
					err = host_to_ip(hostname, addr, &domain);
					if (err != 0) {
						uv_rwlock_rdunlock(&isgw_table_lock);
						log_error(lg, "ISGW connection broker create error: %d", err);
						return err;
					}
				} else {
					strncpy(addr, hostname, INET_ADDRSTRLEN);
				}



				err = cbr_add_remote_endpoint(&pe->cbr, addr, port, AF_INET, 0);
				if (err)
					log_error(lg, "Coudln't added an ISGW endpoint %s:%d to"
						"the connbroker", ae->addr, ISGW_PORT);
				else
					log_debug(lg, "Added new ISGW endpoint %s:%d", addr, port);

				HASH_ADD_KEYPTR(hh, isgw_broker_table, pe->key, strlen(pe->key), pe);
			}
		}
	}
	uv_rwlock_rdunlock(&isgw_table_lock);
	return 0;
}

int
ccow_isgw_is_offline(const char* srv, int* offline) {
	assert(srv);
	assert(offline);
	uv_rwlock_rdlock(&isgw_table_lock);
	struct isgw_connbroker_entry *pe = NULL;
	HASH_FIND_STR(isgw_broker_table, srv, pe);
	if (!pe) {
		uv_rwlock_rdunlock(&isgw_table_lock);
		return -ENOENT;
	}
	if (pe->offline) {
		uint64_t backoff_delay = CCOW_ISGW_BACKOFF_TIME;
		if (isgw_tc)
			backoff_delay = isgw_tc->isgw_backoff_time;
		if (pe->ts + backoff_delay*1000UL < get_timestamp_us())
			pe->offline = 0;
	}
	*offline = pe->offline;
	uv_rwlock_rdunlock(&isgw_table_lock);
	return 0;
}

static int
ccow_isgw_set_offline(const char* srv, int offline) {
	assert(srv);
	assert(offline);
	uv_rwlock_rdlock(&isgw_table_lock);
	struct isgw_connbroker_entry *pe = NULL;
	HASH_FIND_STR(isgw_broker_table, srv, pe);
	if (!pe) {
		uv_rwlock_rdunlock(&isgw_table_lock);
		return -ENOENT;
	}
	pe->offline = offline;
	pe->ts = get_timestamp_us();
	uv_rwlock_rdunlock(&isgw_table_lock);
	return 0;
}

static void
isgw_table_destroy(struct isgw_service_entry* table) {
	struct isgw_service_entry *e, *tmp;
	HASH_ITER(hh, table, e, tmp) {
		HASH_DEL(table, e);
		while (!QUEUE_EMPTY(&e->isgw_addr_queue)) {
			QUEUE* q = QUEUE_HEAD(&e->isgw_addr_queue);
			struct iswg_addr_item* ae = QUEUE_DATA(q, struct iswg_addr_item, item);
			QUEUE_REMOVE(q);
			QUEUE_INIT(q);
			je_free(ae);
		}
		je_free(e->bucketID);
		je_free(e);
	}
	je_free(table);
}

static void
isgw_table_show(struct isgw_service_entry* table) {
	struct isgw_service_entry *e, *tmp;
	HASH_ITER(hh, table, e, tmp) {
		QUEUE* q = NULL;
		printf("Bucket: %s ISGW(s): ", e->bucketID);
		QUEUE_FOREACH(q, &e->isgw_addr_queue) {
			struct iswg_addr_item* ae = QUEUE_DATA(q, struct iswg_addr_item, item);
			printf("%s, ", ae->addr);
		}
		printf("\n");
	}
}

int
build_isgw_service_table(ccow_t cl, struct isgw_service_entry** ptable) {
	struct isgw_service_entry* table = NULL;
	int err;
	ccow_completion_t c;

	/*
	 * Read root system object with NHID = 0x0
	 */
	err = ccow_create_completion(cl, NULL, NULL, 1, &c);
	if (err) {
		log_error(lg, "ccow_create_completion returned error = %d", err);
		return err;
	}

	char buf = 0;
	struct iovec iov = { .iov_base = &buf, .iov_len = 1 };
	ccow_lookup_t iter = NULL, biter = NULL;
	err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
		"", 1, "", 1, c, &iov, 1, 10000, CCOW_GET_LIST, &iter);
	if (err) {
		ccow_release(c);
		log_warn(lg, "ccow_tenant_get = %d", err);
		return err;
	}
	err = ccow_wait(c, -1);
	if (err) {
		log_warn(lg, "Error while reading system object: %d, ", err);
		return err;
	}

	int pos = 0;
	struct ccow_metadata_kv *kv;
	while ((kv = ccow_lookup_iter(iter, CCOW_MDTYPE_NAME_INDEX, pos++))) {
		/*
		 * Iterate through all the buckets listed in the tenant
		 * Bucket name is a service ID
		 */
		int get_err = 0;
		char *sid = (char *)kv->key;
		uint16_t sid_size = kv->key_size;

		ccow_completion_t c;
		err = ccow_create_completion(cl, NULL, NULL, 1, &c);
		if (err) {
			log_error(lg, "ccow_create_completion failed with error: %d",
				err);
			goto _cleanup;
		}

		err = ccow_tenant_get("", 1, RT_SYSVAL_TENANT_ADMIN, strlen(RT_SYSVAL_TENANT_ADMIN) + 1,
			sid, sid_size, "", 1, c, &iov, 1, 10000, CCOW_GET_LIST, &biter);

		if (err) {
			ccow_release(c);
			log_debug(lg, "Cannot get service %s: %d", sid, err);
			continue;
		}
		err = ccow_wait(c, -1);
		if (err) {
			if (biter) {
				ccow_lookup_release(biter);
				biter = NULL;
			}
			log_debug(lg, "Cannot get service %s wait error: %d", sid, err);
			continue;
		}

		struct ccow_metadata_kv *bkv;
		int bpos = 0;
		int MD_only_iswg = 0;
		char* addr_str = NULL;
		uint64_t suid = 0;
		int dfetch_mode = eIsgwFTypeMDOnly;
		while ((bkv = ccow_lookup_iter(biter, CCOW_MDTYPE_CUSTOM, bpos++))) {
			char *id = (char *)bkv->key;
			uint16_t id_size = bkv->key_size;
			char value[1024] = {0};
			memcpy(value, bkv->value, bkv->value_size);

			if (!strcmp(id, "X-Service-Type") && !strcmp(value, "isgw")) {
				MD_only_iswg++;
			} else if (!strcmp(id, "X-ISGW-DFLocal") && strcmp(value, "-")) {
				addr_str = je_strdup(value);
				MD_only_iswg++;
			} else if (!strcmp(id, "X-ISGW-Remote-SegID") && strcmp(value, "-"))
				suid = strtoull(value, NULL, 16);
			else if (!strcmp(id, "X-ISGW-Emergency-Lookup") && strcmp(value, "-"))
				dfetch_mode = eIsgwFTypeFull;
		}
		if (MD_only_iswg < 2 || !addr_str) {
			ccow_lookup_release(biter);
			biter = NULL;
			continue;
		}
		bpos = 0;
		/* Releasing custom metadata buffer*/
		rtbuf_free(biter->rb);
		/* Looking for tenants/buckets to be served */
		while ((bkv = ccow_lookup_iter(biter, CCOW_MDTYPE_NAME_INDEX, bpos++))) {
			char *path = (char *)bkv->key;
			struct isgw_service_entry *pe = NULL;
			char *sp = NULL;
			char *bpath = strtok_r(path, ",", &sp);

			HASH_FIND_STR(table,bpath,pe);
			if(!pe) {
				pe = je_malloc(sizeof(*pe));
				if (!pe) {
					log_error(lg, "Malloc error");
					err = -ENOMEM;
					goto _cleanup;
				}
				pe->bucketID = je_strdup(bpath);
				QUEUE_INIT(&pe->isgw_addr_queue);
				struct iswg_addr_item* ie = je_malloc(sizeof(*ie));
				if (!ie) {
					je_free(pe);
					log_error(lg, "Malloc error");
					err = -ENOMEM;
					goto _cleanup;
				}
				QUEUE_INIT(&ie->item);
				strncpy(ie->addr, addr_str, sizeof(ie->addr));
				ie->seg_uid = suid;
				ie->mode = dfetch_mode;
				QUEUE_INSERT_TAIL(&pe->isgw_addr_queue, &ie->item);
				HASH_ADD_KEYPTR(hh,table,pe->bucketID,strlen(pe->bucketID),pe);
			} else {
				struct iswg_addr_item* ie = je_malloc(sizeof(*ie));
				if (!ie) {
					log_error(lg, "Malloc error");
					err = -ENOMEM;
					goto _cleanup;
				}
				QUEUE_INIT(&ie->item);
				QUEUE_INIT(&ie->item);
				strncpy(ie->addr, addr_str, sizeof(ie->addr));
				ie->seg_uid = suid;
				ie->mode = dfetch_mode;
				QUEUE_INSERT_TAIL(&pe->isgw_addr_queue, &ie->item);
			}
		}
		if (addr_str) {
			je_free(addr_str);
			addr_str = NULL;
		}
		ccow_lookup_release(biter);
		biter = NULL;
	}
_cleanup:
	if (biter)
		ccow_lookup_release(biter);
	if (iter)
		ccow_lookup_release(iter);
	if (err) {
		if (table)
			isgw_table_destroy(table);
	} else
		*ptable = table;
	return err;

}

/**
 * Create a new tenat-wide ISGW-to-bucket service table
 */
int
ccow_isgw_service_create(ccow_t tc) {
	if (iswg_service_table)
		return -EEXIST;

	struct isgw_service_entry* t = NULL;
	int err = build_isgw_service_table(tc, &t);
	if (!err) {
		uv_rwlock_wrlock(&isgw_table_lock);
		iswg_service_table = t;
		mtc_iswg_table_ts = get_timestamp_us() + 60*1000000UL;
		uv_rwlock_wrunlock(&isgw_table_lock);
	}
	return err;
}

/**
 * Update the tenat-wide service table
 */
int
ccow_isgw_service_update(ccow_t tc) {
	if (!iswg_service_table)
		return -ENOENT;
	if (mtc_iswg_table_ts > get_timestamp_us())
		return 0;

	struct isgw_service_entry* t = NULL;
	int err = build_isgw_service_table(tc, &t);
	if (!err) {
		uv_rwlock_wrlock(&isgw_table_lock);
		if (iswg_service_table)
			isgw_table_destroy(iswg_service_table);
		iswg_service_table = t;
		mtc_iswg_table_ts = get_timestamp_us() + 60*1000000UL;
		uv_rwlock_wrunlock(&isgw_table_lock);
	} else
		mtc_iswg_table_ts = get_timestamp_us() + 10*1000000UL;
	return err;
}

void
ccow_isgw_service_destroy() {
	if (iswg_service_table) {
		uv_rwlock_wrlock(&isgw_table_lock);
		isgw_table_destroy(iswg_service_table);
		iswg_service_table = NULL;
		uv_rwlock_wrunlock(&isgw_table_lock);
	}
}

int
ccow_bucket_isgw_lookup(const char* cid, const char* tid, const char* bid, QUEUE* res) {
	char bucket[2048];
	char tenant[2048];
	sprintf(bucket, "%s/%s/%s", cid, tid, bid);
	sprintf(tenant, "%s/%s", cid, tid);
	struct isgw_service_entry *pe = NULL;
	int rc = -ENOENT;
	uv_rwlock_rdlock(&isgw_table_lock);
	if (iswg_service_table) {
		HASH_FIND_STR(iswg_service_table, bucket, pe);
		if (!pe) { // look for tenant
			HASH_FIND_STR(iswg_service_table, tenant, pe);
		}
		if (pe) {
			if (res) {
				QUEUE_INIT(res);
				QUEUE* q = NULL;
				QUEUE_FOREACH(q, &pe->isgw_addr_queue) {
					struct iswg_addr_item* ae = QUEUE_DATA(q, struct iswg_addr_item, item);
					struct iswg_addr_item* e = je_malloc(sizeof(*e));
					if (!e) {
						rc = -ENOMEM;
						break;
					}
					memcpy(e, ae, sizeof(*ae));
					QUEUE_INIT(&e->item);
					QUEUE_INSERT_TAIL(res, &e->item);
				}
			}
			rc = 0;
		}
	}
	uv_rwlock_rdunlock(&isgw_table_lock);
	return rc;
}

/*****************************************************
 *
 * ISGW communication state machine
 *
 *
 ******************************************************/
typedef void (*isgw_proto_cb_t) (void *data, int status, void *rsp);

static int
replicast_pack_sg_dynfetch_payload(msgpack_p *p, const struct dynfetch_data* data) {
	size_t i = 0;
	int err = msgpack_pack_uint64(p, data->flags);
	if (err)
		return err;
	err = msgpack_pack_raw(p, data->obj_path, strlen(data->obj_path)+1);
	if (err)
		return err;
	err = replicast_pack_refentry_dfetch(p, (struct refentry*)&data->ref);
	if (err)
		return err;
	err = msgpack_pack_array(p, data->n_chids);
	if (err)
		return err;
	for (size_t i = 0; i < data->n_chids; i++) {
		err = msgpack_pack_uint512(p, data->chids + i);
		if (err)
			break;
	}
	return err;
}

struct dynamic_fetch_request
{
	struct connbroker_context brx;
	isgw_proto_cb_t cb;
	uv_mutex_t cb_lock;
	void *cb_data;
	int inexec;
	int opcode;
	struct state state;
	int status;
	msgpack_p *p;
	uv_buf_t  payload;
	uv_timer_t* tmr;
	uint64_t ts;
	int timeout_event;
	char isgw_addr[128];
	struct repmsg_sg_dynfetch msg;
};

static void
sg_dynamic_fetch_set_timeout(struct state *st, int timeout, int event);

static void
sg_dynamic_fetch_close_cb(uv_handle_t* handle)
{
	je_free(handle);
}

static void
sg_dynamic_fetch_term(struct state *st)
{
	struct dynamic_fetch_request *r = st->data;
	struct repctx *ctx = r->brx.ctx;

	if (r->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
			r, r->inexec);
		return;
	}

	log_debug(lg, "Terminating request r: %p status: %d", r, r->status);
	if (ctx && r->brx.rbroker->state != CBR_UNINIT) {
		repctx_drop(ctx);
		repctx_destroy(ctx);
		cbr_unref_replicast_client(r->brx.rbroker);
	}

	if (r->tmr) {
		if (r->tmr->data)
			uv_timer_stop(r->tmr);
		r->tmr->data = st;
		uv_close((uv_handle_t*)r->tmr, sg_dynamic_fetch_close_cb);
	}

	if (r->p)
		msgpack_pack_free(r->p);

	je_free(r);
	pthread_mutex_lock(&isgw_tc_lock);
	isgw_tc_refcount--;
	pthread_cond_signal(&isgw_tc_cond);
	pthread_mutex_unlock(&isgw_tc_lock);
}

static void
sg_dynamic_fetch_error(struct state *st)
{
	struct dynamic_fetch_request *r = st->data;
	if (r->status == -ETIME)
		ccow_isgw_set_offline(r->isgw_addr, 1);
	uv_mutex_lock(&r->cb_lock);
	if (r->cb)
		r->cb(r->cb_data, r->status, NULL);
	uv_mutex_unlock(&r->cb_lock);
}

static void
sg_dynamic_fetch_recv(struct state *st)
{
	struct dynamic_fetch_request *r = st->data;
	struct repctx *ctx = r->brx.ctx;
	struct repwqe *wqe = ctx->wqe_in;
	struct repmsg_sg_dynfetch_resp *rsp;

	/* FIXME: tmp work-around, happened when sending link is terminated after timeout */
	if (!wqe)
		return;

	rsp = (struct repmsg_sg_dynfetch_resp *) wqe->msg;
	uv_mutex_lock(&r->cb_lock);
	if (r->cb)
		r->cb(r->cb_data, rsp->status, rsp);
	uv_mutex_unlock(&r->cb_lock);
	state_next(st, EV_DONE);
}

static void
sg_dynamic_fetch_send_cb(void *data, int err, int ctx_valid)
{
	struct state *st = data;
	struct dynamic_fetch_request *r = st->data;

	r->inexec--;
	if (err) {
		log_debug(lg, "Error %d while sending cbr request", err);
		/* Something went wrong, keep trying */
		 sg_dynamic_fetch_set_timeout(st, 1000, EV_CALL);
	} else {
		/* Set an ISGW server response timeout */
		r->ts = get_timestamp_us() + ISGW_REPLY_TIMEOUT;
		/* Repeat the request if no response is received */
		sg_dynamic_fetch_set_timeout(st, ISGW_REPLY_TIMEOUT/1000, EV_CALL);
	}
}

static void
sg_dynamic_fetch_send(struct state *st)
{
	struct dynamic_fetch_request *r = st->data;

	r->inexec++;
	int err = cbr_request_send(&r->brx, st, r->opcode,
		(struct repmsg_generic *)&r->msg, &r->payload, 1,
		sg_dynamic_fetch_send_cb, st, NULL);
	if (err) {
		r->inexec--;
		log_debug(lg, "Failed to send a dynamic fetch request");
		/* Something went wrong, but we don't give up */
		sg_dynamic_fetch_set_timeout(st, 1000, EV_CALL);
	}
}

static void
sg_dynamic_fetch_connect_cb(void *data, int status)
{
	struct dynamic_fetch_request *r = data;
	struct state *st = &r->state;

	uv_timer_stop(r->tmr);
	r->tmr->data = NULL;

	if (status) {
		log_debug(lg, "Failed to establish ISGW server connection: %d",
			status);
		/* Something went wrong, but we don't give up */
		sg_dynamic_fetch_set_timeout(st, 1000, EV_CALL);
	} else
		state_event(st, EV_SEND);
}

static void
sg_dynamic_fetch_restart_cb(uv_timer_t* handle, int status) {
	struct state *st = handle->data;
	struct dynamic_fetch_request *r = st->data;
	uv_timer_stop(handle);
	handle->data = NULL;
	state_event(st, r->timeout_event);
}

static void
sg_dynamic_fetch_connect(struct state *st)
{
	struct dynamic_fetch_request *r = st->data;
	if (!isgw_tc || isgw_tc->abort) {
		r->status = -EIO;
		state_next(st, EV_ERR);
		return;
	}

	int err = cbr_connect(&r->brx, sg_dynamic_fetch_connect_cb, r);
	if (err == -EEXIST) {
		state_next(st, EV_SEND);
		return;
	} else if (err == -EAGAIN) {
		/*
		 * A connection isn't available at the moment.
		 * Try a bit later
		 */
		sg_dynamic_fetch_set_timeout(st, 50, EV_CALL);
		log_debug(lg, "ISGW connection is busy at the moment, retrying");
	} else if (err) {
		/* Something went wrong, but we don't give up */
		sg_dynamic_fetch_set_timeout(st, 250, EV_CALL);
		log_debug(lg, "ISGW connect error, retrying");
	} else {
		/* Connection request sent. It can take a while */
		sg_dynamic_fetch_set_timeout(st, 10000, EV_CALL);
	}
}

static void
sg_dynamic_fetch_set_timeout(struct state *st, int timeout, int event) {
	struct dynamic_fetch_request *r = st->data;
	if (r->tmr->data) {
		uv_timer_stop(r->tmr);
		r->tmr->data = NULL;
	}
	r->tmr->data = st;
	r->timeout_event = event;
	uv_timer_start(r->tmr, sg_dynamic_fetch_restart_cb, timeout, 0);
}

static int
sg_dynamic_fetch_retry_quard(struct state *st) {
	int rc = 0;
	struct dynamic_fetch_request *r = st->data;
	if (r->ts > get_timestamp_us()) {
		log_debug(lg, "req %p, retry", r);
		rc = 1;
	} else {
		log_error(lg, "ISGW server connection timeout");
		r->status = -ETIME;
		if (r->brx.rbroker)
			cbr_destroy_replicast_client(r->brx.rbroker);
		state_next(st, EV_ERR);
	}
	return rc;
}
static int
ccow_isgw_dynamic_fetch_trigger(struct dynamic_fetch_request *r) {
	struct isgw_connbroker_entry *pe = NULL;
	/* Refresh ISGW connection table */
	int err = ccow_isgw_broker_table_update();
	if (err) {
		log_error(lg, "Couldn't update ISGW's brokers table: %d", err);
		return err;
	}
	/* Pick a broker to be used */
	HASH_FIND_STR(isgw_broker_table, r->isgw_addr, pe);
	if (!pe) {
		log_error(lg, "Couldn't find a broker for address %s", r->isgw_addr);
		return -ENOENT;
	}

	pthread_mutex_lock(&isgw_tc_lock);
	isgw_tc_refcount++;
	pthread_mutex_unlock(&isgw_tc_lock);
	uv_timer_init(isgw_tc->loop, r->tmr);

	cbr_init_context(&r->brx, &pe->cbr);

	if (isgw_tc->main_thread == uv_thread_self()) {
		state_event(&r->state, EV_CALL);
	} else {
		while (lfqueue_enqueue(isgw_tc->api_lfq_hp, &r->state) != 0) {
			usleep(250);
		}
		uv_async_send(&isgw_tc->api_call);
	}
	return 0;
}

static void
ccow_isgw_broker_tc_destroy() {
	pthread_mutex_lock(&isgw_tc_lock);
	if (isgw_tc_refcount)
		ccow_tenant_abort(isgw_tc);

	struct isgw_connbroker_entry *e = NULL, *tmp = NULL;
	HASH_ITER(hh, isgw_broker_table, e, tmp) {
		assert(e);
		cbr_destroy(&e->cbr);
	}

	while (isgw_tc_refcount)
		pthread_cond_wait(&isgw_tc_cond, &isgw_tc_lock);

	ccow_tenant_term(isgw_tc);

	pthread_mutex_unlock(&isgw_tc_lock);

	e = NULL, tmp = NULL;
	HASH_ITER(hh, isgw_broker_table, e, tmp) {
		assert(e);
		HASH_DEL(isgw_broker_table, e);
		je_free(e);
	}
	log_info(lg, "ISGW service's tenant context destroyed");
}

static void*
ccow_isgw_broker_tc_create_thread(void* arg) {
	struct dynamic_fetch_request *r = arg;

	pthread_mutex_lock(&isgw_tc_lock);
	if (isgw_tc) {
		pthread_mutex_unlock(&isgw_tc_lock);
		ccow_isgw_dynamic_fetch_trigger(r);
		return NULL;
	}
	int err = 0;
	char path[PATH_MAX];
	char *buf = NULL;
	int fd = -1;

	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	fd = open(path, O_RDONLY);

	if (fd < 0) {
		log_error(lg, "Couldn't create ISGW's tenant context: config open error %d", errno);
		err = -errno;
		pthread_mutex_unlock(&isgw_tc_lock);
		goto _term;
	}
	buf = je_calloc(1, 16384);
	if (!buf) {
		log_error(lg, "Out of memory");
		err = -ENOMEM;
		pthread_mutex_unlock(&isgw_tc_lock);
		goto _term;
	}
	if (read(fd, buf, 16383) < 0) {
		log_error(lg, "Couldn't create ISGW's tenant context: config read error %d", errno);
		err = -errno;
		pthread_mutex_unlock(&isgw_tc_lock);
		goto _term;
	}
	err = ccow_admin_init(buf, "", 1, &isgw_tc);
	je_free(buf);
	if (err) {
		log_error(lg, "Couldn't create ISGW's tenant context: %d", err);
	} else  {
		ccow_isgw_broker_table_update();
		atexit(ccow_isgw_broker_tc_destroy);
	}
	pthread_mutex_unlock(&isgw_tc_lock);
_term:
	if (err) {
		r->cb(r->cb_data, err, r);
		if (buf)
			je_free(buf);
		if (fd >= 0)
			close(fd);
		je_free(r);
	} else {
		assert(isgw_tc);
		ccow_isgw_dynamic_fetch_trigger(r);
	}
	return NULL;
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
// ---------------------------------------------------------------------
{ ST_ANY,  EV_CALL, &sg_dynamic_fetch_connect, ST_INIT, sg_dynamic_fetch_retry_quard },
{ ST_INIT, EV_SEND, &sg_dynamic_fetch_send, ST_WAIT, NULL },
{ ST_WAIT, EV_SEND, &sg_dynamic_fetch_send, ST_WAIT, sg_dynamic_fetch_retry_quard},
{ ST_WAIT, RT_SG_DYN_FETCH_RESP, &sg_dynamic_fetch_recv, ST_WAIT, NULL },
{ ST_ANY, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ERR, &sg_dynamic_fetch_error, ST_TERM, NULL },
};

// State machine for dynamic fetch
int
ccow_isgw_dynamic_fetch_init(const char *isgw_addr, const struct dynfetch_data* msg,
	ccow_isgw_proto_cb_t cb, void *cb_data, void** handle)
{
	struct dynamic_fetch_request *r;
	r = je_calloc(1, sizeof(*r));
	if (r == NULL) {
		log_error(lg, "Failed to allocate memory");
		return -ENOMEM;
	}

	r->p = msgpack_pack_init();
	if (r->p == NULL)
		return -ENOMEM;

	int err = replicast_pack_sg_dynfetch_payload(r->p, msg);
	if (err) {
		msgpack_pack_free(r->p);
		je_free(r);
		return err;
	}

	msgpack_get_buffer(r->p, &r->payload);

	memset(&r->state, 0, sizeof(struct state));
	r->state.table = trans_tbl;
	r->state.cur = ST_INIT;
	r->state.max = sizeof(trans_tbl) / sizeof(*trans_tbl);
	r->state.term_cb = sg_dynamic_fetch_term;
	r->state.data = r;

	r->cb = cb;
	r->cb_data = cb_data;
	r->msg.version = ISGW_PROTO_VERSION;
	r->ts = get_timestamp_us() + ISGW_CONNECT_TIMEOUT;
	strcpy(r->isgw_addr, isgw_addr);

	r->tmr = je_calloc(1, sizeof(*r->tmr));
	if (!r->tmr) {
		msgpack_pack_free(r->p);
		je_free(r);
		return -ENOMEM;
	}
	r->opcode = RT_SG_DYN_FETCH;

	struct isgw_connbroker_entry *pe = NULL;
	if (!err && !isgw_tc) {
		/*
		 * Create a dedicated tenant in a separate thread to avoid
		 * blocking the event loop
		 */
		pthread_attr_t attr;
		pthread_t tid;
		err = pthread_attr_init(&attr);
		if (!err)
			err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (!err)
			err = pthread_create(&tid, &attr, ccow_isgw_broker_tc_create_thread, r);
	} else
		err = ccow_isgw_dynamic_fetch_trigger(r);
	if (!err)
		*handle = r;

	return err;
}

void
ccow_isgw_dynamic_fetch_cancel(void* handle) {
	struct dynamic_fetch_request *r = handle;
	uv_mutex_lock(&r->cb_lock);
	r->cb = NULL;
	uv_mutex_unlock(&r->cb_lock);
	if (r->state.cur != ST_TERM) {
		r->status = -EIO;
		tc_marshal_call(&r->state, isgw_tc, EV_ERR);
	}
}
