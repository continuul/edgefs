/*
 * evactool.c
 *
 *  Created on: Jul 4, 2018
 *      Author: root
 */
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "nanomsg/nn.h"
#include "auditd.h"
#include "ccowutil.h"
#include "ccow.h"
#include "ccowd.h"
#include "ccowd-impl.h"
#include "ccow-impl.h"
#include "rowevac.h"
#include "uthash.h"
#include "pthread.h"
#include <uuid/uuid.h>

#define PROP_DEBUG 0

#define AUDITD_EVAC_QUERY "gauges.ccow.reptrans.rowevac_job"
#define AUDITD_USED_QUERY "gauges.ccow.reptrans.used"
#define AUDITD_ROWUSAGE_QUERY "gauges.ccow.reptrans.rowusagecounters"
#define AUDITD_EVAC_TIMEOUT	30

char* evac_status_str[] = {
	"NONE",
	"AWAITING",
	"IN_PROGRESS",
	"SUSPENDED",
	"CANCELED",
	"SUCCESS",
	"FAILED"
};

enum {
	ROW_MODE_DISABLED = 0,
	ROW_MODE_ENABLED,
	ROW_MODE_EVACUATED
};

struct evac_entry {
	uint64_t id;
	uint128_t src_vdev;
	uint128_t dest_vdev;
	uint16_t row;
	size_t amount;
	uint64_t flags;
};

struct evac_stat {
	struct evac_entry e;
	size_t evacuated;
	size_t total;
	int status;
	UT_hash_handle hh;
};

struct evac_list {
	QUEUE item;
	struct evac_entry e;
};

struct evac_stat* evac_ht = NULL;
pthread_mutex_t ht_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_term = 0;

static void
signal_handler(int signum) {
	printf("\nReceived signal %d\n", signum);
	if (signum == SIGSEGV || signum == SIGABRT)
		exit(-1);
	g_term = 1;
}


static inline void
make_job_id(struct evac_entry* e) {
	uint64_t res = e->src_vdev.u;
	res ^= e->src_vdev.l;
	res ^= e->dest_vdev.u;
	res ^= e->dest_vdev.l;
	res ^= e->row;
	res ^= e->flags;
	res ^= e->amount;
	res ^= rand();
	res &= 0x7fffffffffffffff;
	e->id = res;
}


struct row_use {
	uint8_t mode; /* Set to 1 is row is active for this VDEV */
	int64_t used; /* Number of bytes used by this row */
	int64_t imp_exp_size; /* Number of bytes to be sent/received */
	double util;
};

struct vdev_mod {
	uint128_t id;
	size_t capacity;
	size_t used;
	double util; /* Utilization, % */
	struct row_use* row_usage; /* Initially set to used/numrows, updated with every model change */
	size_t activerows; /* Number of active rows */
};

static int
vdev_mod_sort_util(const void *a, const void *b) {
	const struct vdev_mod* ea = a;
	const struct vdev_mod* eb = b;
	if (ea->util > eb->util)
		return 1;
	if (ea->util < eb->util)
		return -1;
	return 0;
}

static int
fd_vdev_model_calc(ccow_t tc, const uint128_t* fd_id, struct vdev_mod** vdevs_out, int* numrows_out) {
	volatile struct flexhash* fh = tc->flexhash;
	int fd = tc->failure_domain;
	size_t n_vdevs = 24;
	int numrows = 8;
	size_t capacity = 1UL*1024UL*1024UL*1024UL*1024UL; /* 8TB per vdev */

	struct vdev_mod* model = je_calloc(n_vdevs, sizeof(*model));
	if (!model)
		return -ENOMEM;
	for (size_t i = 0; i < n_vdevs; i++) {
		model[i].id.l = i;
		model[i].capacity = capacity - (rand() % (capacity/4));
		model[i].util = (rand() % 10000)/10000.0;
		model[i].used = capacity * model[i].util;
		model[i].row_usage = je_calloc(numrows, sizeof(struct row_use));
		model[i].activerows = numrows - 3 + (rand() % 3);
		size_t k = 0;
		int64_t distr = model[i].used;
		while (k < model[i].activerows) {
			int idx = rand() % numrows;
			if (!model[i].row_usage[idx].mode) {
				model[i].row_usage[idx].mode = ROW_MODE_ENABLED;
				if (k < model[i].activerows - 1) {
					model[i].row_usage[idx].used = distr * (rand() % 100) / 100;
					distr -= model[i].row_usage[idx].used;
				} else {
					model[i].row_usage[idx].used = distr;
				}
				model[i].row_usage[idx].util = (double)model[i].row_usage[idx].used /
					(model[i].capacity/model[i].activerows);
				k++;
			}
		}
	}
	*vdevs_out = model;
	*numrows_out = numrows;
	return n_vdevs;
}

static int
fd_vdev_model_from_fh(ccow_t tc, const uint128_t* fd_id, struct vdev_mod** vdevs_out,
	int* numrows_out) {
	volatile struct flexhash* fh = tc->flexhash;
	struct vdevstore* vs = fh->vdevstore;
	size_t vs_size = vs->lvdevcount;
	int fd = fh->fdmode;
	size_t n_vdevs = 0;

	int fddelta = 0;
	struct fddelta aux;
	flexhash_fddelta_checkpoint(fh, &fddelta, &aux);
	if (fddelta < 0) {
		fprintf(stderr, "ERROR: cluster split condition detected: %d\n", fddelta);
		return -EIO;
	}

	struct vdev_mod* model = je_calloc(vs_size, sizeof(*model));
	if (!model)
		return -ENOMEM;

	/* We need to get of VDEVs that belongs to requested failure domain ID */
	for (size_t i = 0; i < vs_size; i++) {
		struct lvdev* e = vs->lvdevlist + i;
		if ((fd == FD_SERVER && uint128_cmp(&e->server->id, fd_id) == 0) ||
			(fd == FD_ZONE && e->server->zone == fd_id->l)) {
			model[n_vdevs].id = e->vdevid;
			model[n_vdevs].capacity = e->size;
			model[n_vdevs].row_usage = je_calloc(fh->numrows, sizeof(struct row_use));
			for (int j = 0; j < fh->numrows; j++)
				if (e->hashcount[j]) {
					model[n_vdevs].row_usage[j].mode = ROW_MODE_ENABLED;
					model[n_vdevs].activerows++;
				}
			n_vdevs++;
		}
	}
	if (!n_vdevs) {
		je_free(model);
		return -EINVAL;
	}

	/* Now we need to get each VDEV's usage */
	QUEUE resp = QUEUE_INIT_STATIC(resp);
	int err = auditd_stats_query(AUDITD_USED_QUERY, &resp);
	size_t n_filled = 0;
	while (!QUEUE_EMPTY(&resp)) {
		uint128_t vdev;
		QUEUE* q = QUEUE_HEAD(&resp);
		struct auditd_query_resp* e = QUEUE_DATA(q, struct auditd_query_resp, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		char* p = e->entry + strlen(AUDITD_USED_QUERY)+1;
		char* save = NULL;
		char* str = strtok_r(p, ".", &save);
		assert(str);
		/* Skip server ID */
		str = strtok_r(NULL, "|", &save);
		assert(str);
		uint128_fromhex(str, UINT128_STR_BYTES, &vdev);
		for (size_t i = 0; i < n_vdevs; i++) {
			if (uint128_cmp(&model[i].id, &vdev) == 0) {
				str = strtok_r(NULL, "|", &save);
				model[i].used = strtoll(str, NULL, 10);
				model[i].util = (double)model[i].used/model[i].capacity;
				for (int j = 0; j < fh->numrows; j++)
					if (model[i].row_usage[j].mode)
						model[i].row_usage[j].used = model[i].used/model[i].activerows;
				n_filled++;
				break;
			}
		}
		je_free(e);
	}
	if (n_vdevs != n_filled) {
		fprintf(stderr, "ERROR: could fetch usage of %lu out of %lu VDEVs, make sure the auditd is running\n",
			n_filled, n_vdevs);
		je_free(model);
		return -EIO;
	}
	/* Now obtain row usage */
	QUEUE_INIT(&resp);
	n_filled = 0;
	err = auditd_stats_query(AUDITD_ROWUSAGE_QUERY, &resp);
	while (!QUEUE_EMPTY(&resp)) {
		uint128_t vdev;
		QUEUE* q = QUEUE_HEAD(&resp);
		struct auditd_query_resp* e = QUEUE_DATA(q, struct auditd_query_resp, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		char* p = e->entry + strlen(AUDITD_ROWUSAGE_QUERY)+1;
		char* save = NULL;
		char* str = strtok_r(p, ".", &save);
		assert(str);
		/* Skip server ID */
		str = strtok_r(NULL, ".", &save);
		assert(str);
		uint128_fromhex(str, UINT128_STR_BYTES, &vdev);
		for (size_t i = 0; i < n_vdevs; i++) {
			if (uint128_cmp(&model[i].id, &vdev) == 0) {
				if (model[i].activerows) {
					while ((str = strtok_r(NULL, "#", &save)) != NULL) {
						int rowid = strtoll(str, NULL, 10);
						str = strtok_r(NULL, "^", &save);
						size_t usage_mb = strtoll(str, NULL, 10);
						if (model[i].row_usage[rowid].mode == ROW_MODE_DISABLED) {
							fprintf(stderr, "ERROR: FH claims the VDEV %016lX%016lX ins't a member of row %d\n",
								vdev.u, vdev.l, rowid);
							je_free(model);
							return -EINVAL;
						}
						model[i].row_usage[rowid].used = usage_mb*1024UL*1024UL;
						model[i].row_usage[rowid].util = (double)model[i].row_usage[rowid].used /
							(model[i].capacity/model[i].activerows);
					}
				}
				n_filled++;
				break;
			}
		}
		je_free(e);
	}

	if (n_vdevs != n_filled) {
		fprintf(stderr, "ERROR: couldn't fetch usage of %lu out of %lu VDEVs, "
			"possibly the auditd server isn't running\n",
			n_filled, n_vdevs);
		je_free(model);
		return -EIO;
	}
	err = n_vdevs;
	*vdevs_out = model;
	*numrows_out = fh->numrows;
	return err;
}

#if PROP_DEBUG
static void
dump_vdev_model(const struct vdev_mod* m, size_t n, size_t nrows) {
	for (size_t i = 0; i < n; i++) {
		const struct vdev_mod* e = m + i;
		printf("VDEV %016lX%016lX util %6.3f, cap %14lu, used %14lu, activerows %2lu, row_util, %%: ",
			e->id.u, e->id.l, e->util, e->capacity, e->used, e->activerows);
		for (size_t n = 0; n < nrows; n++) {
			if (e->row_usage[n].mode)
				printf("%6.3f, ", e->row_usage[n].util);
			else
				printf("      , ");
		}
		printf("\n");
	}
}
#endif

static int
vdev_row_sort_util_cb(const void *a, const void *b, void* arg) {
	const struct vdev_mod* ea = a;
	const struct vdev_mod* eb = b;
	int row = *(int*)arg;


	if( ea->row_usage[row].util >
		eb->row_usage[row].util)
		return 1;

	if( ea->row_usage[row].util <
		eb->row_usage[row].util)
		return -1;
	return 0;
}

static int
vdev_row_sort_impexp_cb(const void *a, const void *b, void* arg) {
	const struct vdev_mod* ea = a;
	const struct vdev_mod* eb = b;
	int row = *(int*)arg;

	if( ea->row_usage[row].imp_exp_size >
		eb->row_usage[row].imp_exp_size)
		return 1;

	if( ea->row_usage[row].imp_exp_size <
		eb->row_usage[row].imp_exp_size)
		return -1;
	return 0;
}

static int
vdev_row_sort_ena_cb(const void *a, const void *b, void* arg) {
	const struct vdev_mod* ea = a;
	const struct vdev_mod* eb = b;
	int row = *(int*)arg;

	return eb->row_usage[row].mode - ea->row_usage[row].mode;
}


static void
rowevac_model_deviation(const struct vdev_mod* m, size_t n, int numrows) {
	double mean_vdev_util = 0;
	for (size_t i = 0; i < n; i++) {
		mean_vdev_util += m[i].util*100.0;
	}
	mean_vdev_util /= n;

	double square_seed = 0;
	for (size_t i = 0; i < n; i++) {
		square_seed += pow(m[i].util*100.0 - mean_vdev_util, 2.0);
	}
	square_seed = sqrt(square_seed/n);


	printf("VDEV avg_util %6.3f%%, standard deviation %6.3f%%\n",
		mean_vdev_util, square_seed);

	for (int row = 0; row < numrows; row++) {
		double row_util_mean = 0;
		int width = 0;
		for (size_t i = 0; i < n; i++)
			if (m[i].row_usage[row].mode == ROW_MODE_ENABLED) {
				width++;
				row_util_mean += m[i].row_usage[row].util*100.0;
			}
		row_util_mean /= width;
		square_seed = 0.0;
		for (size_t i = 0; i < n; i++)
			if (m[i].row_usage[row].mode == ROW_MODE_ENABLED)
				square_seed += pow(m[i].row_usage[row].util*100.0
					- row_util_mean, 2.0);
		square_seed = sqrt(square_seed/width);
		printf("ROW %d avg_util %6.3f%%, standard deviation %6.3f%%\n",
			row, row_util_mean, square_seed);
	}
}



static void
rowevac_model_sort_by_row_util(const struct vdev_mod* m, size_t n, int rowid) {
	for (size_t i = 0; i < n; i++)
		if (m[i].row_usage[rowid].mode == ROW_MODE_DISABLED)
			m[i].row_usage[rowid].util = -1;
	qsort_r((void*)m, n, sizeof(struct vdev_mod), vdev_row_sort_util_cb, &rowid);
}

#if 0
struct row {
	int id;
	int vdevs;
};

static int
compare_row_dist_cb(const void *val1, const void *val2)
{
	struct row* a = (struct row *)val1;
	struct row* b = (struct row *)val2;

	return a->vdevs < b->vdevs ? -1 : a->vdevs > b->vdevs ? 1 : 0;
}

static int
rowevac_row_rebalance(struct vdev_mod* m, int n, int numrows) {
	struct row row_dist[numrows];
	memset(row_dist, 0, sizeof(struct row)*numrows);
	int row_total = 0, row_mean = 0;
	/* Calculating rows distribution and row distr. mean */
	for (int row = 0; row < numrows; row++) {
		row_dist[row].id = row;
		for (int i = 0; i < n; i++)
			if (m[i].row_usage[row].mode == ROW_MODE_ENABLED) {
				row_dist[row].vdevs++;
				row_total++;
			}
	}
	row_mean = row_total / numrows;
	int cnt = 10;
	int cont = 0;
	do {
		cont = 0;
		/* Picking up the widest row*/
		qsort(row_dist, numrows, sizeof(struct row), compare_row_dist_cb);

		printf("rowdist mean %d: ", row_mean);
		for (int i = 0; i < numrows; i++) {
			printf("%3d:%d ", row_dist[i].vdevs, row_dist[i].id);
		}
		printf("\n");
		if (row_dist[numrows-1].vdevs > row_mean) {
			/*
			 * the rowid now is a candidate for eviction. We have to find a VDEV
			 * in this row with the minimal row weight
			 */
			int rowid = row_dist[numrows-1].id;

			rowevac_model_sort_by_row_util(m, n, rowid);

			for (int i = 0; i < n; i++) {
				if (m[i].row_usage[rowid].mode == ROW_MODE_ENABLED) {
					m[i].row_usage[rowid].mode = ROW_MODE_EVACUATED;
					m[i].activerows--;
					row_dist[numrows-1].vdevs--;
					printf("VDDEV %lX%lX evicted from row %d, rowsize %luM\n",
						m[i].id.u, m[i].id.l,
						rowid, m[i].row_usage[rowid].used/(1024*1024));
					break;
				}
			}
			cont = 1;
		}
		if (row_dist[0].vdevs < row_mean) {
			int rowid = row_dist[0].id;
			/* Lookup for a VDEV with the lowest utilization */
			qsort(m, n, sizeof(struct vdev_mod), vdev_mod_sort_util);
			for (int i = 0; i < n; i++) {
				if (m[i].row_usage[rowid].mode == ROW_MODE_DISABLED) {
					/* Add the vdev to the row */
					m[i].row_usage[rowid].mode = ROW_MODE_ENABLED;
					m[i].row_usage[rowid].used = 0;
					m[i].activerows++;
					row_dist[0].vdevs++;
					printf("VDDEV %lX%lX ADDed to row %d\n", m[i].id.u, m[i].id.l, rowid);
					break;
				}
			}
			cont = 1;
		}
	} while (cont);
	return 0;
}
#endif

static int
propose_jobs(ccow_t tc, const uint128_t* fd_id, double delta, QUEUE* jobs) {
	volatile struct flexhash* fh = tc->flexhash;
	int fd = fh->fdmode;
	size_t n_vdevs = 0;
	int numrows = 0;

	if (fd == FD_ANY_FIRST) {
		/* The VDEV FD mode isn't supported because we are allowed to
		 * move rows only within a failure domain,
		 * but we cannot move rows within the same VDEV
		 */
		fprintf(stderr, "ERROR: failure domain FD_ANY_FIRST ins't supported\n");
		return -EINVAL;
	}
	struct vdev_mod* vdevs = NULL;
#if PROP_DEBUG
	int err = fd_vdev_model_calc(tc, fd_id, &vdevs, &numrows);
#else
	int err = fd_vdev_model_from_fh(tc, fd_id, &vdevs, &numrows);
#endif
	if (err < 0)
		goto _exit;
	assert(vdevs);
	assert(numrows);
	n_vdevs = err;
	err = 0;


	printf("Utilization before optimization:\n");
	rowevac_model_deviation(vdevs, n_vdevs, numrows);
	int* rowsdist = je_calloc(numrows, sizeof(int));

	for (int row = 0; row < numrows; row++) {
		/*
		 * For each row sort according to relative utilization in each VDEV.
		 * Then try to distribute data across VDEVs of this row,
		 * calculate amount of data each VDEV exports/imports
		 */
		rowevac_model_sort_by_row_util(vdevs, n_vdevs, row);

		int first = 0;
		double util_mean = 0.0;

		/* Last VDEVs in this array are not in the row, filter them out */
		while (!vdevs[first].row_usage[row].mode)
			first++;
		/* Establish mean row utilization and number VDEVs in the row */
		for (size_t i = first; i < n_vdevs; i++) {
			util_mean += vdevs[i].row_usage[row].util;
			rowsdist[row]++;
			assert(vdevs[i].row_usage[row].mode);
		}
		util_mean /= rowsdist[row];
		/* Move data between VDEVs until we are above 5% threshold */
		int iters = 100000;
		while (vdevs[n_vdevs-1].row_usage[row].util - util_mean > delta/100.0 ||
			vdevs[first].row_usage[row].util - util_mean > delta/100.0) {

			int64_t amount = (util_mean - vdevs[first].row_usage[row].util)
				* (vdevs[first].capacity / vdevs[first].activerows);
			if (vdevs[n_vdevs-1].row_usage[row].used < amount)
				amount = vdevs[n_vdevs-1].row_usage[row].used;
			vdevs[first].used += amount;
			vdevs[first].row_usage[row].used += amount;
			vdevs[first].row_usage[row].imp_exp_size -= amount;
			vdevs[first].row_usage[row].util = (double)vdevs[first].row_usage[row].used /
				(vdevs[first].capacity/vdevs[first].activerows);
			vdevs[first].util = (double)vdevs[first].used/vdevs[first].capacity;
			vdevs[n_vdevs-1].used -= amount;
			vdevs[n_vdevs-1].row_usage[row].used -= amount;
			vdevs[n_vdevs-1].row_usage[row].imp_exp_size += amount;
			vdevs[n_vdevs-1].row_usage[row].util = (double)vdevs[n_vdevs-1].row_usage[row].used /
				(vdevs[n_vdevs-1].capacity/vdevs[n_vdevs-1].activerows);
			vdevs[n_vdevs-1].util = (double)vdevs[n_vdevs-1].used/vdevs[n_vdevs-1].capacity;
			rowevac_model_sort_by_row_util(vdevs, n_vdevs, row);

			/* Re-estimate mean row utilization */
			util_mean = 0;
			for (size_t i = first; i < n_vdevs; i++) {
				util_mean += vdevs[i].row_usage[row].util;
				assert(vdevs[i].row_usage[row].mode);
			}
			util_mean /= rowsdist[row];
			if (--iters == 0)
				break;
		}
		if (!iters) {
			err = EFAULT;
			goto _exit;
		}
	}
	/*
	 * Now we know number of bytes to be sent/received by each row
	 * of each VDEV. Create a jobs list.
	 */
	for (int row = 0; row < numrows; row++) {
		int width = rowsdist[row];
		/*
		 * Sort in the way where end of the array will have
		 * VDEVs which aren't row members
		 */
		qsort_r((void*)vdevs, n_vdevs, sizeof(struct vdev_mod),
			vdev_row_sort_ena_cb, &row);
		/* Then sort according to import/export size */
		qsort_r((void*)vdevs, width, sizeof(struct vdev_mod),
			vdev_row_sort_impexp_cb, &row);

		do {
			/* Pick a VDEV with the biggest amount of bytes to transfer
			 * and send them to a VDEV with the biggest demand
			 */
			int64_t amount = vdevs[width-1].row_usage[row].imp_exp_size;

			if (-vdevs[0].row_usage[row].imp_exp_size < amount)
				amount = -vdevs[0].row_usage[row].imp_exp_size;

			/*
			 * Append an evacuation command if it has a reasonable
			 * amount of data to send
			 * */
			if (amount >= (1024*1024)) {
				struct evac_list* e = je_calloc(1, sizeof(*e));
				if (!e) {
					err = -ENOMEM;
					goto _exit;
				}
				QUEUE_INIT(&e->item);
				e->e.src_vdev = vdevs[width-1].id;
				e->e.dest_vdev = vdevs[0].id;
				e->e.row = row;
				e->e.amount = amount / (1024UL*1024UL);
				e->e.flags = EVAC_FLAG_DONT_EXCLUDE_SRC | EVAC_FLAG_AMOUNT_ABS;
				make_job_id(&e->e);
				QUEUE_INSERT_TAIL(jobs, &e->item);
			}
			/* Update the model */
			vdevs[width-1].row_usage[row].imp_exp_size -= amount;
			vdevs[0].row_usage[row].imp_exp_size += amount;
			/*
			 * Re-sort imp/exp and keep doing transfers as long as
			 * there are data to send
			 **/
			qsort_r((void*)vdevs, width, sizeof(struct vdev_mod),
				vdev_row_sort_impexp_cb, &row);
		} while (vdevs[width-1].row_usage[row].imp_exp_size ||
			vdevs[0].row_usage[row].imp_exp_size);
	}

	if (!QUEUE_EMPTY(jobs)) {
		printf("Utilization after optimization:\n");
		qsort(vdevs, n_vdevs, sizeof(struct vdev_mod), vdev_mod_sort_util);
		rowevac_model_deviation(vdevs, n_vdevs, numrows);
	}
_exit:
	for (size_t i = 0; i < n_vdevs; i++)
		je_free(vdevs[i].row_usage);
	je_free(vdevs);
	return err;
}

static int
is_the_same_domain(const struct flexhash* fh, uint128_t* src, uint128_t* dst,
	int fd_policy) {
	int rc = 0;
	struct lvdev* lvs = NULL;
	struct lvdev* lvd = NULL;

	lvs = vdevstore_get_lvdev(fh->vdevstore, src);
	lvd = vdevstore_get_lvdev(fh->vdevstore, dst);

	switch(fd_policy) {
	case FD_ANY_FIRST:
		rc = uint128_cmp(src, dst) == 0;
		break;

	case FD_SERVER:
		rc = lvs->server == lvd->server;
		break;


	case FD_ZONE:
		rc = lvs->server->zone == lvd->server->zone;
		break;

	default:
		rc = -1;
	}
	return rc;
}


static int
evaq_stat_update()
{
	struct evac_stat* entry = NULL;
	QUEUE* q = NULL;
	int row;
	uint128_t src, tgt;
	QUEUE resp = QUEUE_INIT_STATIC(resp);
	int err = auditd_stats_query(AUDITD_EVAC_QUERY, &resp);
	if (err) {
		fprintf(stderr, "auditd stats query error: %d (%s)\n", err, strerror(err));
		return err;
	}
	while (!QUEUE_EMPTY(&resp)) {
		q = QUEUE_HEAD(&resp);
		struct auditd_query_resp* e = QUEUE_DATA(q, struct auditd_query_resp, item);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
		char* p = e->entry + strlen(AUDITD_EVAC_QUERY)+1;
		char* save = NULL;
		char* str = strtok_r(p, ".", &save);
		assert(str);
		/* JobID */
		uint64_t jid = strtoll(str, NULL, 16);
		str = strtok_r(NULL, ".", &save);
		/* Skip server ID */
		str = strtok_r(NULL, ".", &save);
		assert(str);
		uint128_fromhex(str, UINT128_STR_BYTES, &src);
		str = strtok_r(NULL, ".", &save);
		assert(str);
		uint128_fromhex(str, UINT128_STR_BYTES, &tgt);
		str = strtok_r(NULL, ".", &save);
		assert(str);
		row = strtol(str, NULL ,10);
		/* Parse values */
		char* param = strtok_r(NULL, "|", &save);
		char* val = strtok_r(NULL, "|", &save);
		char* ts = strtok_r(NULL, "|", &save);
		/* Getting the timestamp and filtering out old messages */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint64_t t =  strtoll(ts, NULL ,10);
		if (t + AUDITD_EVAC_TIMEOUT < (uint64_t)tv.tv_sec)
			continue;
		/* Looking for the entry */
		pthread_mutex_lock(&ht_lock);
		HASH_FIND(hh,evac_ht,&jid,sizeof(jid),entry);
		if(!entry) {
			entry = je_malloc(sizeof(*entry));
			entry->e.id = jid;
			entry->e.src_vdev = src;
			entry->e.dest_vdev = tgt;
			entry->e.row = row;
			HASH_ADD(hh,evac_ht,e.id,sizeof(jid),entry);
		}
		pthread_mutex_unlock(&ht_lock);
		assert(entry);

		if (!strncmp(param, "total", 5))
			entry->total = strtoll(val, NULL ,10);
		else if (!strncmp(param, "evacuated",9))
			entry->evacuated = strtoll(val, NULL ,10);
		else if (!strncmp(param, "state",5)) {
			entry->status = strtoll(val, NULL ,10);
			if (entry->status >= ES_TOTAL) {
				entry->status = ES_FAILED;
				fprintf(stderr, "Unknown evacuation status ID %d\n",
					entry->status);
			}
		} else
			fprintf(stderr, "Unknown metric %s\n", str);
		je_free(e->entry);
		je_free(e);
	}
	return 0;
}

static int
send_evacuation_request(ccow_t tc, uint8_t opcode, const struct evac_entry* e) {

	struct rowevac_cmd evac_cmd;
	evac_cmd.dest_vdev = e->dest_vdev;
	evac_cmd.src_vdev = e->src_vdev;
	evac_cmd.row = e->row;
	evac_cmd.amount = e->amount;
	evac_cmd.flags = e->flags;
	evac_cmd.opcode = opcode;
	evac_cmd.id = e->id;

	ccow_completion_t c;
	int err = ccow_create_completion(tc, NULL, NULL, 1, &c);
	if (err) {
		fprintf(stderr, "\nERROR: ccow_create_completion %d\n", err);
		return err;
	}
	err = ccow_rowevac_request(tc, c, &evac_cmd);
	if (err) {
		fprintf(stderr, "\nERROR: cow_rowevac_request returned %d\n", err);
	} else {
		err = ccow_wait(c, -1);
		if (err) {
			fprintf(stderr, "\nccow_wait returned: %d\n", err);
		} else if (evac_cmd.status) {
			err = evac_cmd.status;
			switch (err) {
			case -ETXTBSY:
				fprintf(stderr, "ERROR: cannot sumbmit the job in a split\n");
				break;

			case -ENODEV:
				fprintf(stderr, "ERROR: the server couldn't find the target device in a FH\n");
				break;

			case -EBUSY:
				fprintf(stderr, "ERROR: the source VDEV has a job in progress for row %d\n", evac_cmd.row);
				break;

			case -EFAULT:
				fprintf(stderr, "ERROR: the target VDEV has couldn't join row %d\n", evac_cmd.row);
				break;

			case -EROFS:
				fprintf(stderr, "ERROR: the source VDEV status doesn't "
					"allow to start evacuation job for row %d\n",
					evac_cmd.row);
				break;


			case -EMLINK:
			case -EINVAL:
				fprintf(stderr, "ERROR: the source VDEV is unavailable at the moment\n");
				break;

			default:
				fprintf(stderr, "ERROR: couldn't submit a job: %d\n", err);
				break;
			}
		}
	}
	return err;
}

static void
dump_jobs() {
	struct evac_stat* e, *tmp;
	int count = 0;
	char src_vdev_str[UINT128_STR_BYTES];
	char tgt_vdev_str[UINT128_STR_BYTES];
	char jid_str[UINT128_STR_BYTES];

	if (!HASH_COUNT(evac_ht)) {
		printf("No jobs found\n");
		return;
	}

	printf("\n%s\n","        ID                    SRC                     "
		"           DEST                 ROW      STATUS    EVACUATED  "
		" TOTAL   PROGRESS,%");
	pthread_mutex_lock(&ht_lock);
	HASH_ITER(hh, evac_ht, e, tmp) {
		uint128_dump(&e->e.src_vdev, src_vdev_str, UINT128_STR_BYTES);
		uint128_dump(&e->e.dest_vdev, tgt_vdev_str, UINT128_STR_BYTES);
		float progress = e->total ? e->evacuated*100.0/e->total : 0;
		printf(" %016lx %s %s %4d  %11s %10lu %10lu  %7.3f  \n",
			e->e.id, src_vdev_str, tgt_vdev_str, e->e.row,
			evac_status_str[e->status], e->evacuated, e->total,
			progress);
	}
	pthread_mutex_unlock(&ht_lock);
	printf("\n");
}

static void
show_help() {
	printf("\nUsage: evactool [-l | -e | -m | -c | -r | -p]\n\n");
	printf("    --list         | -l       list of jobs which are in progress\n");
	printf("    --interval=<N> | -i <N>   refresh jobs every N sec, to be used with --list\n");
	printf("    --evacuate     | -e       move whole row from source to target\n");
	printf("    --move         | -m       move specified amount of row's data from source to target\n");
	printf("    --cancel <ID>  | -c  <ID> cancel an evacuation job by its ID.\n");
	printf("    --propose      | -p <FID> propose evacuation job list for a failure domain <FID>\n");
	printf("    --threshold    | -T <THD> max. allowed irregularity of row utilization, %%\n");
	printf("    --submit       | -S       submit a proposed job list automatically, use with -p\n");
	printf("    --target <ID>  | -t <ID>  use VDEV <ID> as a target\n");
	printf("    --source <ID>  | -t <ID>  use VDEV <ID> as a source\n");
	printf("    --row=<N>      | -R <N>   evacuate the row <N> from source to target\n");
	printf("    --amount=<VAL> | -a <VAL> amount of data to be moved. Format xx%% or xxM\n");
	printf("    --keep-src     | -k       do NOT exclude the source VDEV from the row when job is done\n");
	/* Resume isn't required at the moment */
#if 0
	printf("    --resume <ID>  | -r <ID>  resume execution of a suspended job\n");
#endif
}
int
main (int argc, char** argv) {
	int option_index = 0;
	int aux = 0;
	uint128_t source_vdev = uint128_null;
	uint128_t target_vdev = uint128_null;
	uint128_t fd_id = uint128_null;
	char* propose_arg = NULL;
	int rowid = -1;
	int list = 0;
	int8_t cmd = -1;
	int repeat_sec = 0;
	uint64_t flags = 0;
	int64_t amount = 0;
	int64_t jid = 0;
	int submit_job_list = 0;
	double row_deviation_threshold = 5.0;
	static struct option long_options[] = {
		{"help", 0, 0, 'h' },
		{"source", required_argument, 0, 's' },
		{"target", required_argument, 0, 't' },
		{"row", required_argument, 0, 'R' },
		{"resume", required_argument, 0, 'r' },
		{"evacuate", 0, 0, 'e' },
		{"move", 0, 0, 'm' },
		{"amount", required_argument, 0, 'a'},
		{"keep-src", 0, 0, 'k'},
		{"submit", 0, 0, 'S'},
		{"cancel", required_argument, 0, 'c' },
		{"interval", required_argument, 0, 'i' },
		{"propose", required_argument, 0, 'p' },
		{"threshold", required_argument, 0, 'T' },
		{"list", 0, 0, 'l' },
		{0, 0, 0, 0 }
	};
	srand(time(NULL));
	while (1) {
		char c = getopt_long(argc, argv, "hs:t:R:ec:li:p:a:kmST:r:",long_options, &option_index);
		if (c < 0)
			break;
		char* tmp_optarg;
		switch (c) {
			case 'a':
				amount = strtoll(optarg, NULL, 10);
				if (amount < 0) {
					fprintf(stderr, "ERROR: the amount isn't a number: %s", optarg);
					exit(-1);
				}
				if (strstr(optarg, "%")) {
					if (amount > 100 || amount == 0) {
						fprintf(stderr, "ERROR: the amount has to be in range 1%%...100%%");
						exit(-2);
					}
				} else if (!strstr(optarg, "M")) {
					fprintf(stderr, "ERROR: the amount format has to be either %ld%% or %ldM", amount, amount);
					exit(-2);
				} else {
					flags |= EVAC_FLAG_AMOUNT_ABS;
				}
				break;

			case 'S':
				submit_job_list = 1;
				break;

			case 'k':
				flags |= EVAC_FLAG_DONT_EXCLUDE_SRC;
				break;

			case 'h':
				show_help();
				exit(0);
				break;

			case 't':
				uint128_fromhex(optarg, UINT128_STR_BYTES, &target_vdev);
				break;

			case 's':
				uint128_fromhex(optarg, UINT128_STR_BYTES, &source_vdev);
				break;

			case 'R':
				rowid = strtol(optarg, NULL, 10);
				break;

			case 'e':
				cmd = EVAC_OP_START;
				flags |= EVAC_FLAG_EVACUATE;
				break;

			case 'T':
				row_deviation_threshold = strtof(optarg, NULL);
				if (row_deviation_threshold < 0.1 || row_deviation_threshold > 100.0) {
					fprintf(stderr, "ERROR: row standard deviation must be in range 0.1 - 100.0\n");
					return -2;
				}
				break;

			case 'm':
				cmd = EVAC_OP_START;
				break;

			case 'c':
				cmd = EVAC_OP_CANCEL;
				jid = strtoll(optarg, NULL, 16);
				if (jid < 0) {
					fprintf(stderr, "ERROR: invalid job ID format %s\n", optarg);
					return -1;
				}
				break;

			case 'r':
				cmd = EVAC_OP_RESUME;
				jid = strtoll(optarg, NULL, 16);
				if (jid < 0) {
					fprintf(stderr, "ERROR: invalid job ID format %s\n", optarg);
					return -1;
				}
			break;

			case 'i':
				repeat_sec = strtol(optarg, NULL, 10);
				break;

			case 'l':
				list = 1;
				break;

			case 'p':
				propose_arg = je_strdup(optarg);
				break;

			default:
				fprintf(stderr, "ERROR: unknown argument %c\n", c);
				show_help();
				exit(-1);
				break;
		}
	}

	signal(SIGPIPE, SIG_IGN);// Ignore SIG_IGN
	signal(SIGHUP, signal_handler);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGABRT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);
	signal(SIGINT, signal_handler);


	ccow_t tc = NULL;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: cannot open ccow.json: %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	char *buf = je_calloc(1, 16384);
	assert(buf);
	if (read(fd, buf, 16383) < 0) {
		fprintf(stderr, "ERROR: ccow.json I/O error: %d (%s)\n", errno, strerror(errno));
		return -2;
	}
	close(fd);
	int err = ccow_admin_init(buf, "", 1, &tc);
	je_free(buf);
	if (err) {
		fprintf(stderr, "tenant init error: %d\n", err);
		return -3;
	}
	if (propose_arg) {
		switch (tc->failure_domain) {
			case FD_SERVER:
			case FD_ANY_FIRST:
				uint128_fromhex(propose_arg, UINT128_STR_BYTES, &fd_id);
				break;

			case FD_ZONE:
				fd_id.l = strtoll(propose_arg, NULL, 10);
				break;

			default:
				/* Unsupported failure domain policy */
				assert(0);
				break;
		}
		QUEUE jobs = QUEUE_INIT_STATIC(jobs);
		err = propose_jobs(tc, &fd_id, row_deviation_threshold, &jobs);
		if (err) {
			if (err == -EINVAL)
				fprintf(stderr, "ERROR: unknown failure domain ID %s\n",
					propose_arg);
			return err;
		}
		else if (QUEUE_EMPTY(&jobs)) {
			printf("The failure domain doesn't "
				"require rebalancing.\n");
			return 0;
		}

		QUEUE* item;
		int count = 0;
		printf("Proposed jobs:\n");
		while (!QUEUE_EMPTY(&jobs)) {
			item = QUEUE_HEAD(&jobs);
			struct evac_list* p = QUEUE_DATA(item, struct evac_list, item);
			assert(p);
			QUEUE_REMOVE(&p->item);
			QUEUE_INIT(&p->item);
			printf("%lx: %016lX%016lX -> %016lX%016lX ROW %d %luMB\n",
				p->e.id, p->e.src_vdev.u, p->e.src_vdev.l,
				p->e.dest_vdev.u, p->e.dest_vdev.l,
				p->e.row, p->e.amount);
			if (submit_job_list) {
				err = send_evacuation_request(tc, EVAC_OP_START, &p->e);
				if (err)
					break;
			}
			je_free(p);
			count++;
		}
		return err;
	}


	if (cmd == EVAC_OP_START) {
		/* Verify parameters */
		if (rowid < 0 || rowid >= CLIENT_FLEXHASH->numrows) {
			fprintf(stderr, "ERROR: the rowID has to be in range 0..%d\n",
				CLIENT_FLEXHASH->numrows - 1);
			err = -4;
			goto _term;
		}
		if (!uint128_cmp(&target_vdev, &uint128_null)) {
			fprintf(stderr, "ERROR: the target VDEV ID isn't set\n");
			err = -5;
			goto _term;
		}
		err = flexhash_getvdev_index(CLIENT_FLEXHASH, &target_vdev);
		if (err < 0) {
			fprintf(stderr, "ERROR: the target VDEV ID %016lX%016lX "
				"not found\n", target_vdev.u, target_vdev.l);
			err = -5;
			goto _term;
		}
		if (!uint128_cmp(&source_vdev, &uint128_null)) {
			fprintf(stderr, "ERROR: the source VDEV ID isn't set\n");
			err = -5;
			goto _term;
		}
		err = flexhash_getvdev_index(CLIENT_FLEXHASH, &source_vdev);
		if (err < 0) {
			fprintf(stderr, "ERROR: the source VDEV ID %016lX%016lX "
				"not found\n", source_vdev.u, source_vdev.l);
			err = -5;
			goto _term;
		}
		err = flexhash_is_rowmember_fhrow(CLIENT_FLEXHASH, &source_vdev,
			rowid);
		if (!err) {
			fprintf(stderr, "ERROR: the source VDEV ID %016lX%016lX "
				"isn't a member of the row %d\n",
				source_vdev.u, source_vdev.l, rowid);
			err = -5;
			goto _term;
		}
	}
	/* Start statistic gathering */
	evaq_stat_update();
	int njobs = HASH_COUNT(evac_ht);
	if (list) {
		int count = repeat_sec*10;
		int now = 0;
		if (!repeat_sec)
			g_term = 1;
		do {
			if (!now) {
				evaq_stat_update();
				dump_jobs();
				now = count;
			}
			if (repeat_sec) {
				usleep(100000);
				now--;
			}
		} while (!g_term);
		goto _term;
	} else if (cmd == EVAC_OP_START) {
		int cross_domain = !is_the_same_domain((struct flexhash*)CLIENT_FLEXHASH, &source_vdev,
			&target_vdev, tc->failure_domain);
		assert(cross_domain >= 0);
		if (cross_domain) {
			fprintf(stderr, "ERROR: the cross-domain evacuation isn't supported at the moment\n");
			err = -5;
			goto _term;

		}

		struct evac_entry job = {
			.src_vdev = source_vdev,
			.dest_vdev = target_vdev,
			.row = rowid,
			.amount = amount,
			.flags = flags,
		};
		if (cmd == EVAC_OP_CANCEL)
			job.id = jid;
		else
			make_job_id(&job);

		err = send_evacuation_request(tc, cmd, &job);
		if (!err)
			printf("Evacuation job %016lx has been submitted\n", job.id);
	} else if (cmd == EVAC_OP_CANCEL || cmd == EVAC_OP_RESUME) {
		if (cmd == EVAC_OP_RESUME && !jid) {
			fprintf(stderr, "ERROR: jobID isn't specified\n");
		}
		/* Looking for a job with the specified job ID */
		struct evac_stat* e = NULL, *tmp = NULL;
		struct evac_entry je = {.id = 0};
		pthread_mutex_lock(&ht_lock);
		HASH_ITER(hh, evac_ht, e, tmp) {
			if (e->e.id == (uint64_t)jid) {
				je = e->e;
				break;
			}
		}
		pthread_mutex_unlock(&ht_lock);
		if (je.id == 0 && cmd == EVAC_OP_RESUME) {
			fprintf(stderr, "ERROR: Cannot resume job %lx: not found\n", jid);
			err = -3;
			goto _term;
		} else if (je.id) {
			err = send_evacuation_request(tc, cmd, &je);
			if (err)
				goto _term;
		} else if (cmd == EVAC_OP_CANCEL && je.id == 0 && jid != 0) {
			fprintf(stderr, "ERROR: Cannot cancel job %lx: not found\n", jid);
			err = -5;
			goto _term;
		} else {
			/* Cancel all */
			struct evac_stat* e = NULL, *tmp = NULL;
			pthread_mutex_lock(&ht_lock);
			HASH_ITER(hh, evac_ht, e, tmp) {
				if (e->status == ES_AWAITING ||
					e->status == ES_IN_PROGRESS ||
					e->status == ES_SUSPENDED) {
					err = send_evacuation_request(tc, cmd, &e->e);
					if (err)
						break;
				}
			}
			pthread_mutex_unlock(&ht_lock);
		}
	} else {
		fprintf(stderr, "ERROR: an unknown or unspecified command!\n");
	}
_term:
	ccow_tenant_term(tc);
	if (evac_ht) {
		struct evac_stat* e, *tmp;
		pthread_mutex_lock(&ht_lock);
		HASH_ITER(hh, evac_ht, e, tmp) {
			HASH_DEL(evac_ht, e);
			je_free(e);
		}
		pthread_mutex_unlock(&ht_lock);
	}
	return err;
}

