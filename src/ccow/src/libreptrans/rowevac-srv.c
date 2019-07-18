#include "reptrans.h"
#include "reptrans-data.h"
#include "reptrans_bg_sched.h"
#include "flexhash.h"
#include "ccowd-impl.h"
#include "../include/ccowutil.h"
#include "erasure-coding.h"
#include "rowevac.h"
#include "rowevac-srv.h"

#define FH_REBUILD_WAIT_SEC	30

static int
rowevac_ro_control(struct repdev* dev, int inc) {
	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	int rc = 0;
	if (inc)
		atomic_inc64(&row_xfer->ro_ref_count);
	else
		atomic_dec64(&row_xfer->ro_ref_count);
	uint64_t val = atomic_get_uint64(&row_xfer->ro_ref_count);
	assert(val < 1024);
	int status = reptrans_dev_get_status(dev);
	if (val) {
		if (status == REPDEV_STATUS_ALIVE ||
			status == REPDEV_STATUS_READONLY_DATA ||
			status == REPDEV_STATUS_READONLY_FULL)
			reptrans_dev_set_status(dev, REPDEV_STATUS_READONLY_ROWEVAC);
		else if (status != REPDEV_STATUS_READONLY_ROWEVAC)
			rc = -EPERM;
	} else {
		if (status == REPDEV_STATUS_READONLY_ROWEVAC)
			reptrans_dev_set_status(dev, REPDEV_STATUS_ALIVE);
		else if (status != REPDEV_STATUS_UNAVAILABLE &&
			status != REPDEV_STATUS_READONLY_FAULT)
			rc = -EPERM;
	}
	return rc;
}

int
rowevac_is_in_progress(struct repdev* dev, int rowid) {
	if (rowid >= SERVER_FLEXHASH->numrows)
		return -EINVAL;
	return dev->rowusage_list.jobs[rowid] && dev->rowusage_list.jobs[rowid]->state != ES_NONE;
}


static void
rowevac_auditc_notify_row(struct repdev* dev, int row) {
	if (!dev->rowusage_list.jobs[row] || dev->rowusage_list.jobs[row]->state == ES_NONE)
		return;
	size_t total = 0, moved = 0;
	total = dev->rowusage_list.jobs[row]->amount/(1024UL*1024UL);
	moved = dev->rowusage_list.jobs[row]->moved_amount/(1024UL*1024UL);
	uint128_t tgt = dev->rowusage_list.jobs[row]->vdev_id;
	int state = dev->rowusage_list.jobs[row]->state;
	uint64_t id = dev->rowusage_list.jobs[row]->id;
	auditc_low_obj_rowevac(gauge,"reptrans.rowevac_job",
		id, &dev->vdevid, &tgt, row, total, moved, state);
}

void
rowevac_auditc_notify(struct repdev* dev) {
	for (int i = 0; i < SERVER_FLEXHASH->numrows; i++) {
		if (dev->rowusage_list.jobs[i] && dev->rowusage_list.jobs[i]->state != ES_NONE) {
			uv_rwlock_rdlock(&dev->rowusage_list.lock);
			rowevac_auditc_notify_row(dev, i);
			uv_rwlock_rdunlock(&dev->rowusage_list.lock);
		}
	}
	/*Also traverse the pending queue and notify */
	uv_rwlock_rdlock(&dev->rowusage_list.lock);
	QUEUE* item;
	QUEUE_FOREACH(item, &dev->rowusage_list.queue) {
		evac_job_t* job = QUEUE_DATA(item, evac_job_t, item);
		if (job->state != ES_AWAITING)
			continue;
		int state = job->state;
		uint128_t tgt = job->vdev_id;
		int row = job->row;
		uint64_t id = job->id;
		uint64_t total = job->amount/(1024UL*1024UL);
		auditc_low_obj_rowevac(gauge,"reptrans.rowevac_job",
			id, &dev->vdevid, &tgt, row, total, 0, state);
	}
	uv_rwlock_rdunlock(&dev->rowusage_list.lock);
}

struct rowevac_join_target_arg {
	const uint128_t* tgt_vdev;
	uint16_t row;
};

static int
rowevac_join_target_cb(struct repdev* dev, void* arg) {
	struct rowevac_join_target_arg* e = arg;
	if (uint128_cmp(&dev->vdevid, e->tgt_vdev))
		return 0;
	SERVER_FLEXHASH_SAFE_CALL(reptrans_dev_change_membership(SERVER_FLEXHASH,
		dev, 1), FH_LOCK_READ);
	return 0;
}

int
rowevac_join_target(const uint128_t* tgt_vdev, uint16_t row) {
	struct rowevac_join_target_arg arg = {.tgt_vdev = tgt_vdev, .row = row };
	return reptrans_foreach_vdev(rowevac_join_target_cb, &arg);
}

static void
rowevac_drop_all(struct repdev* dev) {
	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	int numrows = SERVER_FLEXHASH->numrows;
	for (int row = 0; row < numrows; row++) {
		row_xfer->jobs[row] = NULL;
	}
	while (!QUEUE_EMPTY(&row_xfer->queue)) {
		QUEUE* item = QUEUE_HEAD(&row_xfer->queue);
		evac_job_t* job = QUEUE_DATA(item, evac_job_t, item);
		if ((job->state == ES_IN_PROGRESS) && (job->flags & EVAC_FLAG_EVACUATE))
			(void)rowevac_ro_control(dev, 0);
		job->state = ES_FAILED;
		QUEUE_REMOVE(item);
		log_notice(lg, "Dev(%s) the job %lx %016lX%016lX -> %016lX%016lX ROW %u has been "
			"removed", dev->name, job->id, dev->vdevid.u, dev->vdevid.l,
			job->vdev_id.u, job->vdev_id.l, job->row);
		uint64_t id = job->id;
		auditc_low_obj_rowevac(gauge,"reptrans.rowevac_job",
			id, &dev->vdevid, &job->vdev_id, job->row, 0, 0, job->state);
		je_free(job);
	}
}

static int
rowevac_schedule_jobs(struct repdev* dev) {
	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	int numrows = SERVER_FLEXHASH->numrows;
	int n_submited = 0;

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_READONLY_FORCED ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		status == REPDEV_STATUS_UNAVAILABLE) {
		log_info(lg, "Dev(%s) failing all row evacuation jobs due to VDEV state %s",
			dev->name, repdev_status_name[status]);
		rowevac_drop_all(dev);
		return -EROFS;
	}

	if (ccow_daemon->fddelta < 0) {
		log_info(lg, "Dev(%s) failing all row evacuation jobs due to split level %d",
			dev->name, ccow_daemon->fddelta);
		rowevac_drop_all(dev);
		return -ETXTBSY;
	}
	for (int row = 0; row < numrows; row++) {
		/* check finished/failed/canceled jobs */
		if (row_xfer->jobs[row]) {
			int state = row_xfer->jobs[row]->state;
			if (state == ES_SUCCESS || state == ES_FAILED || state == ES_CANCELED) {
				if (row_xfer->jobs[row]->state == ES_CANCELED)
					log_notice(lg, "Dev(%s) an active job %016lX%016lX -> %016lX%016lX ROW %u has been "
						"canceled by user", dev->name, dev->vdevid.u, dev->vdevid.l,
						row_xfer->jobs[row]->vdev_id.u, row_xfer->jobs[row]->vdev_id.l,
						row_xfer->jobs[row]->row);

				/* notify auditc */
				rowevac_auditc_notify_row(dev, row);
				QUEUE_REMOVE(&row_xfer->jobs[row]->item);
				je_free(row_xfer->jobs[row]);
				row_xfer->jobs[row] = NULL;
			}
		}

		if (!row_xfer->jobs[row]) {
			QUEUE* item;
			QUEUE_FOREACH(item, &row_xfer->queue) {
				evac_job_t* job = QUEUE_DATA(item, evac_job_t, item);
				if (job->row != row)
					continue;

				/* Don't activate a job is the tgt isn't ready to accept data */
				ccowd_fhready_lock(FH_LOCK_READ);
				struct lvdev* lv = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore,
					&job->vdev_id);
				if (lv && lv->state != VDEV_STATE_ALIVE) {
					ccowd_fhready_unlock(FH_LOCK_READ);
					continue;
				}
				ccowd_fhready_unlock(FH_LOCK_READ);
				if (row_xfer->numrows != numrows) {
					log_warn(lg, "Changing the rowusage numrows from %d to %d",
						dev->rowusage_list.numrows, numrows);
					row_xfer->numrows = numrows;
				}

				job->evacuated = 0;
				if (job->flags & EVAC_FLAG_EVACUATE) {
					/* Set VDEV RO if we are transferring whole row */
					int err = rowevac_ro_control(dev, 1);
					if (err) {
						log_error(lg, "Dev(%s) unable to switch to RO state",
							dev->name);
						continue;
					}
				}
				/* Link a job entry with current job pointer */
				job->state = ES_IN_PROGRESS;
				row_xfer->jobs[row] = job;
				n_submited++;
				log_notice(lg, "Started a rowevac job %lX%lX -> %lX%lX row %d",
					dev->vdevid.u, dev->vdevid.l, job->vdev_id.u,  job->vdev_id.l,
					job->row);
				break;
			}
		}
	}
	if (n_submited) {
		if (bg_get_job_status(dev->bg_sched, BG_ROWUSAGE)== BG_STATUS_DONE)
			bg_force_job(dev->bg_sched, BG_ROWUSAGE);
	}

	return n_submited;
}

void
rowevac_try_resume(struct repdev* dev) {
	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	uv_rwlock_wrlock(&row_xfer->lock);
	rowevac_schedule_jobs(dev);
	uv_rwlock_wrunlock(&row_xfer->lock);
}

static int
bg_rowevac_iterate_blobs_cb(struct repdev *dev, type_tag_t ttag,
	crypto_hash_t hash_type, uint512_t *chid, uv_buf_t *chunk, void *param)
{
	char chidstr[UINT512_BYTES*2+1];

	assert(dev != NULL);

	int err;
	size_t size = 0;
	rowusage_work_t *work = param;
	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	uint128_t dest_vdev;
	struct bg_job_entry* job = work->job;
	struct vmmetadata md;
	uint512_t* rowid = chid;
	struct manifest_lock_entry* re = NULL;

	if (bg_job_wait_resume(job, 30000))
		return -EINVAL;

	uv_rwlock_wrlock(&row_xfer->lock);
	if (ccow_daemon->fddelta) {
		err = rowevac_schedule_jobs(dev);
		uv_rwlock_wrunlock(&row_xfer->lock);
		return err;
	}

	repdev_status_t status = reptrans_dev_get_status(dev);
	if (status == REPDEV_STATUS_UNAVAILABLE ||
		status == REPDEV_STATUS_READONLY_FAULT ||
		status == REPDEV_STATUS_READONLY_FORCED) {
		/*
		 * The source VDEV got unavailable or under maintenance.
		 * Drop all current/pending jobs
		 */
		err = rowevac_schedule_jobs(dev);
		uv_rwlock_wrunlock(&row_xfer->lock);
		return err;
	}

	for (int i  = 0; i < row_xfer->numrows; i++) {
		if (!row_xfer->jobs[i])
			continue;
		if (row_xfer->jobs[i]->state == ES_CANCELED)
			rowevac_schedule_jobs(dev);
	}
	uv_rwlock_wrunlock(&row_xfer->lock);

	job->chunk_counter++;

	if (ttag == TT_VERSION_MANIFEST) {
		rtbuf_t* rb = rtbuf_init_mapped(chunk, 1);
		if (!rb)
			return -EAGAIN;
		int err = replicast_get_metadata(rb, &md);
		rtbuf_destroy(rb);
		if (err) {
			log_error(lg, "VM %lX unpack error %d", chid->u.u.u, err);
			return 0;
		}
		rowid = &md.nhid;
	}
	int row = HASHROWID(rowid, SERVER_FLEXHASH);
	int job_state = -1;
	uv_rwlock_rdlock(&row_xfer->lock);
	if (row_xfer->jobs[row]) {
		job_state = row_xfer->jobs[row]->state;
		dest_vdev = row_xfer->jobs[row]->vdev_id;
	}
	uv_rwlock_rdunlock(&row_xfer->lock);
	if (job_state != ES_IN_PROGRESS) {
		/* There are no jobs for this row */
		return 0;
	}
	ccowd_fhready_lock(FH_LOCK_READ);
	struct lvdev* lv = vdevstore_get_lvdev(SERVER_FLEXHASH->vdevstore,
		&dest_vdev);
	if (!lv) {
		char vdevstr[MAX_SDEVID_STR];
		ccowd_fhready_unlock(FH_LOCK_READ);
		uint128_dump(&dest_vdev, vdevstr, MAX_SDEVID_STR);
		log_error(lg, "Target device %s disappeared from the row %d,"
			" canceling the job",vdevstr, row);
		uv_rwlock_wrlock(&row_xfer->lock);
		row_xfer->jobs[row]->state = ES_FAILED;
		uv_rwlock_wrunlock(&row_xfer->lock);
		return -EAGAIN;
	}
	if (lv->state != VDEV_STATE_ALIVE) {
		char vdevstr[MAX_SDEVID_STR];
		ccowd_fhready_unlock(FH_LOCK_READ);
		uint128_dump(&dest_vdev, vdevstr, MAX_SDEVID_STR);
		log_notice(lg, "Dev(%s) target device %s isn't ready to accepts data from row %d,"
			"moving to pending", dev->name, vdevstr, row);
		uv_rwlock_wrlock(&row_xfer->lock);
		row_xfer->jobs[row]->state = ES_AWAITING;
		row_xfer->jobs[row] = NULL;
		uv_rwlock_wrunlock(&row_xfer->lock);
		return 0;
	}
	ccowd_fhready_unlock(FH_LOCK_READ);

	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_exists(SERVER_FLEXHASH, row, &dest_vdev),
		FH_LOCK_READ);
	if (!err) {
		char vdevstr[MAX_SDEVID_STR];
		uint128_dump(&dest_vdev, vdevstr, MAX_SDEVID_STR);
		log_error(lg, "Target device %s disappeared from the row %d,"
			" canceling the job",vdevstr, row);
		uv_rwlock_wrlock(&row_xfer->lock);
		row_xfer->jobs[row]->state = ES_FAILED;
		uv_rwlock_wrunlock(&row_xfer->lock);
		return -EAGAIN;
	}
	if (ttag == TT_VERSION_MANIFEST || ttag == TT_CHUNK_MANIFEST) {
		/*
		 * before manifest relocation we have to be sure there is no
		 * encoding/recovery in progress
		 */
		int status = MANIFEST_PROCESSING;
		manifest_lock_status_t st = MANIFEST_PROCESSING;
		while ((re = reptrans_manifest_lock_or_wait(dev, chid, &st)) == NULL)
			usleep(100000);
	}
	uint512_dump(chid, chidstr, UINT512_BYTES*2+1);
	struct blob_stat bs;
	err = reptrans_blob_stat(dev, ttag, hash_type, chid, &bs);
	if (err) {
		log_warn(lg, "Dev(%s) cannot stat a blob %s type %s ht %s: %d",
			dev->name, chidstr, type_tag_name[ttag],
			hash_type_name[hash_type], err);
		work->repeat_count[row]++;
		return 0;
	} else
		size = bs.size;

	/*
	 * Got a destination VDEV, trying to relocated the chunk
	 * along with related metadata
	 * */
	uint64_t attr = RD_ATTR_COMPOUND | RD_ATTR_RETRY_FAILFAST |
		RD_ATTR_NCOMP | RD_ATTR_TARGETED;
	int opts = REPLICATE_OPTIONAL_VBR | REPLICATE_EC_VBR | REPLICATE_NO_VBR_OWERWRITE;
	err = reptrans_replicate_chunk(dev, ttag, hash_type, chid, attr,
		&dest_vdev, 1, opts);
	if (err) {
		/* Something went wrong, maybe split or server is too busy.
		 * In either case repeat an attempt later
		 */
		log_warn(lg, "Dev(%s) evacuation %s %s failed %d", dev->name,
			chidstr, type_tag_name[ttag], err);
		work->repeat_count[row]++;
		return 0;
	}
	/* now it has been moved , delete it and connected metadata locally */
	if (ttag == TT_CHUNK_PAYLOAD)
		err = reptrans_delete_blob(dev, ttag, hash_type, chid);
	else
		err = reptrans_delete_manifest(dev, ttag, hash_type, chid);
	if (err) {
		log_warn(lg, "Dev(%s) unable to delete an evacuated chunk %s ttag %s",
			dev->name, chidstr, type_tag_name[ttag]);
	}
	/*
	 * Remove VBRs (if any)
	 */
#if 1
	err = reptrans_delete_blob(dev, TT_VERIFIED_BACKREF, hash_type, chid);
	if (err && err != -ENOENT) {
		log_warn(lg, "Dev(%s) delete VBRs for %016lX ht %s rc %d",
			dev->name, chid->u.u.u, hash_type_name[hash_type], err);
	}
#else
	rtbuf_t* vbr = NULL;
	err = reptrans_get_blob(dev, TT_VERIFIED_BACKREF, hash_type, chid, &vbr);
	if (!err && vbr) {
		err = dev->__vtbl->delete_blob_value(dev, TT_VERIFIED_BACKREF,
			hash_type, chid, vbr->bufs, vbr->nbufs);
		log_debug(lg, "Dev(%s) rm %lu VBRs for %016lX ht %s rc %d",
			dev->name, vbr->nbufs, chid->u.u.u,
			hash_type_name[hash_type], err);
	}
#endif
	/* Unlock the manifest */
	if (ttag == TT_VERSION_MANIFEST || ttag == TT_CHUNK_MANIFEST) {
		assert(re);
		reptrans_manifest_unlock(dev, re, ROW_EVAC_DONE);
	}
	err = 0;
	uv_rwlock_wrlock(&row_xfer->lock);
	work->chunks_evacuated[row]++;
	row_xfer->jobs[row]->evacuated++;
	row_xfer->jobs[row]->moved_amount += size;
	if (!(row_xfer->jobs[row]->flags & EVAC_FLAG_EVACUATE) &&
		row_xfer->jobs[row]->moved_amount >= row_xfer->jobs[row]->amount)
		err = -EFBIG;
	uv_rwlock_wrunlock(&row_xfer->lock);

	log_debug(lg, "Dev(%s) moved  %s ttag %s row %d, evacuated %lu",
		dev->name, chidstr, type_tag_name[ttag],
		row, row_xfer->jobs[row]->evacuated);

	return err;
}

int
bg_rowevac_init(struct bg_job_entry *job, void **pdata)
{
	rowusage_work_t *work = je_calloc(1, sizeof(rowusage_work_t));
	if (!work)
		return -ENOMEM;

	work->dev = job->sched->dev;
	work->job = job;
	*pdata = work;

	return 0;
}

void
bg_rowevac_done(struct bg_job_entry *job, void *data)
{
	rowusage_work_t *work = data;
	assert(work != NULL);
	struct repdev *dev = work->dev;
	je_free(work);
}

void
bg_rowevac_work(struct bg_job_entry *job, void* data)
{
	rowusage_work_t *work = data;
	rowusage_xfer_t *row_xfer = &work->dev->rowusage_list;
	struct repdev *dev = work->dev;
	uint128_t *tgt_vdevid;

	assert(work != NULL);
	assert(dev != NULL);


	/* Iterate only CMs, payloads and VMs. VBRs, parity manifests, versions
	 * will be picked up by the reptrans_replicate_chunk() function if needed.
	 * Important: VMs reside in a ROW of a corresponding nameindex entry.
	 * NOTE: The row being evacuated has to be write-protected from the
	 * front IO side.
	 */
	int err;
	type_tag_t ttags[] = {TT_CHUNK_PAYLOAD, TT_CHUNK_MANIFEST, TT_VERSION_MANIFEST};
	size_t ttag_cnt = sizeof(ttags)/sizeof(ttags[0]);

_repeat:
	memset(work->repeat_count, 0, sizeof(work->repeat_count));
	memset(work->chunks_evacuated, 0, sizeof(work->chunks_evacuated));
	uint32_t flags = RD_FLUSH_FORCE | RD_FLUSH_SYNC;
	dev->rt->dev_ctl(dev, vdevCtlFlush, &flags);
	size_t n_rep_max = 10;
	for (int i = 0; i < (int) ttag_cnt; err == -EAGAIN ? i = 0 : i++) {
		err = reptrans_iterate_blobs(dev, ttags[i],
			bg_rowevac_iterate_blobs_cb, work,
			ttags[i] == TT_VERSION_MANIFEST);
		if (err) {
			if (err == -EAGAIN) {
				if (--n_rep_max)
					sleep(5);
				else
					break;
			} else
				break;
		}
	}

	if (err && err != -EFBIG)
		return;

	flags = RD_FLUSH_FORCE;
	dev->rt->dev_ctl(dev, vdevCtlFlush, &flags);

	/* Inform the leader about end of row change (data transfer) */
	int n_incompleted = 0;
	for (int row = 0; row < row_xfer->numrows; row++) {
		evac_state_t new_state = ES_SUCCESS;
		/* Ensure the row has been evacuated successfully*/
		uv_rwlock_rdlock(&row_xfer->lock);
		if (!row_xfer->jobs[row] || row_xfer->jobs[row]->state != ES_IN_PROGRESS) {
			uv_rwlock_rdunlock(&row_xfer->lock);
			continue;
		}

		/* We expect flexcount to be zero for a fully evacuated row */
		size_t n_chunks_estimated = 0;
		reptrans_estimate_row_usage(dev, row, row_xfer->numrows,
			&n_chunks_estimated);

		if (!(row_xfer->jobs[row]->flags & EVAC_FLAG_EVACUATE)) {
			/* Partial row transfer */
			if (row_xfer->jobs[row]->amount <= row_xfer->jobs[row]->moved_amount ||
				!n_chunks_estimated || !work->chunks_evacuated[row]) {
				uv_rwlock_rdunlock(&row_xfer->lock);
				goto _finish;
			}
		}

		if (work->repeat_count[row]) {
			/* Got some skipped chunks, retrying */
			uv_rwlock_rdunlock(&row_xfer->lock);
			n_incompleted++;
			continue;
		}

		if (work->chunks_evacuated[row] && n_chunks_estimated) {
			/*
			 * It seems some chunks were evacuated, but this has to be
			 * double checked since a new job could be added during
			 * an iterator run.
			 */
			uv_rwlock_rdunlock(&row_xfer->lock);
			n_incompleted++;
			continue;
		}
		uv_rwlock_rdunlock(&row_xfer->lock);
		if (n_chunks_estimated) {
			log_error(lg, "Dev(%s) the flexcount for row %u has "
				"value %lu when expected to be 0\n",
				dev->name, row, n_chunks_estimated);
			/*
			 * Workaround for a possible HC bug.
			 * We have double checked there are no data in the row,
			 * so we just clean flexcount entries.
			 */
			for (size_t i = row; i < HASHCOUNT_TAB_LENGTH; i += row_xfer->numrows) {
				dev->stats.hashcount[i] = 0;
			}
			dev->hc_flush = 1;
			reptrans_put_hashcount(dev);
		}

		/* Don't exclude this VDEV from row if the flag is set */
		if (row_xfer->jobs[row]->flags & EVAC_FLAG_DONT_EXCLUDE_SRC)
			goto _finish;

		struct sockaddr_in6 addr;
		int j;
		/* Source device should leave MC before it is removed from flexhash */
		flexhash_get_rowaddr(SERVER_FLEXHASH, row, &addr);
		char dst[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr.sin6_addr, dst, INET6_ADDRSTRLEN);
		j =  row / (row_xfer->numrows >> (ccow_daemon->if_indexes_count - 1));
		int nfound;
		SERVER_FLEXHASH_SAFE_CALL(nfound = flexhash_exists(SERVER_FLEXHASH,
						row, &dev->vdevid), FH_LOCK_READ);
		if (nfound) {
			replicast_leave(dev->robj, dst,
					ccow_daemon->if_indexes[j]);
			log_debug(lg, "Replicast object %s left multicast groups [%s]",
					dev->robj->name, dst);
		}

		if (!ccow_daemon->fddelta) {
			/* Exclude the source VDEV from the row, update FH/CP */
			clengine_notify_rowusage_change(0, &dev->vdevid,
				&row_xfer->jobs[row]->vdev_id, row, -1);
			int row_wait_count = FH_REBUILD_WAIT_SEC*10; /* 10 sec */
			do {
				if (row_wait_count < FH_REBUILD_WAIT_SEC*10)
					usleep(100000);
				SERVER_FLEXHASH_SAFE_CALL(err = flexhash_is_rowmember_fhrow(SERVER_FLEXHASH,
					&dev->vdevid, row), FH_LOCK_READ);
			} while (err && --row_wait_count);
			if (!row_wait_count) {
				new_state = ES_FAILED;
				log_error(lg, "Dev(%s) timeout while waiting for flexhash_leave row %d",
					dev->name, row);
			}
		} else {
			char str[UINT128_BYTES*2+1];
			uint128_dump(&row_xfer->jobs[row]->vdev_id, str, UINT128_BYTES*2+1);
			log_error(lg, "Dev(%s) the VDEV %s hasn't been attached to the row "
				"%d due to a split", dev->name, str, row);
		}
_finish:
		log_notice(lg, "Dev(%s) ROW %d has been evacuated to VDEV.u=%lX%lX, moved %lu chunks of total size %lu MB",
			dev->name, row, row_xfer->jobs[row]->vdev_id.u,
			row_xfer->jobs[row]->vdev_id.l, row_xfer->jobs[row]->evacuated,
			row_xfer->jobs[row]->moved_amount/(1024L*1024L));

		uv_rwlock_wrlock(&row_xfer->lock);
		if (new_state == ES_SUCCESS)
			row_xfer->jobs[row]->amount = row_xfer->jobs[row]->moved_amount;
		if (row_xfer->jobs[row]->flags & EVAC_FLAG_EVACUATE)
			rowevac_ro_control(dev, 0);
		row_xfer->jobs[row]->state = new_state;
		/* Update jobs. Restart the cycle if there are new jobs */
		if (rowevac_schedule_jobs(dev) > 0)
			n_incompleted++;
		uv_rwlock_wrunlock(&row_xfer->lock);
	}
	if (n_incompleted)
		goto _repeat;
}

/* row evacuation command processing code */

struct rowevac_srv_req {
	REQ_CLASS_FIELDS
	struct repmsg_rowevac reply;
};

static void
rowevac_srv__error(struct state *st)
{
	struct rowevac_srv_req *req = st->data;
	log_trace(lg, "st %p", st);
}

static void
rowevac_srv__term(struct state *st)
{
	struct rowevac_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	log_trace(lg, "Dev(%s) rowevac_srv__term st %p inexec %d", dev->name,
		st, req->inexec);

	assert(req->inexec >= 0);
	repctx_drop(req->ctx);

	if (req->inexec) {
		log_debug(lg, "req %p request inexec %d, cannot terminate",
		    req, req->inexec);
		return;
	}
	reptrans_dev_ctxfree_one(dev, req->ctx);
}

static void
rowevac_srv_ack__done(void *data, int err, int ctx_valid) {
	struct state *st = data;
	struct rowevac_srv_req *req = st->data;
	struct repctx *ctx = req->ctx;

	log_trace(lg, "data %p, err %d, ctx_valid %d seqid %d.%d",
	    data, err, ctx_valid, ctx->sequence_cnt, ctx->sub_sequence_cnt);

	req->inexec--;
	if (state_check(st, ST_TERM)) {
		rowevac_srv__term(st);
		return;
	}

	if (err) {
		log_error(lg, "Error %d while sending ROWEVAC ACK",
			err);
		assert(err < 0);
		state_event(st, EV_ERR);
		return;
	}
	state_event(st, EV_DONE);
}

static void
rowevac_srv_work(void* arg) {
	struct state *st = (struct state*)arg;
	struct rowevac_srv_req *req = st->data;
	struct repdev *dev = req->dev;

	rowusage_xfer_t *row_xfer = &dev->rowusage_list;
	int active_state = -1;
	uint64_t active_jid = 0;

	if (ccow_daemon->fddelta) {
		log_error(lg, "Dev(%s) Cannot start rowevac job for target VDEV"
			" %lX%lX: split level %d detected ",
			dev->name, req->reply.dest_vdev.u,
			req->reply.dest_vdev.l, ccow_daemon->fddelta);
		req->reply.status = -ETXTBSY;
		return;
	}

	uv_rwlock_wrlock(&row_xfer->lock);
	if (req->reply.opcode == EVAC_OP_START) {
		QUEUE* item;
		QUEUE_FOREACH(item, &row_xfer->queue) {
			struct evac_job* j = QUEUE_DATA(item, struct evac_job, item);
			assert(j);
			if (j->id == req->reply.id) {
				uv_rwlock_wrunlock(&row_xfer->lock);
				req->reply.status = -EEXIST;
				return;
			}
		}
		struct evac_job* job = je_calloc(1, sizeof(*job));
		if (!job) {
			req->reply.status = -ENOMEM;
			uv_rwlock_wrunlock(&row_xfer->lock);
			return;
		}
		ccowd_fhready_lock(FH_LOCK_READ);
		int numrows = SERVER_FLEXHASH->numrows;
		ccowd_fhready_unlock(FH_LOCK_READ);
		job->state = ES_AWAITING;
		job->vdev_id = req->reply.dest_vdev;
		job->flags = req->reply.flags;
		job->row = req->reply.row;
		job->id = req->reply.id;
		job->amount = reptrans_get_rowusage(dev, job->row, numrows);
		if (!(job->flags & EVAC_FLAG_EVACUATE)) {
			if (!(job->flags & EVAC_FLAG_AMOUNT_ABS)) {
				job->amount = req->reply.amount * job->amount / 100UL;
			} else
				job->amount = req->reply.amount * 1024UL*1024UL;
		}
		QUEUE_INIT(&job->item);
		QUEUE_INSERT_TAIL(&row_xfer->queue, &job->item);
	} else if (req->reply.opcode == EVAC_OP_CANCEL) {
		req->reply.status = -ENOENT;
		if (row_xfer->jobs[req->reply.row] &&
			row_xfer->jobs[req->reply.row]->id == req->reply.id) {
			/*
			 * Canceling the job. Send and auditc message and make
			 * the VDEV available
			 */
			row_xfer->jobs[req->reply.row]->state = ES_CANCELED;
			req->reply.status = 0;
		}
		/*  try to find a pending job(s) and remove */
		QUEUE* item = NULL;
		QUEUE_FOREACH(item, &row_xfer->queue) {
			struct evac_job* job = QUEUE_DATA(item, struct evac_job, item);
			assert(job);
			if (job->id == req->reply.id) {
				QUEUE_REMOVE(&job->item);
				QUEUE_INIT(&job->item);
				je_free(job);
				break;
			}
		}
		req->reply.status = 0;
		uv_rwlock_wrunlock(&row_xfer->lock);
		return;
	}
	if (row_xfer->jobs[req->reply.row]) {
		active_state = row_xfer->jobs[req->reply.row]->state;
		active_jid = row_xfer->jobs[req->reply.row]->id;
		if (active_state != ES_SUSPENDED) {
			/* there is an in-progress job for this row, postpone */
			req->reply.status = 0;
			uv_rwlock_wrunlock(&row_xfer->lock);
			return;
		}
	}
	uv_rwlock_wrunlock(&row_xfer->lock);

	if (req->reply.opcode == EVAC_OP_RESUME &&
		active_state == ES_SUSPENDED && active_jid == req->reply.id) {
		/* Resume a job */
		uv_rwlock_wrlock(&row_xfer->lock);
		row_xfer->jobs[req->reply.row]->state = ES_IN_PROGRESS;
		uv_rwlock_wrunlock(&row_xfer->lock);
		req->reply.status = 0;
		return;
	}

	/* we own the source vdev, now check the destination vdev*/
	int err = 0;
	SERVER_FLEXHASH_SAFE_CALL(err =
		vdevstore_getvdev_index_nl(SERVER_FLEXHASH->vdevstore,
		&req->reply.dest_vdev), FH_LOCK_READ);
	if (err == -ENOENT) {
		log_error(lg, "Dev(%s) Cannot submit rowevac job: target VDEV "
			"%lX%lX doesn't exist", dev->name,
			req->reply.dest_vdev.u, req->reply.dest_vdev.l);
		req->reply.status = -ENODEV;
		return;
	}


	/* If the destination isn't a row member - add it */
	SERVER_FLEXHASH_SAFE_CALL(err = flexhash_is_rowmember_fhrow(SERVER_FLEXHASH,
		&req->reply.dest_vdev, req->reply.row), FH_LOCK_READ);
	if (!err) {
		clengine_notify_rowusage_change(1, &dev->vdevid,
			&req->reply.dest_vdev, req->reply.row, -1);
		/* We expects every online node received the notification.
		 * Wait for local FH to be changed, then start evacuation or
		 * report an error.
		 */
		int row_wait_count =  FH_REBUILD_WAIT_SEC*10; /* 10 sec */
		do {
			usleep(100000);
			SERVER_FLEXHASH_SAFE_CALL(err =
				flexhash_is_rowmember_fhrow(SERVER_FLEXHASH,
				&req->reply.dest_vdev, req->reply.row),
				FH_LOCK_READ);
		} while (!err && --row_wait_count);
		if (!err) {
			log_error(lg, "Dev(%s) Timeout waiting for target VDEV "
				"%lX%lX to join the row %u", dev->name,
				req->reply.dest_vdev.u, req->reply.dest_vdev.l,
				req->reply.row);
			req->reply.status = -EFAULT;
			return;
		}
	}
	uv_rwlock_wrlock(&row_xfer->lock);
	err = rowevac_schedule_jobs(dev);
	uv_rwlock_wrunlock(&row_xfer->lock);
	req->reply.status = err >= 0 ? 0 : err;
}

static void
rowevac_srv_after_work(void* arg, int status) {
	struct state *st = (struct state*)arg;
	struct rowevac_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;


	int err = replicast_send(dev->robj, ctx, RT_ROWEVAC_ACK,
		(struct repmsg_generic *)&req->reply,
		(struct repmsg_generic *)wqe->msg,
		NULL, 0, NULL, rowevac_srv_ack__done, st,
		NULL);
	if (err) {
		req->inexec--;
		log_error(lg, "RT_ROWEVAC_ACK operation error %d on send", err);
		state_event(st, EV_ERR);
	}
}

static void
rowevac_srv__req(struct state *st) {
	struct rowevac_srv_req *req = st->data;
	struct repdev *dev = req->dev;
	struct repctx *ctx = req->ctx;
	struct repwqe *wqe = ctx->wqe_in;
	assert(wqe);
	char chidstr[UINT512_BYTES*2+1];

	struct repmsg_rowevac *msg =
		(struct repmsg_rowevac *)wqe->msg;

	log_trace(lg, "Dev(%s): rowevac_srv__req st %p, inexec %d src %lX%lX",
		dev->name, st, req->inexec, msg->src_vdev.u, msg->src_vdev.l);

	if (req->inexec) {
		state_next(st, EV_ERR);
		return;
	}

	if (uint128_cmp(&dev->vdevid, &msg->src_vdev)) {
		/* skip the request if we aren't a source VDEV */
		state_next(st, EV_DONE);
		return;
	}
	req->reply = *msg;
	req->inexec++;
	ccowtp_work_queue(dev->tp, REPTRANS_TP_PRIO_LOW, rowevac_srv_work,
		rowevac_srv_after_work, st);
}

static const struct transition trans_tbl[] = {
// FROM, EVENT, ACTION, TO, GUARD
//---------------------------------------------------------------------
{ ST_INIT, RT_ROWEVAC, rowevac_srv__req, ST_WAIT, NULL },
{ ST_WAIT, EV_DONE, NULL, ST_TERM, NULL },
{ ST_ANY, EV_ANY, rowevac_srv__error, ST_TERM, NULL }
};

int
rowevac_request_init(struct replicast *robj, struct repctx *ctx, struct state *state)
{
	log_trace(lg, "robj %p, ctx %p, state %p", robj, ctx, state);

	struct repdev* dev = robj->priv_data;
	repdev_status_t status = reptrans_dev_get_status(dev);
	if(dev->terminating || status == REPDEV_STATUS_UNAVAILABLE)
		return -ENODEV;
	struct rowevac_srv_req *req = je_calloc(1, sizeof (*req));
	if (!req)
		return -ENOMEM;
	req->dev = robj->priv_data;
	req->ctx = ctx;

	state->table = trans_tbl;
	state->cur = ST_INIT;
	state->max = sizeof(trans_tbl)/sizeof(*trans_tbl);
	state->data = req;
	state->term_cb =rowevac_srv__term;
	ctx->stat_cnt = &robj->stats.rowevac_active;
	reptrans_lock_ref(dev->robj_lock, ctx->stat_cnt);
	return 0;
}

