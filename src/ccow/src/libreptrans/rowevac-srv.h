/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 */
#ifndef __ROW_USAGE__
#define __ROW_USAGE__

#ifdef	__cplusplus
extern "C" {
#endif

#include <uv.h>
#include "ccowutil.h"
#include "hashtable.h"
#include "replicast.h"

struct reptrans;
struct repdev;
struct bg_job_entry;


int bg_rowevac_init(struct bg_job_entry* job, void** pdata);
void bg_rowevac_done(struct bg_job_entry* job, void* data);
void bg_rowevac_work(struct bg_job_entry *job, void* data);

int
rowevac_request_init(struct replicast *robj, struct repctx *ctx,
	struct state *state);

int
rowevac_add_job(struct repdev* dev, int numrows, uint128_t *src_vdevid,
	uint128_t *tgt_vdevid, int row, uint64_t flags, uint64_t amount);
void
rowevac_auditc_notify(struct repdev* dev);

int
rowevac_is_in_progress(struct repdev* dev, int rowid);

int
rowevac_join_target(const uint128_t* tgt_vdev, uint16_t row);


/**
 * To be called when FH changed in order to resume waiting jobs
 */
void
rowevac_try_resume(struct repdev* dev);

#ifdef	__cplusplus
}
#endif

#endif /* __ROW_USAGE__ */
