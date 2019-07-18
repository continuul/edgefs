provider blob {
	probe reptrans_get_blob(char* dev_name, int ttag, int hash_type, char* chid, int rc, int duration);
	probe reptrans_put_blob(char* dev_name, int ttag, int hash_type, char* chid, int compute, int rc, int duration);
	probe reptrans_put_blob_with_attr(char* dev_name, int ttag, int hash_type, char* chid, int compute, int attr, int rc, int duration);
	probe reptrans_get_blob_ts(char* dev_name, int ttag,int hash_type, char* chid, uint64_t ts, int rc, int duration);
	probe reptrans_set_blob_ts(char* dev_name, int ttag, int hash_type, char* chid, uint64_t ts, int rc, int duration);
	probe reptrans_get_blob_verify(char* dev, int ttag, int hash_type, char* chid, int rc, int duration);
	probe reptrans_get_blobs(char* dev, int ttag, int hash_type, char* chid, int max_num, int rc, int duration);
	probe reptrans_delete_blob(char* dev, int ttag, int hash_type, char* chid, int rc, int duration);
	probe reptrans_delete_blob_filtered(char *dev, int ttag, int hash_type, char* chid, int rc, int duration);
	probe reptrans_blob_stat(char* dev, int ttag, int hash_type, char* chid, u64_t blob_size, int rc, int duration);
	probe reptrans_blob_query(char* dev, int ttag, int hash_type, char* key, int rc, int duration);
}

provider bg {
	probe done_ibatch(char* dev_name, u64 duration, u64 chunk_counter, u64 n_verified, u64 n_propagated, u64 n_processed, u64 bg_delal_avg, u64 n_skipped);
	probe done_verification(char* dev_name, u64 duration, u64 chunk_counter, u64 n_batches_sent, u64 n_bytes_sent, u64 n_queued, u64 verify_delay, u64 n_vbrs_veified);
	probe done_replication(char* dev_name, u64 duration, u64 chunk_counter, u64, u64, u64, u64, u64);
	probe done_sr(char* dev_name, u64 duration, u64 chunk_counter, u64 ngcount_delay, u64 n_chunks_removed, u64 n_replication_scheduled, u64 r_erc_restored, u64);
	probe done_gc(char* dev_name, u64 duration, u64 chunk_counter, u64 n_garbage_chunks, u64 n_version_purged, u64, u64, u64);
	probe done_scrub(char* dev_name, u64 duration, u64 chunk_counter, u64 n_lost_chuks, u64 n_corrupted_manifests, u64 n_recovered_chunks, u64 n_recovered_manifests);
	probe done_ecenc(char* dev_name, u64 duration, u64 chunk_counter, u64 n_skipped_manifests, u64, u64, u64, u64);
}
