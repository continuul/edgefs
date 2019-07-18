##
## Copyright (c) 2015-2018 Nexenta Systems, inc.
##
## This file is part of EdgeFS Project
## (see https://github.com/Nexenta/edgefs).
##
## Licensed to the Apache Software Foundation (ASF) under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  The ASF licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
##
##   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##
bin_PROGRAMS = daemon_test client_test libcrypto_test \
            bucket_lookup_test libcompress_test librtbuf_test \
	    put_test get_test delete_test  versions_test vol_test libcmcache_test \
	    cluster_test msite_test tenant_test libhashtable_test \
	    libskiplist_test iter_test reptrans_test cmcache_test reptrans_del \
	    btree_test libbtreenam_test libbtreemap_test btree_rand_update_test stress_btreemap_test \
	    stress_btreemap_stream_test btreenam_stream_test multiobject_stress_test \
	    auditd_test talloc_test auditc_test clone_test cluster_lookup_test \
	    stress_test simple_put simple_get simple_iter pingpong \
	    stgt_test snapview_test seq_test stress_stream_io_test simple_import \
	    queue_test stream_io_error_test txid_test simple_1gb_test ccowperf_test \
	    threaded_bucket_test purge_test verify_test reptrans_standalone_test \
	    tenant_accounting io_error_test rdchk error_put_get_test \
	    blob_lookup_test liberasurecode_test cache_test ucache_test \
	    stream_io_negative_test libccowvol_test slg_test erasure_coding_test \
	    put_file delete_parity_chunk coroflex coroflex_test get_file trlog_test vmm_test \
	    paread_test object_replace_test serial_update_test cancel_test libconnbroker_test \
	    get_chids_test append_aligned_test append_unaligned_test \
        locks_api_test locks_rt_test key_cache_test \
        basic_fs_multifile_test basic_fs_ops_test basic_fs_rw_test basic_fs_parallel_rd_test \
        basic_fs_inodefetch_test basic_fs_bvt basic_fs_sharded_dir \
        rd_bloom_test simple_simple get_kv msort_test btreenam_iter_test modbit_test \
        pseudo_delete simple_wait sharded_list_test user_list_test \
        gwlru_api_test  acl_list_test ec_unencode_test bucket_list_objects \
        ccowtp_test reptrans_pattern_test fs_verify_dentry ccow_isgw_test \
        ccow_lookup_test

DISABLED=libflexhash_test flexhash_sim fhzone_test

install-exec-hook:
	cp -f reptrans_bg_test $(DESTDIR)$(bindir)/

ccow_lookup_test_SOURCES = ccow_lookup_test.c cmocka.c common.c
ccow_lookup_test_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow \
	-I$(top_srcdir)/src/libflexhash \
	-I$(top_srcdir)/src/libtrlog \
	-I$(top_srcdir)/src/libreptrans
ccow_lookup_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccow/libccow.la $(top_srcdir)/src/libccowd/libccowd.la  -luv -lcrypto $(ASAN_LIB)


ccow_isgw_test_SOURCES = ccow_isgw_test.c cmocka.c common.c
ccow_isgw_test_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow -I$(top_srcdir)/src/libflexhash
ccow_isgw_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccow/libccow.la $(top_srcdir)/src/libccowd/libccowd.la  -luv -lcrypto $(ASAN_LIB)

stgt_test_SOURCES = stgt_test.c cmocka.c common.c
stgt_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
stgt_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccow/libccow.la -luv -lcrypto $(ASAN_LIB)

auditc_test_SOURCES = auditc_test.c cmocka.c
auditc_test_CFLAGS = -I$(top_srcdir)/src/include
auditc_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lnanomsg
auditc_test_LDADD = $(top_srcdir)/src/libauditc/libauditc.la \
		    $(top_srcdir)/src/libccowutil/libccowutil.la $(ASAN_LIB)

basic_fs_multifile_test_CFLAGS =
basic_fs_multifile_test_LDFLAGS = $(AM_LDFLAGS) -lccow
basic_fs_multifile_test_SOURCES = basic_fs_multifile_test.c cmocka.c
basic_fs_multifile_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_ops_test_CFLAGS =
basic_fs_ops_test_LDFLAGS = $(AM_LDFLAGS) -lccow
basic_fs_ops_test_SOURCES = basic_fs_ops_test.c cmocka.c
basic_fs_ops_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_sharded_dir_CFLAGS =
basic_fs_sharded_dir_LDFLAGS = $(AM_LDFLAGS) -lccow
basic_fs_sharded_dir_SOURCES = basic_fs_sharded_dir.c cmocka.c
basic_fs_sharded_dir_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_rw_test_CFLAGS =
basic_fs_rw_test_LDFLAGS = $(AM_LDFLAGS) -lccow -lcrypto
basic_fs_rw_test_SOURCES = basic_fs_rw_test.c cmocka.c
basic_fs_rw_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_parallel_rd_test_CFLAGS =
basic_fs_parallel_rd_test_LDFLAGS = $(AM_LDFLAGS) -lccow -lcrypto
basic_fs_parallel_rd_test_SOURCES = basic_fs_parallel_rd_test.c cmocka.c
basic_fs_parallel_rd_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_inodefetch_test_CFLAGS =
basic_fs_inodefetch_test_LDFLAGS = $(AM_LDFLAGS) -lccow
basic_fs_inodefetch_test_SOURCES = basic_fs_inodefetch_test.c cmocka.c
basic_fs_inodefetch_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

basic_fs_bvt_CFLAGS =
basic_fs_bvt_LDFLAGS = $(AM_LDFLAGS) -lccow
basic_fs_bvt_SOURCES = basic_fs_bvt.c cmocka.c
basic_fs_bvt_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la $(ASAN_LIB)

ccowperf_test_SOURCES = ccowperf_test.c cmocka.c common.c
ccowperf_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow -lpthread
ccowperf_test_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		       -I$(top_srcdir)/src/libflexhash \
		       -I$(top_srcdir)/src/libccow 
ccowperf_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

paread_test_SOURCES = paread_test.c cmocka.c common.c
paread_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow -lpthread
paread_test_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		       -I$(top_srcdir)/src/libflexhash \
		       -I$(top_srcdir)/src/libccow 
paread_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

daemon_test_SOURCES = daemon_test.c cmocka.c
daemon_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lpthread
daemon_test_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		     -I$(top_srcdir)/src/libreptrans
daemon_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la

erasure_coding_test_SOURCES = erasure_coding_test.c cmocka.c common.c
erasure_coding_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lpthread
erasure_coding_test_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow \
		     -I$(top_srcdir)/src/libreptrans -I$(top_srcdir)/src/libflexhash \
		     -I$(top_srcdir)/src/libccowd -I$(top_srcdir)/src/libclengine \
		     -I$(top_srcdir)/src/libtrlog
erasure_coding_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la \
		    $(top_srcdir)/src/libccow/libccow.la $(ASAN_LIB)

delete_parity_chunk_SOURCES = delete_parity_chunk.c
delete_parity_chunk_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lpthread
delete_parity_chunk_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow \
		     -I$(top_srcdir)/src/libreptrans -I$(top_srcdir)/src/libflexhash \
		     -I$(top_srcdir)/src/libtrlog \
		     -I$(top_srcdir)/src/libccowd -I$(top_srcdir)/src/libclengine
delete_parity_chunk_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la \
		    $(top_srcdir)/src/libccow/libccow.la $(ASAN_LIB)

auditd_test_SOURCES = auditd_test.c cmocka.c
auditd_test_CFLAGS =
auditd_test_LDADD = $(top_srcdir)/src/libauditd/libauditd.la $(ASAN_LIB)

libcrypto_test_SOURCES = libcrypto_test.c cmocka.c
libcrypto_test_CFLAGS = -I$(top_srcdir)/src/libcrypto \
                     -I$(top_srcdir)/src/libcrypto/libblake2 \
                     -I$(top_srcdir)/src/libcrypto/libedonr \
                     -I$(top_srcdir)/src/libcrypto/libxxhash \
                     -I$(top_srcdir)/src/libreplicast
libcrypto_test_LDADD = $(top_srcdir)/src/libcrypto/libcrypto.la \
                      $(top_srcdir)/src/libccowutil/libccowutil.la \
                      $(top_srcdir)/src/libcompress/libcompress.la \
                      -lcrypto -luv -lcrypto -lm $(ASAN_LIB)

libcompress_test_SOURCES = libcompress_test.c cmocka.c
libcompress_test_CFLAGS = -I$(top_srcdir)/src/libcompress
libcompress_test_LDADD = $(top_srcdir)/src/libcompress/libcompress.la \
			 -luv -lcrypto $(ASAN_LIB)

#libflexhash_test_SOURCES = libflexhash_test.c cmocka.c
#libflexhash_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
#			  -I$(top_srcdir)/src/libclengine \
#			  -I$(top_srcdir)/src/libreplicast \
#			  -I$(top_srcdir)/src/libreptrans \
#			  -I$(top_srcdir)/src/libtrlog \
#			  -I$(top_srcdir)/src/libccowd
#libflexhash_test_LDFLAGS = $(AM_LDFLAGS)  -lm -luv -lcfg -lquorum -lcpg -llmdb -lnanomsg \
#				-lcrypto $(ASAN_LIB)
#
#libflexhash_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
#			 $(top_srcdir)/src/libflexhash/libflexhash.la \
#			 $(top_srcdir)/src/libclengine/libclengine.la \
#			 $(top_srcdir)/src/libccowd/libccowd.la \
#			$(top_builddir)/../../lib/libcorosync_common.la \
#			$(top_builddir)/../../lib/libcpg.la \
#			$(top_builddir)/../../lib/libquorum.la \
#			$(top_builddir)/../../lib/libcfg.la \
#			$(top_srcdir)/src/libcrypto/libcrypto.la -lcrypto

#fhzone_test_SOURCES = fhzone_test.c cmocka.c
#fhzone_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
#			  -I$(top_srcdir)/src/libclengine \
#			  -I$(top_srcdir)/src/libreplicast \
#			  -I$(top_srcdir)/src/libreptrans \
#			  -I$(top_srcdir)/src/libtrlog \
#			  -I$(top_srcdir)/src/libccowd
#fhzone_test_LDFLAGS = $(AM_LDFLAGS)  -lm -luv -lcfg -lquorum -lcpg -llmdb -lnanomsg \
#				-lcrypto $(ASAN_LIB)
#
#fhzone_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
#			 $(top_srcdir)/src/libflexhash/libflexhash.la \
#			 $(top_srcdir)/src/libclengine/libclengine.la \
#			 $(top_srcdir)/src/libccowd/libccowd.la \
#			$(top_builddir)/../../lib/libcorosync_common.la \
#			$(top_builddir)/../../lib/libcpg.la \
#			$(top_builddir)/../../lib/libquorum.la \
#			$(top_builddir)/../../lib/libcfg.la \
#			$(top_srcdir)/src/libcrypto/libcrypto.la -lcrypto

#flexhash_sim_SOURCES = flexhash_sim.c
#flexhash_sim_CFLAGS = -I$(top_srcdir)/src/libflexhash \
#			  -I$(top_srcdir)/src/libclengine \
#			  -I$(top_srcdir)/src/libreplicast \
#			  -I$(top_srcdir)/src/libtrlog \
#			  -I$(top_srcdir)/src/libreptrans \
#			  -I$(top_srcdir)/src/libccowd
#flexhash_sim_LDFLAGS = $(AM_LDFLAGS)  -lm -luv -lcfg -lquorum -lcpg -llmdb -lnanomsg \
#				-lcrypto $(ASAN_LIB)
#
#flexhash_sim_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
#			 $(top_srcdir)/src/libflexhash/libflexhash.la \
#			 $(top_srcdir)/src/libclengine/libclengine.la \
#			 $(top_srcdir)/src/libccowd/libccowd.la \
#			$(top_builddir)/../../lib/libcorosync_common.la \
#			$(top_builddir)/../../lib/libcpg.la \
#			$(top_builddir)/../../lib/libquorum.la \
#			$(top_builddir)/../../lib/libcfg.la \
#			$(top_srcdir)/src/libcrypto/libcrypto.la -lcrypto


libhashtable_test_SOURCES = libhashtable_test.c cmocka.c
libhashtable_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
                         -I$(top_srcdir)/src/libreplicast \
                         -I$(top_srcdir)/src/libreptrans \
                         -I$(top_srcdir)/src/libccowd
libhashtable_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la -luv -lcrypto $(ASAN_LIB)

libskiplist_test_SOURCES = libskiplist_test.c cmocka.c
libskiplist_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
                         -I$(top_srcdir)/src/libreplicast \
                         -I$(top_srcdir)/src/libreptrans \
                         -I$(top_srcdir)/src/libccowd
libskiplist_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la -luv -lcrypto $(ASAN_LIB)

cluster_test_SOURCES = cluster_test.c cmocka.c common.c
cluster_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
cluster_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
			-I$(top_srcdir)/src/libreplicast \
			-I$(top_srcdir)/src/libccow
cluster_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

msite_test_SOURCES = msite_test.c cmocka.c common.c
msite_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
msite_test_CFLAGS = \
			-I$(top_srcdir)/src/libflexhash \
			-I$(top_srcdir)/src/libreplicast \
			-I$(top_srcdir)/src/libccow
msite_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

cluster_lookup_test_SOURCES = cluster_lookup_test.c cmocka.c common.c
cluster_lookup_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
cluster_lookup_test_CFLAGS =
cluster_lookup_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

client_test_SOURCES = client_test.c cmocka.c common.c
client_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
client_test_CFLAGS =
client_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

bucket_lookup_test_SOURCES = bucket_lookup_test.c cmocka.c common.c
bucket_lookup_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
bucket_lookup_test_CFLAGS =
bucket_lookup_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

threaded_bucket_test_SOURCES = threaded_bucket_test.c cmocka.c common.c
threaded_bucket_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
threaded_bucket_test_CFLAGS =
threaded_bucket_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

put_test_SOURCES = put_test.c cmocka.c common.c
put_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
put_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow
put_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

seq_test_SOURCES = seq_test.c cmocka.c common.c
seq_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
seq_test_CFLAGS =
seq_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

sharded_list_test_SOURCES = sharded_list_test.c cmocka.c common.c
sharded_list_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
sharded_list_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
            -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow
sharded_list_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
         $(top_srcdir)/src/libflexhash/libflexhash.la \
            $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

user_list_test_SOURCES = user_list_test.c cmocka.c common.c
user_list_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
user_list_test_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow
user_list_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
            $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_1gb_test_SOURCES = simple_1gb_test.c cmocka.c common.c
simple_1gb_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_1gb_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
simple_1gb_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			$(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

object_replace_test_SOURCES = object_replace_test.c cmocka.c common.c
object_replace_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
object_replace_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
object_replace_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			$(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_simple_SOURCES = simple_simple.c cmocka.c common.c
simple_simple_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_simple_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow
simple_simple_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_put_SOURCES = simple_put.c cmocka.c common.c
simple_put_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_put_CFLAGS = -I$(top_srcdir)/src/libreplicast
simple_put_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_wait_SOURCES = simple_wait.c cmocka.c common.c
simple_wait_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_wait_CFLAGS = -I$(top_srcdir)/src/libreplicast
simple_wait_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

put_file_SOURCES = put_file.c cmocka.c common.c
put_file_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
put_file_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow \
		-I$(top_srcdir)/src/libflexhash
put_file_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

ec_unencode_test_SOURCES = ec_unencode_test.c cmocka.c common.c
ec_unencode_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
ec_unencode_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
ec_unencode_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

acl_list_test_SOURCES = acl_list_test.c cmocka.c common.c
acl_list_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
acl_list_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
acl_list_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

get_file_SOURCES = get_file.c cmocka.c common.c
get_file_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
get_file_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccow -I$(top_srcdir)/src/libflexhash
get_file_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

cancel_test_SOURCES = cancel_test.c cmocka.c common.c
cancel_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
cancel_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
cancel_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_import_SOURCES = simple_import.c cmocka.c common.c
simple_import_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_import_CFLAGS =
simple_import_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

pingpong_SOURCES = pingpong.c cmocka.c common.c
pingpong_LDFLAGS = $(AM_LDFLAGS) -L$(top_srcdir)/src/libccow \
		   -luv -lcrypto -lccow
pingpong_CFLAGS = -I$(top_srcdir)/src/libccow \
		     -I$(top_srcdir)/src/libchunk \
		     -I$(top_srcdir)/src/libflexhash \
		     -I$(top_srcdir)/src/libreplicast \
                     -I$(top_srcdir)/src/libreptrans 
pingpong_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_get_SOURCES = simple_get.c cmocka.c common.c
simple_get_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_get_CFLAGS =
simple_get_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

simple_iter_SOURCES = simple_iter.c cmocka.c common.c
simple_iter_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
simple_iter_CFLAGS =
simple_iter_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

stress_test_SOURCES = stress_test.c cmocka.c common.c
stress_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stress_test_CFLAGS =
stress_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

multiobject_stress_test_SOURCES = multiobject_stress_test.c cmocka.c common.c
multiobject_stress_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
multiobject_stress_test_CFLAGS =
multiobject_stress_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

bucket_list_objects_SOURCES = bucket_list_objects.c cmocka.c common.c
bucket_list_objects_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
bucket_list_objects_CFLAGS =
bucket_list_objects_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

clone_test_SOURCES = clone_test.c cmocka.c common.c
clone_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
clone_test_CFLAGS =
clone_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

get_test_SOURCES = get_test.c cmocka.c common.c
get_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
get_test_CFLAGS = -fPIC -g -std=gnu99
get_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

get_kv_SOURCES = get_kv.c cmocka.c common.c
get_kv_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
get_kv_CFLAGS = -fPIC -g -std=gnu99
get_kv_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

delete_test_SOURCES = delete_test.c cmocka.c common.c
delete_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
delete_test_CFLAGS =
delete_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

versions_test_SOURCES = versions_test.c cmocka.c common.c
versions_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
versions_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
              -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd \
                           -I$(top_srcdir)/src/libccow
versions_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
            $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

purge_test_SOURCES = purge_test.c cmocka.c common.c
purge_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
purge_test_CFLAGS =
purge_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

libcmcache_test_SOURCES = libcmcache_test.c cmocka.c
libcmcache_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow 
libcmcache_test_CFLAGS = -I$(top_srcdir)/src/libchunk \
			 -I$(top_srcdir)/src/libreplicast \
			 -I$(top_srcdir)/src/libflexhash
libcmcache_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			$(top_srcdir)/src/libchunk/libchunk.la \
			$(top_srcdir)/src/libccow/libccow.la \
			$(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

talloc_test_SOURCES = talloc_test.c cmocka.c
talloc_test_CFLAGS = $(AM_LDFLAGS) -luv -lcrypto
talloc_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccow/libccow.la -luv -lcrypto $(ASAN_LIB)

librtbuf_test_SOURCES = librtbuf_test.c cmocka.c
librtbuf_test_CFLAGS =
librtbuf_test_LDADD = $(top_srcdir)/src/libcrypto/libcrypto.la -luv -lcrypto $(ASAN_LIB)

tenant_test_SOURCES = tenant_test.c cmocka.c common.c
tenant_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
tenant_test_CFLAGS = -I$(top_srcdor)/src/libccow -I$(top_srcdir)/src/libreplicast \
		     -I$(top_srcdir)/src/libchunk \
		     -I$(top_srcdir)/src/libflexhash \
                     -I$(top_srcdir)/src/libreplicast \
                     -I$(top_srcdir)/src/libreptrans 
tenant_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

cmcache_test_SOURCES = cmcache_test.c cmocka.c common.c
cmcache_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
cmcache_test_CFLAGS = -I$(top_srcdor)/src/libccow -I$(top_srcdir)/src/libreplicast \
		     -I$(top_srcdir)/src/libchunk \
		     -I$(top_srcdir)/src/libflexhash \
                     -I$(top_srcdir)/src/libreplicast \
                     -I$(top_srcdir)/src/libreptrans 
cmcache_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

vol_test_SOURCES = vol_test.c cmocka.c common.c
vol_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
vol_test_CFLAGS =
vol_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

snapview_test_SOURCES = snapview_test.c cmocka.c common.c
snapview_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
snapview_test_CFLAGS =
snapview_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

iter_test_SOURCES = iter_test.c cmocka.c common.c
iter_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
iter_test_CFLAGS = -fPIC -g -std=gnu99
iter_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

txid_test_SOURCES = txid_test.c cmocka.c common.c
txid_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
txid_test_CFLAGS = -fPIC -g -std=gnu99
txid_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

reptrans_test_SOURCES = reptrans_test.c cmocka.c common.c
reptrans_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
reptrans_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libccowd \
                          -I$(top_srcdir)/src/libccow \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libclengine
reptrans_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)


reptrans_del_SOURCES = reptrans_del.c cmocka.c common.c
reptrans_del_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
reptrans_del_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libccowd \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libclengine
reptrans_del_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

blob_lookup_test_SOURCES = blob_lookup_test.c cmocka.c common.c
blob_lookup_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
blob_lookup_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd \
                           -I$(top_srcdir)/src/libccow
blob_lookup_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

reptrans_standalone_test_SOURCES = reptrans_standalone_test.c cmocka.c common.c
reptrans_standalone_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
reptrans_standalone_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
                          -I$(top_srcdir)/src/libccow \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
reptrans_standalone_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
				 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

reptrans_pattern_test_SOURCES = reptrans_pattern_test.c cmocka.c common.c
reptrans_pattern_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
reptrans_pattern_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
reptrans_pattern_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
				 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)


verify_test_SOURCES = verify_test.c cmocka.c common.c
verify_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
verify_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
verify_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

queue_test_SOURCES = queue_test.c
queue_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libccowd
queue_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

btree_test_SOURCES = btree_test.c cmocka.c common.c
btree_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
btree_test_CFLAGS = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon
btree_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
		   $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		    $(top_srcdir)/src/libauditc/libauditc.la \
		   -luv -lcrypto -lnanomsg $(ASAN_LIB)

libbtreenam_test_SOURCES = libbtreenam_test.c cmocka.c common.c
libbtreenam_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
libbtreenam_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreenam
libbtreenam_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			 $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreenam/libbtreenam.la \
		-luv -lcrypto $(ASAN_LIB)

btreenam_iter_test_SOURCES = btreenam_iter_test.c cmocka.c common.c
btreenam_iter_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
btreenam_iter_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreenam
btreenam_iter_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			 $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreenam/libbtreenam.la \
		-luv -lcrypto $(ASAN_LIB)

libbtreemap_test_SOURCES = libbtreemap_test.c cmocka.c common.c
libbtreemap_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
libbtreemap_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreemap
libbtreemap_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			 $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreemap/libbtreemap.la \
		-luv -lcrypto $(ASAN_LIB)

btreenam_stream_test_SOURCES = btreenam_stream_test.c cmocka.c common.c
btreenam_stream_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
btreenam_stream_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreemap
btreenam_stream_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			     $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreemap/libbtreemap.la \
		-luv -lcrypto $(ASAN_LIB)

btree_rand_update_test_SOURCES = btree_rand_update_test.c cmocka.c common.c
btree_rand_update_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
btree_rand_update_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreemap
btree_rand_update_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreemap/libbtreemap.la \
		$(top_srcdir)/src/libccowutil/libccowutil.la \
		-luv -lcrypto $(ASAN_LIB)

stress_stream_io_test_SOURCES = stress_stream_io_test.c cmocka.c common.c
stress_stream_io_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stress_stream_io_test_CFLAGS = -I$(top_srcdir)/src/libreplicast \
			       -I$(top_srcdir)/src/libflexhash \
			       -I$(top_srcdir)/src/libccow
stress_stream_io_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

stream_io_negative_test_SOURCES = stream_io_negative_test.c cmocka.c common.c
stream_io_negative_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stream_io_negative_test_CFLAGS =
stream_io_negative_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
				$(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

stress_btreemap_test_SOURCES = stress_btreemap_test.c cmocka.c common.c
stress_btreemap_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stress_btreemap_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreemap
stress_btreemap_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			     $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreemap/libbtreemap.la \
		-luv -lcrypto $(ASAN_LIB)

stress_btreemap_stream_test_SOURCES = stress_btreemap_stream_test.c cmocka.c common.c
stress_btreemap_stream_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stress_btreemap_stream_test_CFLAGS  = -I$(top_srcdir)/src/libchunk/btree/libbtreecommon \
		-I$(top_srcdir)/src/libchunk/btree/libbtreemap
stress_btreemap_stream_test_LDADD = $(top_srcdir)/src/libccowd/libccowd.la \
			     $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libchunk/btree/libbtreecommon/libbtreecommon.la \
		$(top_srcdir)/src/libchunk/btree/libbtreemap/libbtreemap.la \
		-luv -lcrypto $(ASAN_LIB)

stream_io_error_test_SOURCES = stream_io_error_test.c cmocka.c common.c
stream_io_error_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
stream_io_error_test_CFLAGS =
stream_io_error_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

io_error_test_SOURCES = io_error_test.c cmocka.c common.c
io_error_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
io_error_test_CFLAGS =
io_error_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

tenant_accounting_SOURCES = tenant_accounting.c cmocka.c common.c
tenant_accounting_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
tenant_accounting_CFLAGS =
tenant_accounting_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			  $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

rdchk_SOURCES = rdchk.c
rdchk_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
rdchk_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
rdchk_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
	      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

liberasurecode_test_SOURCES = liberasurecode_test.c
liberasurecode_test_LDFLAGS = $(AM_LDFLAGS) -lerasurecode -ldl
liberasurecode_test_CFLAGS = -O0 -fPIC -g -std=gnu99
liberasurecode_test_LDADD = $(ASAN_LIB)

error_put_get_test_SOURCES = error_put_get_test.c cmocka.c common.c
error_put_get_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
error_put_get_test_CFLAGS = -I$(top_srcdir)/src/libreplicast
error_put_get_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

cache_test_SOURCES = cache_test.c cmocka.c common.c
cache_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
cache_test_CFLAGS =
cache_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

ucache_test_SOURCES = ucache_test.c cmocka.c common.c
ucache_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
ucache_test_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		     -I$(top_srcdir)/src/libflexhash \
		     -I$(top_srcdir)/src/libccow
ucache_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

libccowvol_test_SOURCES = libccowvol_test.c cmocka.c common.c
libccowvol_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
libccowvol_test_CFLAGS  = -I$(top_srcdir)/src/libreplicast \
		      -I$(top_srcdir)/src/libflexhash \
		      -I$(top_srcdir)/src/libccow
libccowvol_test_LDADD   = $(top_srcdir)/src/libccowvol/libccowvol.la \
		      $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

slg_test_SOURCES = slg_test.c cmocka.c common.c
slg_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
slg_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow
slg_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

coroflex_SOURCES = coroflex.c
coroflex_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lcpg
coroflex_CFLAGS = -I$(top_builddir)/src/libflexhash \
		-I$(top_builddir)/src/libreplicast \
		-I$(top_builddir)/src/libreptrans \
                -I$(top_srcdir)/src/libtrlog \
		-I$(top_builddir)/src/libclengine \
		-I$(top_builddir)/src/libccowd
coroflex_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libccowd/libccowd.la $(ASAN_LIB)

coroflex_test_SOURCES = coroflex_test.c cmocka.c
coroflex_test_LDFLAGS = $(AM_LDFLAGS) -lccow
coroflex_test_CFLAGS =
coroflex_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la $(ASAN_LIB)

vmm_test_SOURCES = vmm_test.c cmocka.c common.c
vmm_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
vmm_test_CFLAGS  = -I$(top_srcdir)/src/libreplicast \
		   -I$(top_srcdir)/src/libflexhash \
		   -I$(top_srcdir)/src/libccow
vmm_test_LDADD   = $(top_srcdir)/src/libccowutil/libccowutil.la \
	           $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

trlog_test_SOURCES = trlog_test.c cmocka.c common.c
trlog_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
trlog_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		    -I$(top_srcdir)/src/libreplicast \
		    -I$(top_srcdir)/src/libccow \
		    -I$(top_srcdir)/src/libreptrans \
		    -I$(top_srcdir)/src/libtrlog
trlog_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libflexhash/libflexhash.la \
		   $(top_srcdir)/src/libtrlog/libtrlog.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

get_chids_test_SOURCES = get_chids_test.c cmocka.c common.c
get_chids_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
get_chids_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreptrans
get_chids_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

serial_update_test_SOURCES = serial_update_test.c cmocka.c common.c
serial_update_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
serial_update_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreptrans
serial_update_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

libconnbroker_test_SOURCES = libconnbroker_test.c cmocka.c common.c
libconnbroker_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
libconnbroker_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
			    -I$(top_srcdir)/src/libreplicast \
			    -I$(top_srcdir)/src/libconnbroker
libconnbroker_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libreplicast/libreplicast.la \
			   $(top_srcdir)/src/libconnbroker/libconnbroker.la \
			   $(top_srcdir)/src/libflexhash/libflexhash.la -luv -lcrypto $(ASAN_LIB)

locks_api_test_SOURCES = locks_api_test.c cmocka.c common.c
locks_api_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
locks_api_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreplicast \
  		  -I$(top_srcdir)/src/libtrlog \
		  -I$(top_srcdir)/src/libreptrans
locks_api_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libreptrans/libreptrans.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

gwlru_api_test_SOURCES = gwlru_api_test.c cmocka.c common.c
gwlru_api_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
gwlru_api_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libtrlog \
		  -I$(top_srcdir)/src/libreptrans
gwlru_api_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libreptrans/libreptrans.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto -lnanomsg -ldl $(ASAN_LIB)

locks_rt_test_SOURCES = locks_rt_test.c cmocka.c common.c
locks_rt_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
locks_rt_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libreptrans
locks_rt_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libreptrans/libreptrans.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

msort_test_SOURCES = msort_test.c cmocka.c
msort_test_CFLAGS = -I$(top_srcdir)/src/include
msort_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccow/libccow.la -luv -lcrypto $(ASAN_LIB)


ccowtp_test_SOURCES = ccowtp_test.c cmocka.c
ccowtp_test_CFLAGS = -I$(top_srcdir)/src/include
ccowtp_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccow/libccow.la -luv -lcrypto $(ASAN_LIB)

append_aligned_test_SOURCES = append_aligned_test.c cmocka.c common.c
append_aligned_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
append_aligned_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreptrans
append_aligned_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

append_unaligned_test_SOURCES = append_unaligned_test.c cmocka.c common.c
append_unaligned_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
append_unaligned_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libccow \
		  -I$(top_srcdir)/src/libreptrans
append_unaligned_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

key_cache_test_SOURCES = key_cache_test.c cmocka.c common.c
key_cache_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
key_cache_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
                                        -I$(top_srcdir)/src/libflexhash \
                                        -I$(top_srcdir)/src/libreptrans \
                                        -I$(top_srcdir)/src/libtrlog \
                                        -I$(top_srcdir)/src/libccowd
key_cache_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
                	$(top_srcdir)/src/libccowd/libccowd.la -luv -lutil -lrtrd \
			-llmdb -lcrypto -lccowd $(ASAN_LIB)

modbit_test_SOURCES = modbit_test.c cmocka.c common.c
modbit_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
modbit_test_CFLAGS = -I$(top_srcdir)/src/libflexhash \
		     -I$(top_srcdir)/src/libreplicast \
		     -I$(top_srcdir)/src/libccow \
		     -I$(top_srcdir)/src/libreptrans \
		     -I$(top_srcdir)/src/libtrlog \
		     -I$(top_srcdir)/src/libconnbroker \
		     -I$(top_srcdir)/src/libisgw
modbit_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libflexhash/libflexhash.la \
		 $(top_srcdir)/src/libtrlog/libtrlog.la \
		 $(top_srcdir)/src/libconnbroker/libconnbroker.la \
		 $(top_srcdir)/src/libisgw/libisgw.la \
		 $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

pseudo_delete_SOURCES = pseudo_delete.c cmocka.c common.c
pseudo_delete_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
pseudo_delete_CFLAGS = -I$(top_srcdor)/src/libccow \
		       -I$(top_srcdir)/src/libreplicast \
		       -I$(top_srcdir)/src/libchunk \
		       -I$(top_srcdir)/src/libflexhash \
                       -I$(top_srcdir)/src/libreplicast \
                       -I$(top_srcdir)/src/libreptrans
pseudo_delete_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

fs_verify_dentry_CFLAGS =
fs_verify_dentry_LDFLAGS = $(AM_LDFLAGS) -lccow
fs_verify_dentry_SOURCES = fs_verify_dentry.c cmocka.c common.c
fs_verify_dentry_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			   $(top_srcdir)/src/libccowd/libccowd.la \
			   $(top_srcdir)/src/libccowfsio/libccowfsio.la -lcrypto $(ASAN_LIB)

basic-fs-multifile-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_multifile_test

basic-fs-inodefetch-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_inodefetch_test

basic-fs-rw-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_rw_test

basic-fs-parallel-rd-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_parallel_rd_test

basic-fs-ops-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_ops_test

basic-fs-sharded-dir:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_sharded_dir

basic-fs-bvt:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs:../src/libccowfsio/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/basic_fs_bvt


rd_bloom_test_SOURCES = rd_bloom_test.c cmocka.c common.c
rd_bloom_test_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
rd_bloom_test_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
                                        -I$(top_srcdir)/src/libflexhash \
			  		-I$(top_srcdir)/src/libtrlog \
                                        -I$(top_srcdir)/src/libreptrans \
                                        -I$(top_srcdir)/src/libccowd
rd_bloom_test_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
                        $(top_srcdir)/src/libccowd/libccowd.la -luv -lutil -lrtrd \
			            -llmdb -lcrypto -lccowd $(ASAN_LIB)
cluster-lookup-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/cluster_lookup_test

cluster-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
#	@echo r > /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/cluster_test

msite-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
#	@echo r > /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/msite_test

tenant-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/tenant_test


vol-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/vol_test

clone-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/clone_test

put-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/put_test

simple-put:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/simple_put

put-file:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/put_file

get-file:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/get_file

delete-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/delete_test

versions-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/versions_test

purge-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/purge_test

get-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/get_test

iter-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/iter_test

daemon-test:
	@echo b > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/daemon_test

auditd-test:
	@echo b > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libauditd/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/auditd_test

client-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/client_test

stress-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stress_test

bucket-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/bucket_lookup_test

threaded_bucket-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/threaded_bucket_test

btree-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
	@echo break in server-list.c:49 >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/btree_test

libbtreenam-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libbtreenam_test

btreenam_iter-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/btreenam_iter_test

btreenam_stream-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/btreenam_stream_test

libbtreemap-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libbtreemap_test

btree_rand_update-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/btree_rand_update_test

stress_btreemap-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stress_btreemap_test

stress_btreemap_stream-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stress_btreemap_stream_test

multiobject-stress-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/multiobject_stress_test

bucket-list-objects:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/bucket_list_objects

reptrans-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/reptrans_test

reptrans-standalone-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/reptrans_standalone_test

verify-test:
	@echo b main > /tmp/ccow_test.gdb
	@echo r >> /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/verify_test

queue-test:
	@echo r > /tmp/queue_test.gdb
	@echo bt >> /tmp/queue_test.gdb
#	@echo q >> /tmp/queue_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/queue_test.gdb --args ./.libs/queue_test

seq-test:
	@echo r > /tmp/ccow_test.gdb
	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/seq_test

snapview-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/snapview_test

simple_put-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/simple_put

put_file-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/put_file

tenant_accounting-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/tenant_accounting

ccowperf-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/ccowperf_test

libflexhash-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libflexhash_test

flexhash-sim:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/flexhash_sim


rdchk-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/rdchk

stress_stream_io-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stress_stream_io_test

stream_io_negative-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stream_io_negative_test

stream_io_error-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/stream_io_error_test

io_error-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/io_error_test

cmcache-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/cmcache_test

ucache-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/ucache_test

libcmcache-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libcmcache_test

error_put_get-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/error_put_get_test

cache-test:
	@echo set breakpoint pending on > /tmp/ccow_test.gdb
#	@echo r > /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/cache_test

libccowvol-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
#	@echo r  >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q  >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libccowvol_test

slg-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/slg_test

coroflex-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/coroflex_test

vmm_io-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	@echo "set listsize 35" >> /tmp/ccow_test.gdb
#	@echo "b ccow_fail_io" >> /tmp/ccow_test.gdb
#	@echo r >> /tmp/ccow_test.gdb
#	@echo bt >> /tmp/ccow_test.gdb
#	@echo q >> /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/vmm_test

trlog-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/trlog_test

get_chids-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/get_chids_test

libconnbroker-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/libconnbroker_test

modbit-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/modbit_test

pseudo-delete:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/pseudo_delete

sharded-list-test:
	@echo "set breakpoint pending on" > /tmp/ccow_test.gdb
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/sharded_list_test

fhzone-test:
	@echo "fhzone test "
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):../src/libccowd/.libs:../src/libccow/.libs gdb --command=/tmp/ccow_test.gdb --args ./.libs/fhzone_test
