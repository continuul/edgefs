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
sbin_PROGRAMS = blobfind vdevinspect rdhold ecstat dbi_delete nezap evactool \
	dbi_util

noinst_PROGRAMS = chinjector pingpong rtbench ecstat ccowfh_check

DISABLED=clbench

chinjector_SOURCES = chinjector.c
chinjector_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
chinjector_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libflexhash \
		-I$(top_srcdir)/src/libtrlog \
		-I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libccowd
chinjector_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto $(ASAN_LIB)

dbi_delete_SOURCES = dbi_delete.c
dbi_delete_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow -llmdb
dbi_delete_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libflexhash \
		-I$(top_srcdir)/src/libtrlog \
		-I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libccowd
		
dbi_util_SOURCES = dbi_util.c
dbi_util_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow -llmdb
dbi_util_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libflexhash \
		-I$(top_srcdir)/src/libtrlog \
		-I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libccowd
dbi_util_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto -ldl $(ASAN_LIB)


nezap_SOURCES = nezap.c
nezap_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
nezap_CFLAGS = -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libflexhash \
		-I$(top_srcdir)/src/include \
		-I$(top_srcdir)/src/libtrlog \
		-I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libclengine \
		-I$(top_srcdir)/src/libccowd
nezap_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		   $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto -ldl $(ASAN_LIB)

#clbench_SOURCES = clbench.c
#clbench_LDFLAGS = $(AM_LDFLAGS)
#clbench_CFLAGS  = -I$(top_builddir)/../../include
#clbench_LDADD  = $(top_srcdir)/src/libccowutil/libccowutil.la \
#		 $(top_builddir)/../../lib/libqb.la \
#		 $(top_builddir)/../../lib/libcorosync_common.la \
#		 $(top_builddir)/../../lib/libcpg.la \
#		 $(top_builddir)/../../lib/libcfg.la $(ASAN_LIB) -lpthread

pingpong_SOURCES = pingpong.c
pingpong_CFLAGS  = -I$(top_builddir)/src/libccow \
		   -I$(top_builddir)/src/libflexhash \
		   -I$(top_builddir)/src/libchunk \
		   -I$(top_builddir)/src/libreplicast \
		   -I$(top_builddir)/src/libreptrans
pingpong_LDFLAGS = $(AM_LDFLAGS) -L$(top_srcdir)/src/libccow \
		   -luv -lcrypto -lccow
pingpong_LDADD  = $(top_srcdir)/src/libccowutil/libccowutil.la \
		  $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto

blobfind_SOURCES = blobfind.c
blobfind_LDFLAGS = -lpthread $(AM_LDFLAGS) -luv -lcrypto -lccow
blobfind_CFLAGS = -I$(top_srcdir)/src/libccow -I$(top_srcdir)/src/libreptrans \
		  -I$(top_srcdir)/src/libreplicast \
		  -I$(top_srcdir)/src/libflexhash
blobfind_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		 $(top_srcdir)/src/libccow/libccow.la \
		    $(ASAN_LIB)

vdevinspect_SOURCES = vdevinspect.c
vdevinspect_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
vdevinspect_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
vdevinspect_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto \
		      $(ASAN_LIB)

rdhold_SOURCES = rdhold.c
rdhold_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
rdhold_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
rdhold_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lcrypto \
		      $(ASAN_LIB)

rtbench_SOURCES = rtbench.c
rtbench_LDFLAGS = $(AM_LDFLAGS) -luv -lcrypto -lccow
rtbench_CFLAGS = -O0 -fPIC -g -std=gnu99 -I$(top_srcdir)/src/libreplicast \
			  -I$(top_srcdir)/src/libflexhash \
                          -I$(top_srcdir)/src/libreptrans \
                          -I$(top_srcdir)/src/libtrlog \
                          -I$(top_srcdir)/src/libccowd
rtbench_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		      $(top_srcdir)/src/libccowd/libccowd.la -luv -lutil -lrtrd -llmdb -lcrypto \
		      $(ASAN_LIB)

ecstat_SOURCES = ecstat.c
ecstat_LDFLAGS = -lpthread $(AM_LDFLAGS) -luv -lcrypto -lccow
ecstat_CFLAGS = -I$(top_srcdir)/src/libccow -I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libflexhash
ecstat_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libccow/libccow.la \
		$(ASAN_LIB)

ccowfh_check_SOURCES = ccowfh_check.c
ccowfh_check_LDFLAGS = -lpthread $(AM_LDFLAGS) -luv -lcrypto -lccow
ccowfh_check_CFLAGS = $(clbench_CFLAGS) $(pingpong_CFLAGS) -I$(top_srcdir)/src/libccow
ccowfh_check_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la \
		    $(ASAN_LIB)

evactool_SOURCES = evactool.c
evactool_LDFLAGS = -lpthread $(AM_LDFLAGS) -luv -lcrypto -lccow -lm
evactool_CFLAGS = -I$(top_srcdir)/src/libccow -I$(top_srcdir)/src/libreptrans \
		-I$(top_srcdir)/src/libreplicast \
		-I$(top_srcdir)/src/libccowd \
		-I$(top_srcdir)/src/libclengine \
		-I$(top_srcdir)/src/libtrlog \
		-I$(top_srcdir)/src/libflexhash
evactool_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		$(top_srcdir)/src/libccow/libccow.la \
		$(top_srcdir)/src/libauditd/libauditd.la \
		$(ASAN_LIB)
