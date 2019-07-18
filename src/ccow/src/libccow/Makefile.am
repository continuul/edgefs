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
lib_LTLIBRARIES = libccow.la

instdir = $(includedir)/ccow/private
inst_HEADERS = ec-common.h ccow-dynamic-fetch.h ccow-impl.h network.h sop_cache.h

libccow_la_SOURCES = ccow.c network.c iter.c \
		     bucket-create.c bucket-delete.c bucket-lookup.c \
		     server-list.c put.c named-get.c named-put.c get.c \
		     unnamed-get.c unnamed-put.c compress-hash.c \
		     hash-uncompress.c cluster-init.c tenant-create.c \
		     tenant-delete.c tenant-lookup.c cluster-lookup.c \
		     bucket-init.c putcommon_client.c getcommon_client.c \
		     pingpong.c snapview.c cluster-delete.c blob-lookup.c \
		     notification.c opp-status.c sharded-list.c user-list.c acl-list.c \
		     rowevac.c sop_cache.c res-get.c ccow-dynamic-fetch.c

libccow_la_CFLAGS = -I$(top_srcdir)/src/libreplicast \
		    -I$(top_srcdir)/src/libflexhash \
		    -I$(top_srcdir)/src/libconnbroker \
		    -I$(top_srcdir)/src/libtrlog \
		    -I$(top_srcdir)/src/libccowutil

libccow_la_LDFLAGS = -lpthread $(AM_LDFLAGS) -lm -luv -lnanomsg \
		     -lcrypto $(ASAN_LIB)

libccow_la_LIBADD = $(top_srcdir)/src/libreplicast/libreplicast.la \
		    $(top_srcdir)/src/libcompress/libcompress.la \
		    $(top_srcdir)/src/libtrlog/libtrlog.la \
		    $(top_srcdir)/src/libchunk/libchunk.la \
		    $(top_srcdir)/src/libconnbroker/libconnbroker.la \
		    $(top_srcdir)/src/libflexhash/libflexhash.la \
		    $(top_srcdir)/src/libauditc/libauditc.la \
		    $(top_srcdir)/src/libccowutil/libccowutil.la

if ENABLE_SYSTEMTAP
# adde probes definition files below
DPROBES = probes.d


DHEADERS = $(DPROBES:.d=.h)
DSOURCES = $(DPROBES:.d=.c)
BUILT_SOURCES = $(DSOURCES) $(DHEADERS)
libccow_la_SOURCES += $(DPROBES) $(DSOURCES)

$(DHEADERS): $(DPROBES)
	$(DTRACE) -C -h -s $< -o $@

$(DSOURCES): $(DPROBES)
	$(DTRACE) -C -k -G -s $< | awk '/source:/{print $$2}' | xargs -I % mv % $@

clean-local:
	-rm -rf probes.c probes.h
endif
