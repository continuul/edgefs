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
noinst_LTLIBRARIES = libreptrans.la
SUBDIRS = rtlfs rtrd rtkvs

instdir = $(includedir)/ccow/private
inst_HEADERS = reptrans-data.h reptrans.h sop_list.h vmm_cache.h \
	       erasure-coding.h reptrans-device.h

libreptrans_la_SOURCES = reptrans-data.c reptrans.c named-put.c unnamed-put.c \
			 named-get.c unnamed-get.c putcommon_server.c \
			 pingpong.c ngrequest.c ngrequest-send.c \
			 getcommon_server.c verify.c ngrequest-count.c \
			 ngrequest-count-srv.c ngrequest-purge.c \
			 ngrequest-locate-srv.c ngrequest-locate.c \
			 ngrequest-purge-srv.c erasure-coding.c \
			 reptrans_bg_sched.c ec_xor_codec.c ec_rs_codec.c \
			 vmm_cache.c recovery-srv.c rt_locks.c \
			 rcvd_cache.c opp-status-srv.c serial_op.c gwcache-get.c \
			 gwcache-async.c reptrans-flex.c rowevac-srv.c sop_list.c \
			 res-get.c

libreptrans_la_CFLAGS = -I$(top_srcdir)/src/libflexhash \
			-I$(top_srcdir)/src/libreplicast \
			-I$(top_srcdir)/src/libreptrans \
			-I$(top_srcdir)/src/libccowd \
			-I$(top_srcdir)/src/libflexhash \
			-I$(top_srcdir)/src/libclengine \
			-I$(top_srcdir)/src/libtrlog \
			-I$(top_srcdir)/src/libccow

libreptrans_la_LIBADD = $(top_srcdir)/src/libreptrans/rtlfs/librtlfs.la \
			$(top_srcdir)/src/libreptrans/rtrd/librtrd.la \
			$(top_srcdir)/src/libreptrans/rtkvs/librtkvs.la

libreptrans_la_LDFLAGS = $(AM_LDFLAGS) -lerasurecode

if ENABLE_SYSTEMTAP
# adde probes definition files below
DPROBES = probes.d


DHEADERS = $(DPROBES:.d=.h)
DSOURCES = $(DPROBES:.d=.c)
BUILT_SOURCES = $(DSOURCES) $(DHEADERS)
libreptrans_la_SOURCES += $(DPROBES) $(DSOURCES)

$(DHEADERS): $(DPROBES)
	$(DTRACE) -C -h -s $< -o $@

$(DSOURCES): $(DPROBES)
	$(DTRACE) -C -k -G -s $< | awk '/source:/{print $$2}' | xargs -I % mv % $@

clean-local:
	-rm -rf probes.c probes.h
endif
