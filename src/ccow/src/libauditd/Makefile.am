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
lib_LTLIBRARIES = libauditd.la

libauditd_la_SOURCES = cm_quantile.c config.c conn_handler.c counter.c \
	hashmap.c heap.c hll.c hll_constants.c ini.c metrics.c networking.c \
	radix.c set.c streaming.c timer.c auditd.c corosync.c

libauditd_la_CFLAGS = -I$(top_srcdir)/src/include \
		      -I$(top_srcdir)/src/libreplicast

libauditd_la_LDFLAGS = $(AM_LDFLAGS) -lm -luv -lcfg -lcpg -lnanomsg $(ASAN_LIB)

libauditd_la_LIBADD = $(top_srcdir)/src/libccowutil/libccowutil.la
