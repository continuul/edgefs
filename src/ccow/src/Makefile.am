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
SUBDIRS = libcrypto libccowutil libreptrans libreplicast libclengine \
          libconnbroker libcompress libchunk libflexhash libccache libauditc \
	  libauditd libtrlog libccow libccowd libccowfsio libccowvol \
	  include

sbin_PROGRAMS = ccow-auditd ccow-daemon

ccow_auditd_SOURCES = ccow-auditd.c
ccow_auditd_CFLAGS =
ccow_auditd_LDFLAGS = $(ASAN_LIB)
ccow_auditd_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libauditd/libauditd.la

ccow_daemon_SOURCES = ccow-daemon.c
ccow_daemon_CFLAGS =	-I$(top_srcdir)/src/libreplicast \
			-I$(top_srcdir)/src/libreptrans
ccow_daemon_LDFLAGS = $(ASAN_LIB)
ccow_daemon_LDADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		    $(top_srcdir)/src/libccowd/libccowd.la \
		    $(top_srcdir)/src/libtrlog/libtrlog.la \
		    $(top_srcdir)/src/libccache/libccache.la
