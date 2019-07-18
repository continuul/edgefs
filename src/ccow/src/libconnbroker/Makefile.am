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
lib_LTLIBRARIES = libconnbroker.la

instdir = $(includedir)/ccow/private
inst_HEADERS = connbroker.h

libconnbroker_la_SOURCES = connbroker.c replicast_broker.c
libconnbroker_la_CFLAGS = \
			  -I$(top_srcdir)/src/libreplicast
libconnbroker_la_LDFLAGS = $(AM_LDFLAGS) -luv -llmdb -lcrypto
libconnbroker_la_LIBADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
			  $(top_srcdir)/src/libreplicast/libreplicast.la $(ASAN_LIB)

