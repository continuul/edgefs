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
noinst_LTLIBRARIES = libcompress.la
SUBDIRS = libfastlz liblz4 libsnappy

libcompress_la_SOURCES = fastlzlib.c

libcompress_la_CFLAGS = -g -O3 \
			-DZFAST_USE_FASTLZ -DZFAST_USE_LZ4 -DZFAST_USE_SNAPPY \
			-I$(top_srcdir)/src/libcompress/liblz4 \
			-I$(top_srcdir)/src/libcompress/libsnappy \
			-I$(top_srcdir)/src/libcompress/libfastlz

libcompress_la_LIBADD = $(top_srcdir)/src/libcompress/liblz4/liblz4.la \
			$(top_srcdir)/src/libcompress/libsnappy/libsnappy.la \
			$(top_srcdir)/src/libcompress/libfastlz/libfastlz.la
