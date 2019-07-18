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
lib_LTLIBRARIES = libccowfsio.la

libccowfsio_la_SOURCES = fsio_common.c fsio_disk.c fsio_file.c fsio_flusher.c fsio_inode.c fsio_namespace.c fsio_s3_transparency.c fsio_system.c fsio_debug.c fsio_control_thread.c fsio_snapshot.c fsio_clone.c fsio_dir.c fsio_cache.c fsio_recovery.c tc_pool.c fsio_listcache.c

libccowfsio_la_CFLAGS = -I$(top_srcdir)/src/libreplicast -I$(top_srcdir)/src/libccowfsio/include

libccowfsio_la_LIBADD = $(top_srcdir)/src/libccowutil/libccowutil.la \
		     $(top_srcdir)/src/libccow/libccow.la
