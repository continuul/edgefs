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
noinst_LTLIBRARIES = libclengine.la

libclengine_la_SOURCES = clengine.c corosync.c cltopo.c cltopo-server-list.c blob-lookup-srv.c

libclengine_la_CFLAGS = -I$(top_srcdir)/src/libreplicast \
			-I$(top_srcdir)/src/libreptrans \
			-I$(top_srcdir)/src/libflexhash \
			-I$(top_srcdir)/src/libtrlog \
			-I$(top_srcdir)/src/libccowd

if ENABLE_SYSTEMTAP
# adde probes definition files below
DPROBES = probes.d


DHEADERS = $(DPROBES:.d=.h)
DSOURCES = $(DPROBES:.d=.c)
BUILT_SOURCES = $(DSOURCES) $(DHEADERS)
libclengine_la_SOURCES += $(DPROBES) $(DSOURCES)

$(DHEADERS): $(DPROBES)
	$(DTRACE) -C -h -s $< -o $@

$(DSOURCES): $(DPROBES)
	$(DTRACE) -C -k -G -s $< | awk '/source:/{print $$2}' | xargs -I % mv % $@

clean-local:
	-rm -rf probes.c probes.h
endif
