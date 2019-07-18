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
noinst_LTLIBRARIES = libflexhash.la
DEBUGFLAG = -DDEBUG=20
libflexhash_la_SOURCES = flexhash.c combination.c hashcount.c rebalance.c

instdir = $(includedir)/ccow/private
inst_HEADERS = fhprivate.h flexhash.h
			
libflexhash_la_CFLAGS = -g $(DEBUGFLAG) \
			 -I$(top_srcdir)/src/libreplicast \
			 -I$(top_srcdir)/src/libclengine \
			 -I$(top_srcdir)/src/libreptrans \
			 -I$(top_srcdir)/src/libccow 	 \
			 -I$(top_srcdir)/src/libtrlog 	 \
			 -I$(top_srcdir)/src/libccowd 

libflexhash_la_LIBADD = -lm

%.h %.o: %.a
	cp $< $*.h
	cat $< | sed -e 's,/\*/,,g' > $*.c
	$(CC) $(libflexhash_1a_CFLAGS) $*.c -o $*.o
	rm -f $*.c

if ENABLE_SYSTEMTAP
# adde probes definition files below
DPROBES = probes.d

DHEADERS = $(DPROBES:.d=.h)
DSOURCES = $(DPROBES:.d=.c)
BUILT_SOURCES = $(DSOURCES) $(DHEADERS)
libflexhash_la_SOURCES += $(DPROBES) $(DSOURCES)

$(DHEADERS): $(DPROBES)
	$(DTRACE) -C -h -s $< -o $@

$(DSOURCES): $(DPROBES)
	$(DTRACE) -C -k -G -s $< | awk '/source:/{print $$2}' | xargs -I % mv % $@

clean-local:
	-rm -rf probes.c probes.h
endif
