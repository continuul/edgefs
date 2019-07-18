/*
 * Copyright (c) 2015-2018 Nexenta Systems, Inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package clusterImpl

/*
#include "ccow.h"
#include "errno.h"
*/
import "C"
import "unsafe"

import (
	proto ".."
	"../../efsutil"
	"golang.org/x/net/context"
	"google.golang.org/grpc/status"
	"strings"
)

type ClusterImpl struct {
}

func (s *ClusterImpl) CheckHealth(ctx context.Context, msg *proto.CheckHealthRequest) (*proto.CheckHealthResponse, error) {
	return &proto.CheckHealthResponse{Status: "ok"}, nil
}

func (s *ClusterImpl) ClusterList(ctx context.Context, msg *proto.ClusterListRequest) (*proto.ClusterListResponse, error) {

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Error(500, "Cannot initialize library")
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_pat := C.CString(msg.Pattern)
	defer C.free(unsafe.Pointer(c_pat))

	var clCnt = msg.Count
	if clCnt == 0 {
		clCnt = 1000
	}

	var iter C.ccow_lookup_t
	ret = C.ccow_cluster_lookup(tc, c_pat, C.strlen(c_pat)+1, C.ulong(clCnt), &iter)
	if ret != 0 {
		if iter != nil {
			C.ccow_lookup_release(iter)
		}

		if ret == -C.ENOENT && (msg.Pattern == "" || len(msg.Pattern) == 0) {
			return &proto.ClusterListResponse{}, nil
		}

		return nil, status.Errorf(500, "ccow_cluster_lookup err=%d", ret)
	}

	info := make(map[string]*proto.ClusterInfo)

	cnt := int32(0)
	found := 0
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter, C.CCOW_MDTYPE_NAME_INDEX, -1))
		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		if efsutil.IsSystemName(C.GoString(kv.key)) {
			continue
		}

		if msg.Count > 0 && msg.Count <= cnt {
			break
		}
		cnt++

		if msg.Pattern == "" || len(msg.Pattern) == 0 {
			found = 1
			info[C.GoString(kv.key)] = &proto.ClusterInfo{Name: C.GoString(kv.key)}
			continue
		}

		cmpRes := strings.Compare(msg.Pattern, C.GoString(kv.key))
		if cmpRes == 0 {
			found = 1
			info[C.GoString(kv.key)] = &proto.ClusterInfo{Name: C.GoString(kv.key)}
		} else if cmpRes < 0 {
			found = 2
			info[C.GoString(kv.key)] = &proto.ClusterInfo{Name: C.GoString(kv.key)}
		}
	}

	C.ccow_lookup_release(iter)

	if found == 0 || (found == 2 && msg.Count == 1) {
		return &proto.ClusterListResponse{}, nil
	}

	return &proto.ClusterListResponse{Info: info}, nil
}
