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
package bucketImpl

/*
#include "ccow.h"
#include "ccowfsio.h"
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

type BucketImpl struct {
}

func (s *BucketImpl) BucketCreate(ctx context.Context, msg *proto.BucketCreateRequest) (*proto.GenericResponse, error) {
	c_bpath := C.CString(msg.Cluster + "/" + msg.Tenant + "/" + msg.Bucket)
	defer C.free(unsafe.Pointer(c_bpath))

	c_cluster := C.CString(msg.Cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(msg.Tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(msg.Bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Error(500, "Cannot initialize library")
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	ret = C.ccow_bucket_create(tc, c_bucket, C.strlen(c_bucket)+1, nil)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_bucket_create err=%d", ret)
	}

	ret = C.ccow_fsio_create_bucket(tc, c_bpath, nil)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_fsio_create_bucket err=%d", ret)
	}

	return &proto.GenericResponse{}, nil
}

func (s *BucketImpl) BucketDelete(ctx context.Context, msg *proto.BucketDeleteRequest) (*proto.GenericResponse, error) {
	c_bpath := C.CString(msg.Cluster + "/" + msg.Tenant + "/" + msg.Bucket)
	defer C.free(unsafe.Pointer(c_bpath))

	c_cluster := C.CString(msg.Cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(msg.Tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(msg.Bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Error(500, "Cannot initialize library")
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	empty := C.ccow_fsio_is_not_empty(tc, c_bpath, nil)
	if empty == 1 {
		return nil, status.Errorf(500, "NFS: Bucket not empty")
	}

	ret = C.ccow_bucket_delete(tc, c_bucket, C.strlen(c_bucket)+1)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_bucket_delete err=%d", ret)
	}

	ret = C.ccow_fsio_delete_bucket(tc, c_bpath, nil)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_fsio_delete_bucket err=%d", ret)
	}

	return &proto.GenericResponse{}, nil
}

func (s *BucketImpl) BucketList(ctx context.Context, msg *proto.BucketListRequest) (*proto.BucketListResponse, error) {

	c_cluster := C.CString(msg.Cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(msg.Tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Error(500, "Cannot initialize library")
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return nil, status.Errorf(500, "ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_pat := C.CString(msg.Pattern)
	defer C.free(unsafe.Pointer(c_pat))

	var bkCnt = msg.Count
	if bkCnt == 0 {
		bkCnt = 1000
	}

	var iter C.ccow_lookup_t
	ret = C.ccow_bucket_lookup(tc, c_pat, C.strlen(c_pat)+1, C.ulong(bkCnt), &iter)
	if ret != 0 {
		if iter != nil {
			C.ccow_lookup_release(iter)
		}

		if ret == -C.ENOENT && (msg.Pattern == "" || len(msg.Pattern) == 0) {
			return &proto.BucketListResponse{}, nil
		}

		return nil, status.Errorf(500, "ccow_tenant_lookup err=%d", ret)
	}

	info := make(map[string]*proto.BucketInfo)

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
			info[C.GoString(kv.key)] = &proto.BucketInfo{Name: C.GoString(kv.key)}
			continue
		}

		cmpRes := strings.Compare(msg.Pattern, C.GoString(kv.key))
		if cmpRes == 0 {
			found = 1
			info[C.GoString(kv.key)] = &proto.BucketInfo{Name: C.GoString(kv.key)}
		} else if cmpRes < 0 {
			found = 2
			info[C.GoString(kv.key)] = &proto.BucketInfo{Name: C.GoString(kv.key)}
		}
	}

	C.ccow_lookup_release(iter)

	if found == 0 || (found == 2 && msg.Count == 1) {
		return &proto.BucketListResponse{}, nil
	}

	return &proto.BucketListResponse{Info: info}, nil
}
