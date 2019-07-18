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
package snapshotImpl

/*
#include "ccow.h"
#include "errno.h"
*/
import "C"
import "unsafe"

import (
	proto ".."
	"../../efsutil"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc/status"
	"log"
	"strings"
	"time"
)

const (
	EDGEFS_SNAPVIEW_SUFFIX = ".snapview"
)

type SnapshotImpl struct {
}

func ValidateSnapViewPath(snapViewPath string) error {
	snapViewPathParts := strings.Split(snapViewPath, "/")
	if len(snapViewPathParts) != 4 {
		return fmt.Errorf("Wrong snapview path: %s", snapViewPath)
	}

	if !strings.HasSuffix(snapViewPath, EDGEFS_SNAPVIEW_SUFFIX) {
		return fmt.Errorf("invalid snapview path: %s", snapViewPath)
	}
	return nil
}

func ValidateSnapshotPath(snapshotPath string) error {
	snapPathParts := strings.Split(snapshotPath, "@")
	if len(snapPathParts) != 2 {
		return fmt.Errorf("Wrong object snapshot format %s. Should be <cluster>/<tenant>/<bucket>/<object>@<snapshotName>", snapshotPath)
	}

	objectPath := strings.Split(snapPathParts[0], "/")
	if len(objectPath) != 4 {
		return fmt.Errorf("Wrong object path in snapshot path: %s", snapshotPath)
	}
	return nil
}

func (s *SnapshotImpl) CreateSnapshot(ctx context.Context, msg *proto.SnapshotRequest) (*proto.SnapshotResponse, error) {

	log.Printf("Executing CreateSnapshot %+v ", *msg)
	if msg.Snapshot.Cluster == "" || msg.Snapshot.Tenant == "" || msg.Snapshot.Bucket == "" || msg.Snapshot.Object == "" || msg.Snapshot.Name == "" {
		return nil, status.Error(400, "missing required field in snapshot path")
	}

	snapviewObjectName := msg.Snapshot.Object
	if !strings.HasSuffix(snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX) {
		snapviewObjectName = fmt.Sprintf("%s%s", snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX)
	}

	sourceObjectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, msg.Snapshot.Object)
	snapviewPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, snapviewObjectName)
	snapshotPath := fmt.Sprintf("%s@%s", sourceObjectPath, msg.Snapshot.Name)

	log.Printf("CreateSnapshot::SourceObjectPath: %s", sourceObjectPath)
	log.Printf("CreateSnapshot::SnapviewPath: %s", snapviewPath)
	log.Printf("CreateSnapshot::SnapshotPath: %s", snapshotPath)

	c_svPath := C.CString(snapviewPath)
	defer C.free(unsafe.Pointer(c_svPath))

	// SnapView path parts
	c_svCluster := C.CString(msg.Snapshot.Cluster)
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(msg.Snapshot.Tenant)
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(msg.Snapshot.Bucket)
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapviewObjectName)
	defer C.free(unsafe.Pointer(c_svObject))

	// SourceObject and Snapshot path parts
	c_snapshot := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(c_snapshot))

	c_ssObject := C.CString(msg.Snapshot.Object)
	defer C.free(unsafe.Pointer(c_ssObject))

	// Libccow Init
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	//SnapView ccow_t
	var svtc C.ccow_t
	ret := C.ccow_tenant_init(c_conf, c_svCluster, C.strlen(c_svCluster)+1, c_svTenant, C.strlen(c_svTenant)+1, &svtc)
	if ret != 0 {
		return nil, status.Errorf(500, "%: snapView ccow_tenant_init err=%d", efsutil.GetFUNC(), ret)
	}

	defer C.ccow_tenant_term(svtc)

	var snapviewHandler C.ccow_snapview_t
	ret = C.ccow_snapview_create(svtc, &snapviewHandler, c_svBucket, C.strlen(c_svBucket)+1, c_svObject, C.strlen(c_svObject)+1)
	if ret != 0 && ret != -C.EEXIST {
		return nil, status.Errorf(500, "%s: snapView ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_snapview_destroy(svtc, snapviewHandler)

	ret = C.ccow_snapshot_create(svtc, snapviewHandler, c_svBucket, C.strlen(c_svBucket)+1, c_ssObject, C.strlen(c_ssObject)+1, c_snapshot, C.strlen(c_snapshot)+1)
	creationTime := time.Now().Unix()
	if ret != 0 {
		if ret == -C.EEXIST {
			log.Printf("Snapshot %s already exists in the snapview %s\n", snapshotPath)
			return &proto.SnapshotResponse{Snapshot: &proto.SnapshotInfo{Name: snapshotPath, SourceObject: sourceObjectPath, CreationTime: creationTime}}, nil
		}

		return nil, status.Errorf(500, "%s: snapshot ccow_snapshot_create=%d\n", efsutil.GetFUNC(), ret)
	}

	return &proto.SnapshotResponse{Snapshot: &proto.SnapshotInfo{Name: snapshotPath, SourceObject: sourceObjectPath, CreationTime: creationTime}}, nil
}

func (s *SnapshotImpl) DeleteSnapshot(ctx context.Context, msg *proto.SnapshotRequest) (*proto.GenericResponse, error) {

	if msg.Snapshot.Cluster == "" || msg.Snapshot.Tenant == "" || msg.Snapshot.Bucket == "" || msg.Snapshot.Object == "" {
		return nil, status.Error(400, "missing required field in snapshot")
	}

	snapviewObjectName := msg.Snapshot.Object
	if !strings.HasSuffix(snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX) {
		snapviewObjectName = fmt.Sprintf("%s%s", snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX)
	}

	sourceObjectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, msg.Snapshot.Object)
	snapviewPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, snapviewObjectName)
	snapshotPath := fmt.Sprintf("%s@%s", sourceObjectPath, msg.Snapshot.Name)

	log.Printf("DeleteSnapshot::SourceObjectPath: %s", sourceObjectPath)
	log.Printf("DeleteSnapshot::SnapviewPath: %s", snapviewPath)
	log.Printf("DeleteSnapshot::SnapshotPath: %s", snapshotPath)

	c_svPath := C.CString(snapviewPath)
	defer C.free(unsafe.Pointer(c_svPath))

	// SnapView path parts
	c_svCluster := C.CString(msg.Snapshot.Cluster)
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(msg.Snapshot.Tenant)
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(msg.Snapshot.Bucket)
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapviewObjectName)
	defer C.free(unsafe.Pointer(c_svObject))

	// SourceObject and Snapshot path parts
	c_snapshot := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(c_snapshot))

	c_ssObject := C.CString(msg.Snapshot.Object)
	defer C.free(unsafe.Pointer(c_ssObject))

	// Libccow Init
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	//SnapView ccow_t
	var svtc C.ccow_t
	ret := C.ccow_tenant_init(c_conf, c_svCluster, C.strlen(c_svCluster)+1,
		c_svTenant, C.strlen(c_svTenant)+1, &svtc)
	if ret != 0 {
		return nil, status.Errorf(500, "%: snapView ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(svtc)

	var snapviewHandler C.ccow_snapview_t
	ret = C.ccow_snapview_create(svtc, &snapviewHandler, c_svBucket, C.strlen(c_svBucket)+1, c_svObject, C.strlen(c_svObject)+1)
	if ret != 0 && ret != -C.EEXIST {
		return nil, status.Errorf(500, "%s: snapView ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_snapview_destroy(svtc, snapviewHandler)

	ret = C.ccow_snapshot_delete(svtc, snapviewHandler, c_snapshot, C.strlen(c_snapshot)+1)
	if ret != 0 {
		if ret == -C.ENOENT {
			//fmt.Printf("Snapshot %s not exists in the snapview %s\n", sourceSnapshotPath, snapViewPath)
			return &proto.GenericResponse{}, nil
		}

		return nil, status.Errorf(500, "%s: snapshot ccow_snapshot_create=%d\n", efsutil.GetFUNC(), ret)
	}

	//fmt.Printf("Snapshot %s has been removed from %s\n", sourceSnapshotPath, snapViewPath)
	return &proto.GenericResponse{}, nil
}

func (s *SnapshotImpl) CloneSnapshot(ctx context.Context, msg *proto.SnapshotCloneRequest) (*proto.CloneResponse, error) {
	if msg.Snapshot.Cluster == "" || msg.Snapshot.Tenant == "" || msg.Snapshot.Bucket == "" || msg.Snapshot.Object == "" {
		return nil, status.Error(400, "missing required field in snapshot")
	}

	if msg.Clone.Cluster == "" || msg.Clone.Tenant == "" || msg.Clone.Bucket == "" || msg.Clone.Object == "" {
		return nil, status.Error(400, "missing required field in snapview ")
	}

	snapviewObjectName := msg.Snapshot.Object
	if !strings.HasSuffix(snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX) {
		snapviewObjectName = fmt.Sprintf("%s%s", snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX)
	}

	sourceObjectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, msg.Snapshot.Object)
	snapviewPath := fmt.Sprintf("%s/%s/%s/%s", msg.Snapshot.Cluster, msg.Snapshot.Tenant, msg.Snapshot.Bucket, snapviewObjectName)
	snapshotPath := fmt.Sprintf("%s@%s", sourceObjectPath, msg.Snapshot.Name)
	cloneObjectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Clone.Cluster, msg.Clone.Tenant, msg.Clone.Bucket, msg.Clone.Object)

	log.Printf("CloneSnapshot::SourceObjectPath: %s", sourceObjectPath)
	log.Printf("CloneSnapshot::SourceSnapviewPath: %s", snapviewPath)
	log.Printf("CloneSnapshot::SourceSnapshotPath: %s", snapshotPath)
	log.Printf("CloneSnapshot::CloneObjectPath: %s", cloneObjectPath)

	// SnapView path parts
	c_svPath := C.CString(snapviewPath)
	defer C.free(unsafe.Pointer(c_svPath))

	c_svCluster := C.CString(msg.Snapshot.Cluster)
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(msg.Snapshot.Tenant)
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(msg.Snapshot.Bucket)
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapviewObjectName)
	defer C.free(unsafe.Pointer(c_svObject))

	//Snapshot path and variables
	c_ssName := C.CString(snapshotPath)
	defer C.free(unsafe.Pointer(c_ssName))

	// Clone parts and vars
	c_cloneCluster := C.CString(msg.Clone.Cluster)
	defer C.free(unsafe.Pointer(c_cloneCluster))

	c_cloneTenant := C.CString(msg.Clone.Tenant)
	defer C.free(unsafe.Pointer(c_cloneTenant))

	c_cloneBucket := C.CString(msg.Clone.Bucket)
	defer C.free(unsafe.Pointer(c_cloneBucket))

	c_cloneObject := C.CString(msg.Clone.Object)
	defer C.free(unsafe.Pointer(c_cloneObject))

	// Libccow Init
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Errorf(500, err.Error())
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	//SnapView ccow_t
	var svtc C.ccow_t
	ret := C.ccow_tenant_init(c_conf, c_svCluster, C.strlen(c_svCluster)+1,
		c_svTenant, C.strlen(c_svTenant)+1, &svtc)
	if ret != 0 {
		return nil, status.Errorf(500, "%: snapView ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(svtc)

	var svc C.ccow_completion_t
	ret = C.ccow_create_completion(svtc, nil, nil, 1, &svc)
	if ret != 0 {
		return nil, status.Errorf(500, "%s: snapview ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	var snapviewHandler C.ccow_snapview_t
	ret = C.ccow_snapview_create(svtc, &snapviewHandler, c_svBucket, C.strlen(c_svBucket)+1, c_svObject, C.strlen(c_svObject)+1)
	if ret != 0 && ret != -C.EEXIST {
		return nil, status.Errorf(500, "%s: snapView ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}

	//clone ccow_t
	var clonetc C.ccow_t
	ret = C.ccow_tenant_init(c_conf, c_cloneCluster, C.strlen(c_cloneCluster)+1,
		c_cloneTenant, C.strlen(c_cloneTenant)+1, &clonetc)
	if ret != 0 {
		return nil, status.Errorf(500, "%s: clone ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(clonetc)

	//clone completion
	var clonec C.ccow_completion_t
	ret = C.ccow_create_completion(clonetc, nil, nil, 1, &clonec)
	if ret != 0 {
		return nil, status.Errorf(500, "%s: clone ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_clone_snapview_object(svtc,
		snapviewHandler,
		c_ssName,
		C.strlen(c_ssName)+1,
		c_cloneTenant,
		C.strlen(c_cloneTenant)+1,
		c_cloneBucket,
		C.strlen(c_cloneBucket)+1,
		c_cloneObject,
		C.strlen(c_cloneObject)+1)
	if ret != 0 {
		if snapviewHandler != nil {
			C.ccow_snapview_destroy(svtc, snapviewHandler)
		}

		if ret == -C.EEXIST {
			return &proto.CloneResponse{Clone: cloneObjectPath}, nil
		}

		return nil, status.Errorf(500, "%s: clone ccow_clone_snapview_object=%d\n", efsutil.GetFUNC(), ret)
	}

	defer C.ccow_snapview_destroy(svtc, snapviewHandler)
	return &proto.CloneResponse{Clone: cloneObjectPath}, nil
}

func (s *SnapshotImpl) ListSnapshots(ctx context.Context, msg *proto.SnapshotListRequest) (*proto.SnapshotListResponse, error) {

	count := uint32(10000)
	if msg.Count > 0 {
		count = msg.Count
	}

	snapviewObjectName := msg.Object.Object
	if !strings.HasSuffix(snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX) {
		snapviewObjectName = fmt.Sprintf("%s%s", snapviewObjectName, EDGEFS_SNAPVIEW_SUFFIX)
	}

	sourceObjectPath := fmt.Sprintf("%s/%s/%s/%s", msg.Object.Cluster, msg.Object.Tenant, msg.Object.Bucket, msg.Object.Object)
	snapviewPath := fmt.Sprintf("%s/%s/%s/%s", msg.Object.Cluster, msg.Object.Tenant, msg.Object.Bucket, snapviewObjectName)

	log.Printf("ListSnapshots::SourceObjectPath: %s", sourceObjectPath)
	log.Printf("ListSnapshots::SourceSnapviewPath: %s", snapviewPath)

	c_pattern := C.CString(msg.Pattern)
	defer C.free(unsafe.Pointer(c_pattern))

	// SnapView path parts
	c_svCluster := C.CString(msg.Object.Cluster)
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(msg.Object.Tenant)
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(msg.Object.Bucket)
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapviewObjectName)
	defer C.free(unsafe.Pointer(c_svObject))

	// Libccow Init
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return nil, status.Error(500, "Cannot initialize library")
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	//SnapView ccow_t
	var svtc C.ccow_t
	ret := C.ccow_tenant_init(c_conf, c_svCluster, C.strlen(c_svCluster)+1,
		c_svTenant, C.strlen(c_svTenant)+1, &svtc)
	if ret != 0 {
		return nil, status.Errorf(500, "%: snapView ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(svtc)

	var svc C.ccow_completion_t
	ret = C.ccow_create_completion(svtc, nil, nil, 1, &svc)
	if ret != 0 {
		return nil, status.Errorf(500, "%s: snapview ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	var snapviewHandler C.ccow_snapview_t
	ret = C.ccow_snapview_create(svtc, &snapviewHandler, c_svBucket, C.strlen(c_svBucket)+1, c_svObject, C.strlen(c_svObject)+1)
	if ret != 0 && ret != -C.EEXIST {
		return nil, status.Errorf(500, "%s: snapView ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_snapview_destroy(svtc, snapviewHandler)

	info := make(map[string]*proto.SnapshotInfo)
	var snapshotIterator C.ccow_lookup_t
	ret = C.ccow_snapshot_lookup(svtc, snapviewHandler, c_pattern, C.strlen(c_pattern)+1, C.ulong(count), &snapshotIterator)
	if ret != 0 {
		if snapshotIterator != nil {
			C.ccow_lookup_release(snapshotIterator)
		}
		// no entries found, just return empty map
		if ret == -C.ENOENT {
			return &proto.SnapshotListResponse{Info: info}, nil
		}

		return nil, status.Errorf(500, "ccow_snapshot_lookup err=%d\n", ret)
	}
	defer C.ccow_lookup_release(snapshotIterator)

	var kv *C.struct_ccow_metadata_kv
	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(snapshotIterator, C.CCOW_MDTYPE_NAME_INDEX, -1))
		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		if strings.HasPrefix(C.GoString(kv.key), strings.TrimSpace(msg.Pattern)) {
			//found = 1
			if !efsutil.IsSystemName(C.GoString(kv.key)) {
				info[C.GoString(kv.key)] = &proto.SnapshotInfo{Name: C.GoString(kv.key)}
			}
		}
	}

	return &proto.SnapshotListResponse{Info: info}, nil
}
