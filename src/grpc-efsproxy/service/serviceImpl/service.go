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
package serviceImpl

/*
#include "ccow.h"
#include "errno.h"
*/
import "C"
import "unsafe"

import (
	proto ".."
	"../../../grpc-iscsi/lun"
	"../../../grpc-nfs/export"
	"../../efsutil"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	VOLSIZE_KEY   = "X-volsize"
	BLOCKSIZE_KEY = "X-blocksize"
	CHUNKSIZE_KEY = "ccow-chunkmap-chunk-size"
)

var (
	nfsIDMutex   sync.Mutex // mutex for NFS service ID calculation
	iscsiIDMutex sync.Mutex // mutex for ISCSI service ID calculation
)

type ServiceImpl struct {
}

type VolumeSettings struct {
	isClonedObject bool
	volumeSize     int64
	chunkSize      int32
	blockSize      int32
}

func NFSAddExport(eps map[string]int, msg *proto.ServeRequest, exportId uint32) error {
	quit := make(chan bool)
	done := make(chan error)
	for h, p := range eps {
		go func(host string, port int) {

			log.Printf("Contacting %s:%d with ExportAddRequest", host, port)

			conn, err := grpc.Dial(fmt.Sprintf("%s:%d", host, port), grpc.WithInsecure())
			if err != nil {
				err = fmt.Errorf("did not connect: %v", err)
			} else {
				defer conn.Close()

				c := export.NewExportClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				r, err := c.ExportAdd(ctx,
					&export.ExportRequest{
						Service:  msg.Service,
						Cluster:  msg.Cluster,
						Tenant:   msg.Tenant,
						Bucket:   msg.Bucket,
						ExportId: exportId,
					})
				if err != nil {
					err = fmt.Errorf("could not add export %s/%s/%s: %v", err,
						msg.Cluster, msg.Tenant, msg.Bucket)
				} else {
					log.Printf("export added %s/%s/%s: %v", msg.Cluster, msg.Tenant, msg.Bucket, r)
				}
			}
			select {
			case done <- err:
			case <-quit:
			}
		}(h, p)
	}
	for success := 0; success < len(eps); success++ {
		err := <-done
		if err != nil {
			close(quit)
			return err
		}
	}
	return nil
}

func ISCSIAddLun(eps map[string]int, serviceName, clusterName, tenantName, bucketName, objectName string, lunNumber uint32) error {
	quit := make(chan bool)
	done := make(chan error)
	for h, p := range eps {
		go func(host string, port int) {

			log.Printf("Contacting %s:%d with AddLun", host, port)
			log.Printf("AddLun params: ServiceName: %s,  clusterName: %s, tenantName: %s, bucketName: %s, objectName: %s, lunNumber: %d", serviceName, clusterName, tenantName, bucketName, objectName, lunNumber)
			conn, err := grpc.Dial(fmt.Sprintf("%s:%d", host, port), grpc.WithInsecure())
			if err != nil {
				err = fmt.Errorf("did not connect: %v", err)
			} else {
				defer conn.Close()

				c := lun.NewLunClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				r, err := c.AddLun(ctx,
					&lun.LunRequest{
						Service:   serviceName,
						Cluster:   clusterName,
						Tenant:    tenantName,
						Bucket:    bucketName,
						Object:    objectName,
						LunNumber: lunNumber,
					})
				if err != nil {
					err = fmt.Errorf("could not add lun %s/%s/%s/%s: %v",
						clusterName, tenantName, bucketName, objectName, err)
				} else {
					log.Printf("lun added %s/%s/%s/%s: %s", clusterName, tenantName, bucketName, objectName, r)
				}
			}
			select {
			case done <- err:
			case <-quit:
			}
		}(h, p)
	}
	for success := 0; success < len(eps); success++ {
		err := <-done
		if err != nil {
			close(quit)
			return err
		}
	}
	return nil
}

func ISCSIRemoveLun(eps map[string]int, serviceName, clusterName, tenantName, bucketName, objectName string, lunNumber uint32) error {
	quit := make(chan bool)
	done := make(chan error)
	for h, p := range eps {
		go func(host string, port int) {

			log.Printf("Contacting %s:%d with RemoveLunRequest", host, port)

			conn, err := grpc.Dial(fmt.Sprintf("%s:%d", host, port), grpc.WithInsecure())
			if err != nil {
				err = fmt.Errorf("did not connect: %v", err)
			} else {
				defer conn.Close()

				c := lun.NewLunClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				r, err := c.RemoveLun(ctx,
					&lun.LunRequest{
						Service:   serviceName,
						Cluster:   clusterName,
						Tenant:    tenantName,
						Bucket:    bucketName,
						Object:    objectName,
						LunNumber: lunNumber,
					})
				if err != nil {
					err = fmt.Errorf("could not remove lun %s/%s/%s/%s: %s",
						clusterName, tenantName, bucketName, objectName, err)
				} else {
					log.Printf("lun removed %s/%s/%s/%s: %v", clusterName, tenantName, bucketName, objectName, r)
				}
				select {
				case done <- err:
				case <-quit:
				}
			}
		}(h, p)
	}
	for success := 0; success < len(eps); success++ {
		err := <-done
		if err != nil {
			close(quit)
			return err
		}
	}
	return nil
}

func NFSRemoveExport(eps map[string]int, msg *proto.ServeRequest, exportId uint32) error {
	quit := make(chan bool)
	done := make(chan error)
	for h, p := range eps {
		go func(host string, port int) {

			log.Printf("Contacting %s:%d with ExportRemoveRequest", host, port)

			conn, err := grpc.Dial(fmt.Sprintf("%s:%d", host, port), grpc.WithInsecure())
			if err != nil {
				err = fmt.Errorf("did not connect: %v", err)
			} else {
				defer conn.Close()

				c := export.NewExportClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				r, err := c.ExportRemove(ctx,
					&export.ExportRequest{
						Service:  msg.Service,
						Cluster:  msg.Cluster,
						Tenant:   msg.Tenant,
						Bucket:   msg.Bucket,
						ExportId: exportId,
					})
				if err != nil {
					err = fmt.Errorf("could not remove export %s/%s/%s: %v", err,
						msg.Cluster, msg.Tenant, msg.Bucket)
				} else {
					log.Printf("export removed %s/%s/%s: %v", msg.Cluster, msg.Tenant, msg.Bucket, r)
				}
				select {
				case done <- err:
				case <-quit:
				}
			}
		}(h, p)
	}
	for success := 0; success < len(eps); success++ {
		err := <-done
		if err != nil {
			close(quit)
			return err
		}
	}
	return nil
}

func BuildGrpcEndpoints(eps *map[string]int, service string, namespace string) {

	client, err := efsutil.NewInClusterK8sClient()

	ns := namespace
	if namespace == "" {
		ns = "default"
	}

	if err != nil {
		log.Printf("attempt to connect to a local protocol controller on port 49000")
		(*eps)["localhost"] = 49000
	} else {
		e, err := client.GetEndpoints(ns, service)
		log.Printf("%v %v", e, err)

		for _, subset := range e.Subsets {
			for _, port := range subset.Ports {
				if port.Name != "grpc" {
					continue
				}
				for _, addr := range subset.Addresses {
					(*eps)[addr.IP] = port.Port
				}
				break
			}
		}
	}
}

func NewExportIdNFS(sname string, cluster string, tenant string, bucket string) (uint32, error) {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" {
		return 0, fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s",
			sname, cluster, tenant, bucket)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	bpath := cluster + "/" + tenant + "/" + bucket
	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	var maxExportId int = 1
	keys, err := efsutil.GetKeys("", "svcs", sname, "")
	if err != nil {
		return 0, err
	}

	suffix := fmt.Sprintf("%s/%s@%s", tenant, bucket, bpath)
	for _, key := range keys {
		p := strings.Split(key, ",")
		id, e := strconv.Atoi(p[0])
		if e != nil || len(p) < 2 {
			continue
		}
		if id > maxExportId {
			maxExportId = id
		}

		if strings.Compare(p[1], suffix) == 0 {
			return 0, fmt.Errorf("Export already exists: %s", suffix)
		}
	}
	return uint32(maxExportId + 1), nil
}

func NewLunIdISCSI(sname, cluster, tenant, bucket, lun string) (uint32, error) {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" || lun == "" {
		return 0, fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s, lun: %s",
			sname, cluster, tenant, bucket, lun)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	lunPath := cluster + "/" + tenant + "/" + bucket + "/" + lun
	c_lunPath := C.CString(lunPath)
	defer C.free(unsafe.Pointer(c_lunPath))

	keys, err := efsutil.GetKeys("", "svcs", sname, "")
	if err != nil {
		return 0, err
	}

	var maxLunId int = 0

	suffix := fmt.Sprintf("%s", lunPath)
	for _, key := range keys {
		p := strings.Split(key, "@")
		id, e := strconv.Atoi(p[0])
		if e != nil || len(p) < 2 {
			continue
		}
		if id > maxLunId {
			maxLunId = id
		}

		if strings.HasSuffix(p[1], suffix) {
			return 0, fmt.Errorf("LUN already exists: %s", suffix)
		}
	}

	return uint32(maxLunId + 1), nil
}

func InsertServiceObjectNFS(sname string, cluster string, tenant string, bucket string, newExportId uint32) error {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" {
		return fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s",
			sname, cluster, tenant, bucket)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	bpath := cluster + "/" + tenant + "/" + bucket
	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	svcs := C.CString("svcs")
	defer C.free(unsafe.Pointer(svcs))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	newExport := fmt.Sprintf("%d,%s/%s@%s", newExportId, tenant, bucket, bpath)

	c_export := C.CString(newExport)
	defer C.free(unsafe.Pointer(c_export))

	var comp C.ccow_completion_t

	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_export)
	iov_name.iov_len = C.strlen(c_export) + 1
	ret = C.ccow_insert_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_insert_list err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	return nil
}

func InsertServiceObjectISCSI(sname, cluster, tenant, bucket, object string, newLunId uint32, settings VolumeSettings) error {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" || object == "" {
		return fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s, object: %s",
			sname, cluster, tenant, bucket, object)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	c_object := C.CString(object)
	defer C.free(unsafe.Pointer(c_object))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	opath := fmt.Sprintf("%s/%s/%s/%s", cluster, tenant, bucket, object)
	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	newLun := fmt.Sprintf("%d@%s", newLunId, opath)
	c_lun := C.CString(newLun)
	defer C.free(unsafe.Pointer(c_lun))

	svcs := C.CString("svcs")
	defer C.free(unsafe.Pointer(svcs))

	fmt.Printf("Serving new LUN %s\n", newLun)

	var tc C.ccow_t
	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	// create or update LUN
	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	// Skip volume object settings in case of cloned volume
	if !settings.isClonedObject {
		if settings.volumeSize == 0 {
			settings.volumeSize = 10 * 1024 * 1024 * 1024 //10Gb
		}
		if settings.chunkSize == 0 {
			settings.chunkSize = 16384
		}
		if settings.blockSize == 0 {
			settings.blockSize = 4096
		}

		c_volsize_key := C.CString(VOLSIZE_KEY)
		defer C.free(unsafe.Pointer(c_volsize_key))
		ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_UINT64, c_volsize_key, C.int(C.strlen(c_volsize_key)+1),
			unsafe.Pointer(&settings.volumeSize), 8, nil)
		if ret != 0 {
			return fmt.Errorf("%s: ccow_attr_modify_custom %s err=%d", efsutil.GetFUNC(), VOLSIZE_KEY, ret)
		}

		c_blocksize_key := C.CString(BLOCKSIZE_KEY)
		defer C.free(unsafe.Pointer(c_blocksize_key))
		ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_UINT32, c_blocksize_key, C.int(C.strlen(c_blocksize_key)+1),
			unsafe.Pointer(&settings.blockSize), 4, nil)
		if ret != 0 {
			return fmt.Errorf("%s: ccow_attr_modify_custom %s err=%d", efsutil.GetFUNC(), BLOCKSIZE_KEY, ret)
		}

		ret = C.ccow_attr_modify_default(comp, C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE, unsafe.Pointer(&settings.chunkSize), nil)
		if ret != 0 {
			return fmt.Errorf("%s: ccow_attr_modify_default err=%d", efsutil.GetFUNC(), ret)
		}

	}
	ret = C.ccow_admin_pseudo_put(c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, c_bucket, C.strlen(c_bucket)+1,
		c_object, C.strlen(c_object)+1, nil, 0, 0, C.CCOW_PUT, nil, comp)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_put err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	// insert into service object
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_lun)
	iov_name.iov_len = C.strlen(c_lun) + 1
	ret = C.ccow_insert_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_insert_list err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	return nil
}

func (s *ServiceImpl) Serve(ctx context.Context, msg *proto.ServeRequest) (*proto.ServeResponse, error) {

	if msg.Service == "" || msg.Cluster == "" || msg.Tenant == "" {
		return nil, status.Error(400, "missing required field")
	}

	eps := make(map[string]int)

	BuildGrpcEndpoints(&eps, msg.K8SService, msg.K8SNamespace)
	log.Printf("Serve: eps %+v, msg %+v", eps, *msg)

	volumeSettings := VolumeSettings{
		isClonedObject: msg.VolumeSettings.IsClonedObject,
		volumeSize:     msg.VolumeSettings.VolumeSize,
		blockSize:      msg.VolumeSettings.BlockSize,
		chunkSize:      msg.VolumeSettings.ChunkSize,
	}

	// new volume object path
	var volumePath string

	switch t := msg.Type; t {
	case proto.ProtocolType_NFS:
		if msg.Bucket == "" {
			return nil, status.Error(400, "missing required Bucket field")
		}
		nfsIDMutex.Lock()
		newExportId, err := NewExportIdNFS(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket)
		if err != nil {
			nfsIDMutex.Unlock()
			return nil, status.Error(500, err.Error())
		}

		err = InsertServiceObjectNFS(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, newExportId)
		if err != nil {
			nfsIDMutex.Unlock()
			return nil, status.Error(500, err.Error())
		}
		nfsIDMutex.Unlock()

		err = NFSAddExport(eps, msg, newExportId)
		if err != nil {
			NFSRemoveExport(eps, msg, newExportId)
			return nil, status.Error(500, err.Error())
		}

		mountPoint := fmt.Sprintf("%s/%s", msg.Tenant, msg.Bucket)
		volumePath = fmt.Sprintf("%d,%s@%s/%s/%s", newExportId, mountPoint, msg.Cluster, msg.Tenant, msg.Bucket)

	case proto.ProtocolType_ISCSI:

		// CSI will pass the following information:
		//
		// 1. LUN object name
		// 2. Number of stripes
		//
		// Logic below needs to take LUN object name and compound final object name: name.stripe
		// For example for 2 stripes, cltest/test/bk/lun1 will be cltest/test/bk/lun1.0 and cltest/test/bk/lun1.1
		// If stripe == 1, then do not create .stripe extenstion
		//
		// If number of service instances > 1, then stripes can be shuffled in round-robin fashion. I.e.
		// cltest/test/bk/lun1.0 will be assigned to instance 1, and cltest/test/bk/lun1.1 to instance 2.
		// Each iSCSI instance represents TGPG (target portal group) where instance number is group number.
		//

		if msg.Bucket == "" {
			return nil, status.Error(400, "missing required Bucket value")
		}

		if msg.Object == "" {
			return nil, status.Error(400, "missing required Object value")
		}

		iscsiIDMutex.Lock()
		newLunId, err := NewLunIdISCSI(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object)
		if err != nil {
			iscsiIDMutex.Unlock()
			return nil, status.Error(500, err.Error())
		}
		err = InsertServiceObjectISCSI(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, newLunId, volumeSettings)
		if err != nil {
			iscsiIDMutex.Unlock()
			return nil, status.Error(500, err.Error())
		}
		iscsiIDMutex.Unlock()

		err = ISCSIAddLun(eps, msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, newLunId)
		if err != nil {
			DeleteServiceLunISCSI(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, newLunId)
			return nil, status.Error(500, err.Error())
		}
		volumePath = fmt.Sprintf("%d@%s/%s/%s/%s", newLunId, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object)

	default:
		return nil, status.Error(400, "Unsupported protocol type")
	}

	return &proto.ServeResponse{VolumePath: volumePath}, nil
}

func OldExportIdNFS(sname string, cluster string, tenant string, bucket string) (uint32, error) {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" {
		return 0, fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s",
			sname, cluster, tenant, bucket)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	bpath := cluster + "/" + tenant + "/" + bucket
	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	keys, err := efsutil.GetKeys("", "svcs", sname, "")
	if err != nil {
		return 0, err
	}

	var exportId uint32 = 0
	suffix := fmt.Sprintf("%s/%s@%s", tenant, bucket, bpath)
	for _, key := range keys {
		p := strings.Split(key, ",")
		id, e := strconv.Atoi(p[0])
		if e != nil || len(p) < 2 {
			continue
		}

		if strings.Compare(p[1], suffix) == 0 {
			exportId = uint32(id)
			break
		}
	}

	if exportId == 0 {
		return 0, fmt.Errorf("Export not found")
	}

	return exportId, nil
}

func DeleteServiceObjectNFS(sname string, cluster string, tenant string, bucket string, oldExportId uint32) error {
	if sname == "" || cluster == "" || tenant == "" || bucket == "" {
		return fmt.Errorf("Invalid serve request sname: %s, cluster: %s, tenant: %s, bucket: %s",
			sname, cluster, tenant, bucket)
	}

	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	bpath := cluster + "/" + tenant + "/" + bucket
	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	if oldExportId == 0 {
		return fmt.Errorf("Export not found")
	}

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	svcs := C.CString("svcs")
	defer C.free(unsafe.Pointer(svcs))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	oldExport := fmt.Sprintf("%d,%s/%s@%s", oldExportId, tenant, bucket, bpath)

	c_export := C.CString(oldExport)
	defer C.free(unsafe.Pointer(c_export))

	var comp C.ccow_completion_t

	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_export)
	iov_name.iov_len = C.strlen(c_export) + 1
	ret = C.ccow_delete_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_delete_list err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	return nil
}

func DeleteServiceLunISCSI(service, cluster, tenant, bucket, lun string, lunId uint32) error {
	c_service := C.CString(service)
	defer C.free(unsafe.Pointer(c_service))

	opath := fmt.Sprintf("%s/%s/%s/%s", cluster, tenant, bucket, lun)
	path := fmt.Sprintf("%d@%s", lunId, opath)

	keys, err := efsutil.GetKeys("", "svcs", service, "")
	if err != nil {
		return err
	}

	found := false
	for _, key := range keys {
		if strings.Compare(key, path) == 0 {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("LUN %s not found", path)
	}

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	svcs := C.CString("svcs")
	defer C.free(unsafe.Pointer(svcs))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	fmt.Printf("Removing LUN %s\n", path)

	c_path := C.CString(path)
	defer C.free(unsafe.Pointer(c_path))

	var comp C.ccow_completion_t

	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_path)
	iov_name.iov_len = C.strlen(c_path) + 1
	ret = C.ccow_delete_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_delete_list err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	return nil
}

func (s *ServiceImpl) Unserve(ctx context.Context, msg *proto.ServeRequest) (*proto.GenericResponse, error) {

	if msg.Service == "" || msg.Cluster == "" || msg.Tenant == "" {
		return nil, status.Error(400, "missing required field")
	}

	eps := make(map[string]int)

	BuildGrpcEndpoints(&eps, msg.K8SService, msg.K8SNamespace)
	log.Printf("Unserve: eps %+v, msg %+v", eps, *msg)

	switch t := msg.Type; t {
	case proto.ProtocolType_NFS:
		if msg.Bucket == "" {
			return nil, status.Error(400, "missing required Bucket field")
		}

		oldExportId, err := OldExportIdNFS(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket)
		if err != nil {
			return nil, status.Error(500, err.Error())
		}
		err = NFSRemoveExport(eps, msg, oldExportId)
		if err != nil {
			NFSAddExport(eps, msg, oldExportId)
			return nil, status.Error(500, err.Error())
		}
		err = DeleteServiceObjectNFS(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, oldExportId)
		if err != nil {
			return nil, status.Error(500, err.Error())
		}
	case proto.ProtocolType_ISCSI:
		if msg.Bucket == "" {
			return nil, status.Error(400, "missing required Bucket value")
		}

		if msg.Object == "" {
			return nil, status.Error(400, "missing required Object value")
		}

		if msg.VolumeId == 0 {
			return nil, status.Error(400, "missing required volumeId value")
		}

		err := ISCSIRemoveLun(eps, msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, msg.VolumeId)
		if err != nil {
			return nil, status.Error(500, err.Error())
		}

		err = DeleteServiceLunISCSI(msg.Service, msg.Cluster, msg.Tenant, msg.Bucket, msg.Object, msg.VolumeId)
		if err != nil {
			return nil, status.Error(500, err.Error())
		}

	default:
		return nil, status.Error(400, "Unsupported protocol type")
	}

	return &proto.GenericResponse{}, nil
}

func (s *ServiceImpl) SetParam(ctx context.Context, msg *proto.SetParamRequest) (*proto.GenericResponse, error) {
	return &proto.GenericResponse{}, nil
}

func (s *ServiceImpl) ServiceList(ctx context.Context, msg *proto.ServiceListRequest) (*proto.ServiceListResponse, error) {

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

	var bkCnt = msg.Count
	if bkCnt == 0 {
		bkCnt = 1000 // default
	}
	var iter C.ccow_lookup_t
	ret = C.ccow_bucket_lookup(tc, c_pat, C.strlen(c_pat)+1, C.ulong(bkCnt), &iter)
	if ret != 0 {
		if iter != nil {
			C.ccow_lookup_release(iter)
		}

		if ret == -C.ENOENT && (msg.Pattern == "" || len(msg.Pattern) == 0) {
			return &proto.ServiceListResponse{}, nil
		}

		return nil, status.Errorf(500, "ccow_tenant_lookup err=%d", ret)
	}

	info := make(map[string]*proto.ServiceInfo)

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
			info[C.GoString(kv.key)] = &proto.ServiceInfo{Name: C.GoString(kv.key)}
			continue
		}

		cmpRes := strings.Compare(msg.Pattern, C.GoString(kv.key))
		if cmpRes == 0 {
			found = 1
			info[C.GoString(kv.key)] = &proto.ServiceInfo{Name: C.GoString(kv.key)}
		} else if cmpRes < 0 {
			found = 2
			info[C.GoString(kv.key)] = &proto.ServiceInfo{Name: C.GoString(kv.key)}
		}
	}

	C.ccow_lookup_release(iter)

	if found == 0 || (found == 2 && msg.Count == 1) {
		return &proto.ServiceListResponse{}, nil
	}

	// TODO: do second pass on the returned dict and re-fine result
	for _, info := range info {
		props, err := efsutil.GetMDPat("", "svcs", info.Name, "", "X-")
		if err != nil {
			return nil, status.Error(500, "Cannot initialize library")
		}
		log.Printf("Service %s props: %+v", info.Name, props)
		switch props["X-Service-Type"] {
		case "nfs":
			info.Type = proto.ProtocolType_NFS
		case "iscsi":
			info.Type = proto.ProtocolType_ISCSI
			info.Iqn = fmt.Sprintf("%s%s", props["X-ISCSI-TargetName"], props["X-ISCSI-TargetID"])
		}
	}

	return &proto.ServiceListResponse{Info: info}, nil
}

func (s *ServiceImpl) ServiceObjectList(ctx context.Context, msg *proto.ServiceObjectListRequest) (*proto.ServiceObjectListResponse, error) {
	if msg.Service == "" {
		return nil, status.Error(400, "missing required service field ")
	}

	info := make(map[string]*proto.ServiceObjectInfo)
	found := 0
	cnt := int32(0)

	keys, err := efsutil.GetKeys("", "svcs", msg.Service, "")
	if err != nil {
		return nil, status.Error(500, err.Error())
	}

	for _, key := range keys {
		if msg.Count > 0 && cnt >= msg.Count {
			break
		}

		if msg.Pattern == "" || len(msg.Pattern) == 0 {
			found = 1
			info[key] = &proto.ServiceObjectInfo{Name: key}
			cnt++
			continue
		}

		cmpRes := strings.Compare(msg.Pattern, key)
		if cmpRes == 0 {
			found = 1
			info[key] = &proto.ServiceObjectInfo{Name: key}
			cnt++
			continue
		} else if cmpRes < 0 {
			found = 2
			info[key] = &proto.ServiceObjectInfo{Name: key}
			cnt++
			continue
		}
	}

	if found == 0 || (found == 2 && msg.Count == 1) {
		return &proto.ServiceObjectListResponse{}, nil
	}

	return &proto.ServiceObjectListResponse{Info: info}, nil
}
