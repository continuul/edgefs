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
package service

/*
#include "ccow.h"
*/
import "C"
import "unsafe"

import (
	"../efsutil"
	"../validate"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/im-kulikov/sizefmt"
	"os"
	"strconv"
	"strings"
)

func ServiceServeISCSI(sname string, opath string, opts string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	err := validate.ServiceIscsiOpts(opath, opts)
	if err != nil {
		return err
	}

	s := strings.Split(opath, "/")
	var cluster string = s[0]
	var tenant string = s[1]
	var bucket string = s[2]
	var object string = s[3]

	VOLSIZE_KEY := "X-volsize"
	BLOCKSIZE_KEY := "X-blocksize"
	CHUNKSIZE_KEY := "ccow-chunkmap-chunk-size"

	var newlun bool = false
	var blocksize uint32 = 4096
	var volsize uint64 = 10 * 1024 * 1024 * 1024
	var chunksize uint32 = 16384
	chunksizeStr, err := efsutil.GetMDKey(cluster, tenant, bucket, object, CHUNKSIZE_KEY)
	if err != nil {
		chunksize = 16384
		// if we cannot read chunksize, then it is likely that
		// object isn't yet initialized, set the rest of parameters
		newlun = true
	} else {
		v, err := strconv.ParseUint(chunksizeStr, 10, 32)
		if err == nil {
			chunksize = uint32(v)
		}
		blocksizeStr, err := efsutil.GetMDKey(cluster, tenant, bucket, object, BLOCKSIZE_KEY)
		if err == nil {
			v, err = strconv.ParseUint(blocksizeStr, 10, 32)
			if err == nil {
				blocksize = uint32(v)
			}
		}
		volsizeStr, err := efsutil.GetMDKey(cluster, tenant, bucket, object, VOLSIZE_KEY)
		if err == nil {
			v, err = strconv.ParseUint(volsizeStr, 10, 64)
			if err == nil {
				volsize = v
			}
		}
	}

	for _,p := range strings.Split(opts, ",") {
		s := strings.Split(p, "=")
		if s[0] == VOLSIZE_KEY {
			bytes, err := sizefmt.ToBytes(s[1])
			if err != nil {
				return err
			}
			volsize = uint64(bytes)
		}
		if s[0] == BLOCKSIZE_KEY {
			bytes, err := sizefmt.ToBytes(s[1])
			if err != nil {
				return err
			}
			blocksize = uint32(bytes)
		}
		if newlun && s[0] == CHUNKSIZE_KEY {
			bytes, err := sizefmt.ToBytes(s[1])
			if err != nil {
				return err
			}
			chunksize = uint32(bytes)
		}
	}

	var maxLunId int = 0

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
	}

	suffix := fmt.Sprintf("@%s", opath)
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
			return fmt.Errorf("LUN already exists: %s", suffix)
		}
	}

	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(bucket)
	defer C.free(unsafe.Pointer(c_bucket))

	c_object := C.CString(object)
	defer C.free(unsafe.Pointer(c_object))

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

	newLun := fmt.Sprintf("%d@%s", (maxLunId + 1), opath)
	fmt.Printf("Serving new LUN %s\n", newLun)

	c_lun := C.CString(newLun)
	defer C.free(unsafe.Pointer(c_lun))

	var comp C.ccow_completion_t

	// create or update LUN
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	c_volsize_key := C.CString(VOLSIZE_KEY)
	defer C.free(unsafe.Pointer(c_volsize_key))
	ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_UINT64, c_volsize_key, C.int(C.strlen(c_volsize_key)+1),
	    unsafe.Pointer(&volsize), 8, nil)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_attr_modify_custom %s err=%d", efsutil.GetFUNC(), VOLSIZE_KEY, ret)
	}

	c_blocksize_key := C.CString(BLOCKSIZE_KEY)
	defer C.free(unsafe.Pointer(c_blocksize_key))
	ret = C.ccow_attr_modify_custom(comp, C.CCOW_KVTYPE_UINT32, c_blocksize_key, C.int(C.strlen(c_blocksize_key)+1),
	    unsafe.Pointer(&blocksize), 4, nil)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_attr_modify_custom %s err=%d", efsutil.GetFUNC(), BLOCKSIZE_KEY, ret)
	}

	ret = C.ccow_attr_modify_default(comp, C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE, unsafe.Pointer(&chunksize), nil)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_attr_modify_default err=%d", efsutil.GetFUNC(), ret)
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

func ServiceServeNFS(sname string, bpath string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	s := strings.Split(bpath, "/")
	if len(s) != 3 {
		return errors.New("Requires <service> <cluster>/<tenant>/<bucket>")
	}
	var tenant string = s[1]
	var bucket string = s[2]

	var maxExportId int = 1

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
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
			return fmt.Errorf("Export already exists: %s", suffix)
		}
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

	newExport := fmt.Sprintf("%d,%s/%s@%s", (maxExportId + 1), tenant, bucket, bpath)
	fmt.Printf("Serving new export %s\n", newExport)

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

func ServiceServeS3(sname string, tpath string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_tpath := C.CString(tpath)
	defer C.free(unsafe.Pointer(c_tpath))

	s := strings.Split(tpath, "/")
	if len(s) != 2 {
		return errors.New("Requires <service> <cluster>/<tenant>")
	}
	var cluster string = s[0]
	var tenant string = s[1]

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
	}

	var count = 0
	for _, key := range keys {
		if strings.Compare(key, tpath) == 0 {
			return fmt.Errorf("Export already exists: %s", key)
		}
		count++
	}

	if count > 0 {
		return fmt.Errorf("Can't serve more then one tenant")
	}

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

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

	fmt.Printf("Serving new tenant %s\n", tpath)

	c_export := C.CString(tpath)
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

func ServiceServeISGW(sname string, bpath string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	s := strings.Split(bpath, "/")
	if len(s) != 2 && len(s) != 3 {
		return errors.New("Requires <service> <cluster>/<tenant>[/<bucket>][,options]")
	}

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
	}

	oldkey := ""
	for _, key := range keys {
		if strings.Compare(key, bpath) == 0 {
			return fmt.Errorf("Already serving: %s", key)
		}
		skey := strings.Split(key,",")
		sbpath := strings.Split(bpath,",")
		if skey[0] == sbpath[0] {
			oldkey = key
		}
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

	fmt.Printf("Serving new %s\n", bpath)

	c_export := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_export))

	var comp C.ccow_completion_t

	ret = C.ccow_create_completion(tc, nil, nil, 2, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", efsutil.GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	if (len(oldkey) > 0) {
		c_old := C.CString(oldkey)
		defer C.free(unsafe.Pointer(c_old))
		iov_name.iov_base = unsafe.Pointer(c_old)
		iov_name.iov_len = C.strlen(c_old) + 1
		ret = C.ccow_delete_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
		if ret != 0 {
			C.ccow_release(comp)
			return fmt.Errorf("%s: ccow_delete_list err=%d", efsutil.GetFUNC(), ret)
		}

		ret = C.ccow_wait(comp, -1)
		if ret != 0 {
			return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
		}
	}

	iov_name.iov_base = unsafe.Pointer(c_export)
	iov_name.iov_len = C.strlen(c_export) + 1
	ret = C.ccow_insert_list(c_service, C.strlen(c_service)+1, cl, 1, comp, &iov_name, 1)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_insert_list err=%d", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, -1)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", efsutil.GetFUNC(), ret)
	}

	return nil
}

func ServiceServe(args []string) error {
	sname := args[0]
	bpath := args[1]

	stype, err := efsutil.GetMDKey("", "svcs", sname, "", "X-Service-Type")

	opts := ""
	if len(args) > 2 {
		opts = args[2]
	}

	if err != nil {
		return err
	}

	c_stype := C.CString(stype)
	defer C.free(unsafe.Pointer(c_stype))

	c_nfs := C.CString("nfs")
	defer C.free(unsafe.Pointer(c_nfs))

	c_s3 := C.CString("s3")
	defer C.free(unsafe.Pointer(c_s3))

	c_s3x := C.CString("s3x")
	defer C.free(unsafe.Pointer(c_s3x))

	c_iscsi := C.CString("iscsi")
	defer C.free(unsafe.Pointer(c_iscsi))

	c_isgw := C.CString("isgw")
	defer C.free(unsafe.Pointer(c_isgw))

	if C.strcmp(c_stype, c_iscsi) == 0 {
		return ServiceServeISCSI(sname, bpath, opts)
	}

	if C.strcmp(c_stype, c_nfs) == 0 {
		return ServiceServeNFS(sname, bpath)
	}

	if C.strcmp(c_stype, c_s3) == 0 {
		return ServiceServeS3(sname, bpath)
	}

	if C.strcmp(c_stype, c_s3x) == 0 {
		return ServiceServeS3(sname, bpath)
	}

	if C.strcmp(c_stype, c_isgw) == 0 {
		return ServiceServeISGW(sname, bpath)
	}

	return fmt.Errorf("Unknown service type |%s|", stype)
}

var (
	serveCmd = &cobra.Command{
		Use:   "serve <service> <path> [options]",
		Short: "serve an existing service",
		Long:  "serve an existing service",
		Args:  validate.Serve,
		Run: func(cmd *cobra.Command, args []string) {
			err := ServiceServe(args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	ServiceCmd.AddCommand(serveCmd)
}
