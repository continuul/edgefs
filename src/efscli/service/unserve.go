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
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"
	"github.com/spf13/cobra"
)

func ServiceUnserveISCSI(sname string, path string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	s := strings.Split(path, "@")
	if len(s) != 2 {
		return errors.New("Requires <service> id@<cluster>/<tenant>/<bucket>/<object>")
	}
	opath := s[1]

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	s = strings.Split(opath, "/")
	if len(s) < 4 {
		return errors.New("Requires <service> id@<cluster>/<tenant>/<bucket>/<object>")
	}

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
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
		return fmt.Errorf("LUN not found")
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

func ServiceUnserveNFS(sname string, bpath string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	s := strings.Split(bpath, "/")
	if len(s) != 3 {
		return errors.New("Requires <service> <cluster>/<tenant>/<bucket>")
	}
	var cluster string = s[0]
	var tenant string = s[1]
	var bucket string = s[2]

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
	}

	var exportId int = 0
	var oldExport string = ""
	suffix := fmt.Sprintf("%s/%s@%s", tenant, bucket, bpath)
	for _, key := range keys {
		p := strings.Split(key, ",")
		id, e := strconv.Atoi(p[0])
		if e != nil || len(p) < 2 {
			continue
		}

		if strings.Compare(p[1], suffix) == 0 {
			exportId = id
			oldExport = key
			break
		}
	}

	if exportId == 0 {
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

	fmt.Printf("Removing export %s\n", oldExport)

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

func ServiceUnserveS3(sname string, tpath string) error {
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
			count++
			break
		}
	}

	if count == 0 {
		return fmt.Errorf("Export not found")
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

	fmt.Printf("Removing export %s\n", tpath)

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

func ServiceUnserveISGW(sname string, bpath string) error {
	c_service := C.CString(sname)
	defer C.free(unsafe.Pointer(c_service))

	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	s := strings.Split(bpath, "/")
	if len(s) != 3 && len(s) != 2 {
		return errors.New("Requires <service> <cluster>/<tenant>[/<bucket>]")
	}

	keys, err := efsutil.GetKeys("", "svcs", sname, "", 1000)
	if err != nil {
		return err
	}

	var count = 0
	for _, key := range keys {
		if key == bpath {
			count++
			break
		}
	}

	if count == 0 {
		return fmt.Errorf("Bucket not found: %s", bpath)
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

	fmt.Printf("Removing %s\n", bpath)

	c_export := C.CString(bpath)
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

func ServiceUnserve(sname string, bpath string) error {
	stype, err := efsutil.GetMDKey("", "svcs", sname, "", "X-Service-Type")

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
		return ServiceUnserveISCSI(sname, bpath)
	}

	if C.strcmp(c_stype, c_nfs) == 0 {
		return ServiceUnserveNFS(sname, bpath)
	}

	if C.strcmp(c_stype, c_s3) == 0 {
		return ServiceUnserveS3(sname, bpath)
	}

	if C.strcmp(c_stype, c_s3x) == 0 {
		return ServiceUnserveS3(sname, bpath)
	}

	if C.strcmp(c_stype, c_isgw) == 0 {
		return ServiceUnserveISGW(sname, bpath)
	}

	return fmt.Errorf("Unknown service type |%s|", stype)
}

var (
	unserveCmd = &cobra.Command{
		Use:   "unserve <service> <path>",
		Short: "unserve an existing service",
		Long:  "unserve an existing service",
		Args:  validate.Serve,
		Run: func(cmd *cobra.Command, args []string) {
			err := ServiceUnserve(args[0], args[1])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	ServiceCmd.AddCommand(unserveCmd)
}
