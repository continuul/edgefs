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
package bucket

/*
#include "ccow.h"
#include "ccowfsio.h"
*/
import "C"
import "unsafe"

import (
	"../efsutil"
	"../validate"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func BucketDelete(bpath string) error {
	c_bpath := C.CString(bpath)
	defer C.free(unsafe.Pointer(c_bpath))

	s := strings.Split(bpath, "/")

	c_cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(s[2])
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

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	empty := C.ccow_fsio_is_not_empty(tc, c_bpath, nil)
	if empty == 1 {
		return fmt.Errorf("NFS: Bucket not empty")
	}

	ret = C.ccow_bucket_delete(tc, c_bucket, C.strlen(c_bucket)+1)
	if ret == C.RT_ERR_NOT_EMPTY {
		return fmt.Errorf("Bucket not empty")
	}
	if ret != 0 {
		return fmt.Errorf("Bucket delete err=%d", ret)
	}
	return nil
}

var (
	deleteCmd = &cobra.Command{
		Use:   "delete <cluster>/<tenant>/<bucket>",
		Short: "delete an existing bucket",
		Long:  "delete an existing bucket",
		Args:  validate.Bucket,
		Run: func(cmd *cobra.Command, args []string) {
			err := BucketDelete(args[0])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	BucketCmd.AddCommand(deleteCmd)
}
