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
	"fmt"
	"os"
	"strings"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"
	"github.com/spf13/cobra"
)

func BucketCreate(bpath string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}

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

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &c)
	if ret != 0 {
		return fmt.Errorf("ccow_create_completion err=%d", ret)
	}

	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	ret = C.ccow_bucket_create(tc, c_bucket, C.strlen(c_bucket)+1, c)
	if ret != 0 {
		return fmt.Errorf("bucket_create err=%d", ret)
	}

	if efsutil.HasCustomAttributes(flags) {
		nhid, err := efsutil.GetMDKey(s[0], s[1], s[2], "", "ccow-name-hash-id")
		if err != nil {
			return err
		}
		return efsutil.ModifyCustomAttributes(s[0], s[1], s[2], nhid, flags)
	}

	return nil
}

var (
	flagNames = []string{
		"chunk-size",
		"number-of-versions",
		"replication-count",
		"sync-put",
		"ec-data-mode",
		"ec-trigger-policy-timeout",
		"encryption-enabled",
		"select-policy",
		"quota",
		"quota-count",
		"file-object-transparency",
		"options",
	}
	flags []efsutil.FlagValue

	createCmd = &cobra.Command{
		Use:   "create  <cluster>/<tenant>/<bucket>",
		Short: "create a new bucket",
		Long:  "create a new bucket",
		Args:  validate.Bucket,
		Run: func(cmd *cobra.Command, args []string) {
			err := BucketCreate(args[0], flags)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	flags = make([]efsutil.FlagValue, len(flagNames))
	efsutil.ReadAttributes(createCmd, flagNames, flags)
	BucketCmd.AddCommand(createCmd)
}
