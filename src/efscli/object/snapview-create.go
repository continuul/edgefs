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
package object

/*
#include "ccow.h"
#include "errno.h"
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

const (
	EDGEFS_SNAPVIEW_SUFFIX = ".snapview"
)

func snapViewCreate(opath string, flags []efsutil.FlagValue) error {

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	s := strings.SplitN(opath, "/", 4)

	c_cluster := C.CString(s[0])
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(s[1])
	defer C.free(unsafe.Pointer(c_tenant))

	c_bucket := C.CString(s[2])
	defer C.free(unsafe.Pointer(c_bucket))

	c_object := C.CString(s[3])
	defer C.free(unsafe.Pointer(c_object))

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
		return fmt.Errorf("ccow_tenant_init err=%d\n", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &c)
	if ret != 0 {
		return fmt.Errorf("ccow_create_completion err=%d\n", ret)
	}

	var snapview_t C.ccow_snapview_t
	ret = C.ccow_snapview_create(tc, &snapview_t, c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1)
	if ret != 0 {
		if ret == -C.EEXIST {
			C.ccow_snapview_destroy(tc, snapview_t)
			fmt.Printf("Snapview %s already exists!\n", opath)
			return nil
		}
		return fmt.Errorf("%s: ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}

	C.ccow_snapview_destroy(tc, snapview_t)
	return nil
}

var (
	flagsSnapViewCreate []efsutil.FlagValue

	snapViewCreateCmd = &cobra.Command{
		Use:   "snapview-create <cluster>/<tenant>/<bucket>/<object>.snapview",
		Short: "create a new snapview section",
		Long:  "create a new snapview for specified object",
		Args:  validate.Object,
		Run: func(cmd *cobra.Command, args []string) {

			pathParts := strings.Split(args[0], "/")
			if len(pathParts) != 4 {
				fmt.Printf("Wrong path to object: %s\n", args[0])
				return
			}

			if !strings.HasSuffix(args[0], EDGEFS_SNAPVIEW_SUFFIX) {
				fmt.Printf("Not a snapview object path: %s\n", args[0])
				return
			}

			err := snapViewCreate(args[0], flagsSnapViewCreate)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	//flagsSnapViewCreate = make([]efsutil.FlagValue, len(flagNames))
	//efsutil.ReadAttributes(snapViewCreateCmd, flagNames, flagsSnapViewCreate)
	ObjectCmd.AddCommand(snapViewCreateCmd)
}
