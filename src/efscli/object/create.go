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
*/
import "C"
import "unsafe"

import (
	"fmt"
	"os"
	"strings"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

func objectCreate(opath string, flags []efsutil.FlagValue) error {
	e := validate.Flags(flags)
	if e != nil {
		return e
	}

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

	s := strings.SplitN(opath, "/", 4)

	bucket, errb := efsutil.GetMDPat(s[0], s[1], s[2], "", "")
	if errb != nil {
		return errb
	}

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
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	var c C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &c)
	if ret != 0 {
		return fmt.Errorf("ccow_create_completion err=%d", ret)
	}

	err = efsutil.InheritBucketAttributes(unsafe.Pointer(c), bucket)
	if err != nil {
		return err
	}

	err = efsutil.ModifyDefaultAttributes(unsafe.Pointer(c), flags)
	if err != nil {
		return err
	}

	ret = C.ccow_put(c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1, c,
		nil, 0, 0)
	if ret != 0 {
		return fmt.Errorf("ccow_put err=%d", ret)
	}

	ret = C.ccow_wait(c, 0)
	if ret != 0 {
		return fmt.Errorf("object_put wait err=%d", ret)
	}

	if efsutil.HasCustomAttributes(flags) {
		return efsutil.ModifyCustomAttributes(s[0], s[1], s[2], s[3], flags)
	}

	return nil
}

var (
	flagsCreate []efsutil.FlagValue

	createCmd = &cobra.Command{
		Use:   "create <cluster>/<tenant>/<bucket>/<object>",
		Short: "create a new object",
		Long:  "create a new object",
		Args:  validate.Object,
		Run: func(cmd *cobra.Command, args []string) {
			err := objectCreate(args[0], flagsCreate)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	flagsCreate = make([]efsutil.FlagValue, len(flagNames))
	efsutil.ReadAttributes(createCmd, flagNames, flagsCreate)
	ObjectCmd.AddCommand(createCmd)
}
