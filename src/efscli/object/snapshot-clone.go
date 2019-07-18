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

	"../efsutil"
	//"../validate"
	"github.com/spf13/cobra"
)

func snapshotClone(snapViewPath, snapshotName, cloneObjectPath string, flags []efsutil.FlagValue) error {

	c_ssName := C.CString(snapshotName)
	defer C.free(unsafe.Pointer(c_ssName))

	// SnapView path parts
	c_svPath := C.CString(snapViewPath)
	defer C.free(unsafe.Pointer(c_svPath))

	snapPathParts := strings.SplitN(snapViewPath, "/", 4)

	c_svCluster := C.CString(snapPathParts[0])
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(snapPathParts[1])
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(snapPathParts[2])
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapPathParts[3])
	defer C.free(unsafe.Pointer(c_svObject))

	// cloneObject path parts
	cloneObjectParts := strings.SplitN(cloneObjectPath, "/", 4)
	c_cloneCluster := C.CString(cloneObjectParts[0])
	defer C.free(unsafe.Pointer(c_cloneCluster))

	c_cloneTenant := C.CString(cloneObjectParts[1])
	defer C.free(unsafe.Pointer(c_cloneTenant))

	c_cloneBucket := C.CString(cloneObjectParts[2])
	defer C.free(unsafe.Pointer(c_cloneBucket))

	c_cloneObject := C.CString(cloneObjectParts[3])
	defer C.free(unsafe.Pointer(c_cloneObject))

	// Libccow Init
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	//SnapView ccow_t
	var svtc C.ccow_t
	ret := C.ccow_tenant_init(c_conf, c_svCluster, C.strlen(c_svCluster)+1,
		c_svTenant, C.strlen(c_svTenant)+1, &svtc)
	if ret != 0 {
		return fmt.Errorf("%: snapView ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(svtc)

	var svc C.ccow_completion_t
	ret = C.ccow_create_completion(svtc, nil, nil, 1, &svc)
	if ret != 0 {
		return fmt.Errorf("%s: snapview ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	var snapview_t C.ccow_snapview_t
	ret = C.ccow_snapview_create(svtc, &snapview_t, c_svBucket, C.strlen(c_svBucket)+1, c_svObject, C.strlen(c_svObject)+1)
	if ret != 0 && ret != -C.EEXIST {
		return fmt.Errorf("%s: snapView ccow_snapview_create err=%d\n", efsutil.GetFUNC(), ret)
	}

	//clone ccow_t
	var clonetc C.ccow_t
	ret = C.ccow_tenant_init(c_conf, c_cloneCluster, C.strlen(c_cloneCluster)+1,
		c_cloneTenant, C.strlen(c_cloneTenant)+1, &clonetc)
	if ret != 0 {
		return fmt.Errorf("%s: clone ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(clonetc)

	//clone completion
	var clonec C.ccow_completion_t
	ret = C.ccow_create_completion(clonetc, nil, nil, 1, &clonec)
	if ret != 0 {
		return fmt.Errorf("%s: clone ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_clone_snapview_object(svtc,
		snapview_t,
		c_ssName,
		C.strlen(c_ssName)+1,
		c_cloneTenant,
		C.strlen(c_cloneTenant)+1,
		c_cloneBucket,
		C.strlen(c_cloneBucket)+1,
		c_cloneObject,
		C.strlen(c_cloneObject)+1)
	if ret != 0 {
		if ret == -C.EEXIST {
			C.ccow_snapview_destroy(svtc, snapview_t)
			fmt.Printf("Clone %s already exists \n", cloneObjectPath)
			return nil
		}

		if ret == -C.ENOENT {
			C.ccow_snapview_destroy(svtc, snapview_t)
			fmt.Printf("Object for snapview %s d esnt exists \n", cloneObjectPath)
			return nil
		}

		return fmt.Errorf("%s: clone ccow_clone_snapview_object=%d\n", efsutil.GetFUNC(), ret)
	}

	fmt.Printf("Snapshot %s has been cloned to %s\n", snapshotName, cloneObjectPath)
	defer C.ccow_snapview_destroy(svtc, snapview_t)

	return nil
}

var (
	flagsSnapshotClone []efsutil.FlagValue

	snapshotCloneCmd = &cobra.Command{
		Use:   "snapshot-clone object.snapview snapshot cloneDestinationObject",
		Long:  "clone existing snapview's snapshot to a new destination object",
		Short: "clone snapshot to object",
		//Args:  validate.Object,
		Run: func(cmd *cobra.Command, args []string) {

			/*edgefs object snapshot-add cl/tn/bk/ob@snapshotName cl/tn/bk/ob.snapview */
			if len(args) != 3 {
				fmt.Printf("Wrong parameters: Should be 'edgefs object snapshot-clone object.snapview snapshotPath cloneDestination'\n")
				return
			}

			snapViewPathParts := strings.Split(args[0], "/")
			if len(snapViewPathParts) != 4 {
				fmt.Printf("Wrong snapview path: %s", args[0])
				return
			}

			if !strings.HasSuffix(args[0], EDGEFS_SNAPVIEW_SUFFIX) {
				fmt.Printf("Not a snapview path: %s", args[0])
				return
			}

			snapshotParts := strings.Split(args[1], "@")
			if len(snapshotParts) != 2 {
				fmt.Printf("Wrong object snapshot format %s. Should be <cluster>/<tenant>/<bucket>/<object>@<name>\n", args[1])
				return
			}

			snapshotPathParts := strings.Split(snapshotParts[0], "/")
			if len(snapshotPathParts) != 4 {
				fmt.Printf("Wrong object snapshot path: %s", snapshotPathParts[0])
				return
			}

			clonePathParts := strings.Split(args[2], "/")
			if len(clonePathParts) != 4 {
				fmt.Printf("Wrong clone destinaion path: %s", args[2])
				return
			}

			err := snapshotClone(args[0], args[1], args[2], flagsSnapshotClone)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	//flagsSnapshotClone = make([]efsutil.FlagValue, len(flagNames))
	//efsutil.ReadAttributes(snapshotCloneCmd, flagNames, flagsSnapshotClone)
	ObjectCmd.AddCommand(snapshotCloneCmd)
}
