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

func snapshotRm(snapViewPath, sourceSnapshotPath string, flags []efsutil.FlagValue) error {

	c_svPath := C.CString(snapViewPath)
	defer C.free(unsafe.Pointer(c_svPath))

	// SnapView path parts
	snapPathParts := strings.SplitN(snapViewPath, "/", 4)

	c_svCluster := C.CString(snapPathParts[0])
	defer C.free(unsafe.Pointer(c_svCluster))

	c_svTenant := C.CString(snapPathParts[1])
	defer C.free(unsafe.Pointer(c_svTenant))

	c_svBucket := C.CString(snapPathParts[2])
	defer C.free(unsafe.Pointer(c_svBucket))

	c_svObject := C.CString(snapPathParts[3])
	defer C.free(unsafe.Pointer(c_svObject))

	// SourceObject and Snapshot path parts
	snapshotPathParts := strings.Split(sourceSnapshotPath, "@")
	snapshotObjectPath := strings.SplitN(snapshotPathParts[0], "/", 4)

	c_snapshot := C.CString(sourceSnapshotPath)
	defer C.free(unsafe.Pointer(c_snapshot))

	c_ssCluster := C.CString(snapshotObjectPath[0])
	defer C.free(unsafe.Pointer(c_ssCluster))

	c_ssTenant := C.CString(snapshotObjectPath[1])
	defer C.free(unsafe.Pointer(c_ssTenant))

	c_ssBucket := C.CString(snapshotObjectPath[2])
	defer C.free(unsafe.Pointer(c_ssBucket))

	c_ssObject := C.CString(snapshotObjectPath[3])
	defer C.free(unsafe.Pointer(c_ssObject))

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

	//Snapshot ccow_t
	var sstc C.ccow_t
	ret = C.ccow_tenant_init(c_conf, c_ssCluster, C.strlen(c_ssCluster)+1,
		c_ssTenant, C.strlen(c_ssTenant)+1, &sstc)
	if ret != 0 {
		return fmt.Errorf("%s: snapshot ccow_tenant_init err=%d\n", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(sstc)

	//Snapshot completion
	var ssc C.ccow_completion_t
	ret = C.ccow_create_completion(sstc, nil, nil, 1, &ssc)
	if ret != 0 {
		return fmt.Errorf("%s: snapshot ccow_create_completion err=%d\n", efsutil.GetFUNC(), ret)
	}

	ret = C.ccow_snapshot_delete(sstc, snapview_t, c_snapshot, C.strlen(c_snapshot)+1)
	if ret != 0 {
		if ret == -C.ENOENT {
			C.ccow_snapview_destroy(svtc, snapview_t)
			fmt.Printf("Snapshot %s not exists in the snapview %s\n", sourceSnapshotPath, snapViewPath)
			return nil
		}

		return fmt.Errorf("%s: snapshot ccow_snapshot_create=%d\n", efsutil.GetFUNC(), ret)
	}

	fmt.Printf("Snapshot %s has been removed from %s\n", sourceSnapshotPath, snapViewPath)
	defer C.ccow_snapview_destroy(svtc, snapview_t)

	return nil
}

var (
	flagsSnapshotRm []efsutil.FlagValue

	snapshotRmCmd = &cobra.Command{
		Use:   "snapshot-rm <snapViewPath> <snapshotPath>",
		Short: "remove snapshot from snapview",
		Long:  "remove snapshot from specified snapview object",
		//Args:  validate.Object,
		Run: func(cmd *cobra.Command, args []string) {

			/*edgefs object snapshot-rm cl/tn/bk/ob@snapshotName cl/tn/bk/ob.snapview */
			if len(args) != 2 {
				fmt.Printf("Wrong parameters: Should be 'edgefs object snapshot-rm <snapViewPath> <snapshotPath>'\n")
				return
			}

			snapViewPathParts := strings.Split(args[0], "/")
			if len(snapViewPathParts) != 4 {
				fmt.Printf("Wrong snapview path: %s\n", args[1])
				return
			}

			if !strings.HasSuffix(args[0], EDGEFS_SNAPVIEW_SUFFIX) {
				fmt.Printf("Not a snapview path: %s\n", args[1])
				return
			}

			srcPathParts := strings.Split(args[1], "@")
			if len(srcPathParts) != 2 {
				fmt.Printf("Wrong object snapshot format %s. Should be <cluster>/<tenant>/<bucket>/<object>@<snapshotName>\n", args[0])
				return
			}

			pathParts := strings.Split(srcPathParts[0], "/")
			if len(pathParts) != 4 {
				fmt.Printf("Wrong object snapshot path: %s\n", srcPathParts[0])
				return
			}

			err := snapshotRm(args[0], args[1], flagsSnapshotRm)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	//flagsSnapshotRm = make([]efsutil.FlagValue, len(flagNames))
	//efsutil.ReadAttributes(snapshotRmCmd, flagNames, flagsSnapshotRm)
	ObjectCmd.AddCommand(snapshotRmCmd)
}
