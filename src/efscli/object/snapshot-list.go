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
	"../validate"
	"github.com/spf13/cobra"
)

func snapshotList(snapViewPath, pattern string, count uint32, flags []efsutil.FlagValue) error {

	c_pattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(c_pattern))

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
	defer C.ccow_snapview_destroy(svtc, snapview_t)

	var snapshotIterator C.ccow_lookup_t

	ret = C.ccow_snapshot_lookup(svtc, snapview_t, c_pattern, C.strlen(c_pattern)+1, C.ulong(count), &snapshotIterator)
	if ret != 0 {
		if snapshotIterator != nil {
			C.ccow_lookup_release(snapshotIterator)
		}

		if ret == -C.ENOENT {
			return nil
		}

		return fmt.Errorf("ccow_snapshot_lookup err=%d\n", ret)
	}

	var kv *C.struct_ccow_metadata_kv
	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(snapshotIterator, C.CCOW_MDTYPE_NAME_INDEX, -1))
		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		if strings.HasPrefix(C.GoString(kv.key), pattern) {
			//found = 1
			if !efsutil.IsSystemName(C.GoString(kv.key)) {
				fmt.Printf("%s\n", C.GoString(kv.key))
			}
			continue
		}
	}
	C.ccow_lookup_release(snapshotIterator)

	return nil
}

var (
	flagsSnapshotList []efsutil.FlagValue

	snapshotListCmd = &cobra.Command{
		Use:   "snapshot-list snapViewPath <namePattern>",
		Short: "list snapshots of specified snapview object",
		Long:  "list snapshots of specified snapview object",
		Args:  validate.Object,
		Run: func(cmd *cobra.Command, args []string) {

			/*edgefs object snapshot-add cl/tn/bk/ob@snapshotName cl/tn/bk/ob.snapview */
			if len(args) < 1 {
				fmt.Printf("Wrong parameters: Should be edgerfs object snapshot-list <snapViewPath>")
				return
			}

			var pattern string
			if len(args) >= 2 {
				pattern = args[1]
			}

			snapViewPathParts := strings.Split(args[0], "/")
			if len(snapViewPathParts) != 4 {
				fmt.Printf("Wrong snapview path: %s", args[0])
				return
			}

			if !strings.HasSuffix(args[0], EDGEFS_SNAPVIEW_SUFFIX) {
				fmt.Printf("Not a snapview path: %s", args[1])
				return
			}

			err := snapshotList(args[0], pattern, 1000000, flagsSnapshotList)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	//flagsSnapshotList = make([]efsutil.FlagValue, len(flagNames))
	//efsutil.ReadAttributes(snapshotListCmd, flagNames, flagsSnapshotList)
	ObjectCmd.AddCommand(snapshotListCmd)
}
