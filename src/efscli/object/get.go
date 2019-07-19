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
#include <stdio.h>
#include "ccow.h"
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

func ObjectGet(args []string) error {
	opath := args[0]

	s := strings.SplitN(opath, "/", 4)

	fpath := s[3]

	if len(args) > 1 {
		fpath = args[1]
	}

	c_fpath := C.CString(fpath)
	defer C.free(unsafe.Pointer(c_fpath))

	c_wb := C.CString("wb")
	defer C.free(unsafe.Pointer(c_wb))

	fp, err := C.fopen(c_fpath, c_wb)
	if err != nil {
		return fmt.Errorf("Write input file '%s' error: %v", fpath, err)
	}
	defer C.fclose(fp)

	c_opath := C.CString(opath)
	defer C.free(unsafe.Pointer(c_opath))

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
	var cont_flags C.int = 0
	var max_io_count C.int = 50000
	var genid C.uint64_t = 0
	var n C.uint64_t
	var nw C.uint64_t
	var io_count C.int = 0
	var doff C.uint64_t = 0

	var iter C.ccow_lookup_t

	ret = C.ccow_create_stream_completion(tc, nil, nil, max_io_count, &c,
		c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1,
		&genid, &cont_flags, &iter)
	if ret != 0 {
		return fmt.Errorf("ccow_create_stream_completion err=%d", ret)
	}

	if cont_flags != C.CCOW_CONT_F_EXIST {
		return fmt.Errorf("Object '%s' not found", opath)
	}

	var chunk_size C.uint32_t = C.ccow_chunk_size(c)
	var logical_size C.uint64_t = 0

	var kv *C.struct_ccow_metadata_kv
	var npar = 0
	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
			C.CCOW_MDTYPE_METADATA, -1))
		if kv == nil || npar == 3 {
			break
		}
		if strings.Compare(C.GoString(kv.key), C.RT_SYSKEY_LOGICAL_SIZE) == 0 {
			logical_size = (*(*C.ulong)(kv.value))
			npar++
			continue
		}
		if strings.Compare(C.GoString(kv.key), C.RT_SYSKEY_CHUNKMAP_CHUNK_SIZE) == 0 {
			chunk_size = C.uint32_t(*(*C.ulong)(kv.value))
			npar++
			continue
		}
		if strings.Compare(C.GoString(kv.key), C.RT_SYSKEY_CHUNKMAP_TYPE) == 0 {
			if strings.Compare(C.GoString((*C.char)(kv.value)), "btree_key_val") == 0 {
				return fmt.Errorf("ccow_get_cont err: cannot read kv database")
			}
			npar++
			continue
		}
	}

	c_buf := C.malloc(C.ulong(chunk_size))
	defer C.free(unsafe.Pointer(c_buf))

	var iov C.struct_iovec

	for {
		n = C.uint64_t(chunk_size)

		if (doff + n) > logical_size {
			n = logical_size - doff
		}

		iov.iov_base = unsafe.Pointer(c_buf)
		iov.iov_len = C.ulong(n)

		ret = C.ccow_get_cont(c, &iov, 1, doff, 1, &io_count)
		if ret != 0 {
			return fmt.Errorf("ccow_get_cont err=%d", ret)
		}

		ret = C.ccow_wait(c, io_count)
		if ret != 0 {
			return fmt.Errorf("ccow_wait err=%d", ret)
		}

		nw, _ = C.fwrite(c_buf, 1, n, fp)
		if nw < n {
			return fmt.Errorf("File write error")
		}

		doff += n
		if doff >= logical_size {
			break
		}

		if io_count == max_io_count { // Reopen
			ret = C.ccow_cancel(c)
			if ret != 0 {
				return fmt.Errorf("cannot cancel err=%d", ret)
			}
			io_count = 0

			ret = C.ccow_create_stream_completion(tc, nil, nil, max_io_count, &c,
				c_bucket, C.strlen(c_bucket)+1, c_object, C.strlen(c_object)+1,
				&genid, &cont_flags, nil)
			if ret != 0 {
				return fmt.Errorf("ccow_create_stream_completion err=%d", ret)
			}
		}

	}

	if io_count > 0 {
		ret = C.ccow_cancel(c)
		if ret != 0 {
			return fmt.Errorf("cannot cancel err=%d", ret)
		}
	}

	return nil
}

var (
	getCmd = &cobra.Command{
		Use:   "get  <cluster>/<tenant>/<bucket>/<object> [<file>]",
		Short: "get a new object",
		Long:  "get a new object from cluster and write to file",
		Args:  validate.ObjectGet,
		Run: func(cmd *cobra.Command, args []string) {
			err := ObjectGet(args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	ObjectCmd.AddCommand(getCmd)
}
