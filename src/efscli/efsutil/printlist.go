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
package efsutil

/*
#include "ccow.h"
#include "errno.h"
#include "msgpackalt.h"
#include "msgpackccow.h"
*/
import "C"
import "unsafe"

import (
	"fmt"
	"strings"
)
var (
	ondemandPolicyName = [...]string {"LOCAL", "CACHED", "PINNED", "PERSISTENT"}
)

func GetOndemandPolicyString(cl string, tn string, bk string, obj string) (string, error) {
	inline_str,err := GetMDKey(cl, tn, bk, obj, "ccow-inline-data-flags")
		if err != nil {
			return "", fmt.Errorf("%s: error fetching metadata for object %v: %v",
				GetFUNC(), obj, err)
		}
		inline := 0
		n,err := fmt.Sscanf(inline_str, "%d", &inline);
		if err != nil || n != 1 {
				return "", fmt.Errorf("%s: error parsing inline propery of object %v: %v",
					GetFUNC(), obj, inline_str)
		}
		return ondemandPolicyName[(inline>>12) & 3], nil

}

func PrintKeyValues(cl string, tn string, bk string, obj string, pat string, cmp int, count int, extended bool) (string, error) {
	conf, err := GetLibccowConf()
	if err != nil {
		return "", err
	}

	c_pat := C.CString(pat)
	defer C.free(unsafe.Pointer(c_pat))

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return "", fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_cl := C.CString(cl)
	defer C.free(unsafe.Pointer(c_cl))

	c_tn := C.CString(tn)
	defer C.free(unsafe.Pointer(c_tn))

	c_bk := C.CString(bk)
	defer C.free(unsafe.Pointer(c_bk))

	c_obj := C.CString(obj)
	defer C.free(unsafe.Pointer(c_obj))

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return "", fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_pat)
	iov_name.iov_len = C.strlen(c_pat) + 1

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, &iov_name, 1, C.ulong(count), C.CCOW_GET_LIST,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return "", fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret == -C.ENOENT {
		return "", nil
	}
	if ret != 0 {
		return "", fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	var last string = ""
	defer C.ccow_lookup_release(iter)
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
			C.CCOW_MDTYPE_NAME_INDEX, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		gkey := C.GoString(kv.key)
		cmpRes := strings.Compare(gkey, pat)
		if cmpRes < cmp {
			continue
		}
		last = gkey

		var ver C.uint8_t
		u, _ := C.msgpack_unpack_init(kv.value, C.uint(kv.value_size), 0)
		if u == nil {
			return "", fmt.Errorf("%s: unpack init err=%d", GetFUNC(), ret)
		}
		defer C.msgpack_unpack_free(u)

		r, _ := C.msgpack_unpack_uint8(u, &ver)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack version err=%d", GetFUNC(), ret)
		}
		if ver != 1 {
			continue
		}

		var object_deleted C.uint8_t
		r, _ = C.msgpack_unpack_uint8(u, &object_deleted)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object err=%d", GetFUNC(), ret)
		}

		var timestamp C.uint64_t
		r, _ = C.msgpack_unpack_uint64(u, &timestamp)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object timestamp err=%d", GetFUNC(), ret)
		}

		var generation C.uint64_t
		r, _ = C.msgpack_unpack_uint64(u, &generation)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object generation err=%d", GetFUNC(), ret)
		}

		var vmchid C.uint512_t
		r, _ = C.msgpack_unpack_uint512(u, &vmchid)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object vmchid err=%d", GetFUNC(), ret)
		}

		buf := make([]byte, C.UINT512_BYTES*2+1)
		c_buf := C.CString(string(buf))
		defer C.free(unsafe.Pointer(c_buf))

		C.uint512_dump(&vmchid, c_buf, C.UINT512_BYTES*2+1)
		schid := C.GoString(c_buf)

		r, _ = C.msgpack_unpack_str(u, c_buf, 128)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object etag=%d", GetFUNC(), ret)
		}

		r, _ = C.msgpack_unpack_str(u, c_buf, 128)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object content_type=%d", GetFUNC(), ret)
		}

		var size C.uint64_t
		r, _ = C.msgpack_unpack_uint64(u, &size)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object size err=%d", GetFUNC(), ret)
		}
		if extended {
			inline_str,err := GetMDKey(cl, tn, bk, gkey, "ccow-inline-data-flags")
			if err != nil {
				return "", fmt.Errorf("%s: error fetching metadata for object %v err=%d",
					GetFUNC(), gkey, ret)
			}
			inline := 0
			n,err := fmt.Sscanf(inline_str, "%d", &inline);
			if err != nil || n != 1 {
					return "", fmt.Errorf("%s: error parsing inline propery of object %v: %v",
						GetFUNC(), gkey, inline_str)
			}
			polstr := ondemandPolicyName[(inline>>12) & 3]
			fmt.Printf("%20s\t%10s %v %v %v %v %v\n", gkey, polstr,
				object_deleted, timestamp, generation, schid[0:16], size)
		} else {
			fmt.Printf("%20s\t%v %v %v %v %v\n", gkey,
				object_deleted, timestamp, generation, schid[0:16], size)
		}
	}

	return last, nil
}

func PrintKeyStrValues(cl string, tn string, bk string, obj string, pat string, cmp int, max_len int, count int) (string, error) {
	conf, err := GetLibccowConf()
	if err != nil {
		return "", err
	}

	c_pat := C.CString(pat)
	defer C.free(unsafe.Pointer(c_pat))

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return "", fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_cl := C.CString(cl)
	defer C.free(unsafe.Pointer(c_cl))

	c_tn := C.CString(tn)
	defer C.free(unsafe.Pointer(c_tn))

	c_bk := C.CString(bk)
	defer C.free(unsafe.Pointer(c_bk))

	c_obj := C.CString(obj)
	defer C.free(unsafe.Pointer(c_obj))

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return "", fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(c_pat)
	iov_name.iov_len = C.strlen(c_pat) + 1

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, &iov_name, 1, C.ulong(count), C.CCOW_GET_LIST,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return "", fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret == -C.ENOENT {
		return "", nil
	}
	if ret != 0 {
		return "", fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	var last string = ""
	defer C.ccow_lookup_release(iter)
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
			C.CCOW_MDTYPE_NAME_INDEX, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}

		gkey := C.GoString(kv.key)
		cmpRes := strings.Compare(gkey, pat)
		if cmpRes < cmp {
			continue
		}
		last = gkey

		var ver C.uint8_t
		u, _ := C.msgpack_unpack_init(kv.value, C.uint(kv.value_size), 0)
		if u == nil {
			return "", fmt.Errorf("%s: unpack init err=%d", GetFUNC(), ret)
		}
		defer C.msgpack_unpack_free(u)

		r, _ := C.msgpack_unpack_uint8(u, &ver)
		if r != 0 {
			return "", fmt.Errorf("%s: unpack version err=%d", GetFUNC(), ret)
		}
		if ver != 2 {
			continue
		}

		buf := make([]byte, max_len+1)
		c_buf := C.CString(string(buf))
		defer C.free(unsafe.Pointer(c_buf))

		r, _ = C.msgpack_unpack_str(u, c_buf, C.uint(max_len))
		if r != 0 {
			return "", fmt.Errorf("%s: unpack object=%d", GetFUNC(), ret)
		}

		gvalue := C.GoString(c_buf)

		fmt.Printf("%s: %v\n", gkey, gvalue)
	}

	return last, nil
}

func PrintKeys(cl string, tn string, bk string, obj string, count int) error {
	conf, err := GetLibccowConf()
	if err != nil {
		return err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	clempty := C.CString("")
	defer C.free(unsafe.Pointer(clempty))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, clempty, 1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_admin_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_cl := C.CString(cl)
	defer C.free(unsafe.Pointer(c_cl))

	c_tn := C.CString(tn)
	defer C.free(unsafe.Pointer(c_tn))

	c_bk := C.CString(bk)
	defer C.free(unsafe.Pointer(c_bk))

	c_obj := C.CString(obj)
	defer C.free(unsafe.Pointer(c_obj))

	var comp C.ccow_completion_t
	ret = C.ccow_create_completion(tc, nil, nil, 1, &comp)
	if ret != 0 {
		return fmt.Errorf("%s: ccow_create_completion err=%d", GetFUNC(), ret)
	}

	var iov_name C.struct_iovec
	iov_name.iov_base = unsafe.Pointer(clempty)
	iov_name.iov_len = 1

	var iter C.ccow_lookup_t
	ret = C.ccow_admin_pseudo_get(c_cl, C.strlen(c_cl)+1, c_tn, C.strlen(c_tn)+1,
		c_bk, C.strlen(c_bk)+1, c_obj, C.strlen(c_obj)+1, &iov_name, 1, C.ulong(count), C.CCOW_GET_LIST,
		comp, &iter)
	if ret != 0 {
		C.ccow_release(comp)
		return fmt.Errorf("%s: ccow_admin_pseudo_get err=%d", GetFUNC(), ret)
	}

	ret = C.ccow_wait(comp, 0)
	if ret == -C.ENOENT {
		return nil
	}
	if ret != 0 {
		return fmt.Errorf("%s: ccow_wait err=%d", GetFUNC(), ret)
	}

	defer C.ccow_lookup_release(iter)
	var kv *C.struct_ccow_metadata_kv

	for {
		kv = (*C.struct_ccow_metadata_kv)(C.ccow_lookup_iter(iter,
			C.CCOW_MDTYPE_NAME_INDEX, -1))

		if kv == nil {
			break
		}
		if kv.key_size == 0 {
			continue
		}
		fmt.Printf("  %s\n", C.GoString(kv.key))
	}

	return nil
}
