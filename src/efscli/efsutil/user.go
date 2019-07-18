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
#include "msgpackalt.h"
*/
import "C"
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unsafe"
)

// User - general user structure
type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Identity string `json:"identity"`
	Admin    int    `json:"admin"`

	// s3 authentication keys
	Authkey string `json:"authkey"`
	Secret  string `json:"secret"`
}

// RandomString  generates a random string for S3 key, secret auth
func RandomString(size int) string {
	charSet := ([]byte)("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	var buffer bytes.Buffer

	rand.Seed(time.Now().UnixNano())

	for i := 0; i < size; i++ {
		buffer.WriteByte(charSet[rand.Intn(len(charSet))])
	}

	return buffer.String()
}

func CreateUser(cluster string, tenant string, username string, password string,
	usertype string, identity string, authkey string, secret string, admin int) *User {
	user := new(User)
	user.Username = username
	user.Type = usertype
	user.Identity = identity
	user.Authkey = authkey
	user.Secret = secret
	user.Admin = admin

	sum := sha256.Sum256([]byte(cluster + tenant + username + password))
	user.Hash = fmt.Sprintf("%x", sum)

	return user
}

func PrintUser(user *User) {
	if user.Admin == 1 {
		fmt.Printf("S3 user %s - administrator:\n", user.Username)
	} else {
		fmt.Printf("S3 user %s:\n", user.Username)
	}
	fmt.Printf("Access key: %s\n", user.Authkey)
	fmt.Printf("Secret key: %s\n\n", user.Secret)
}

func MatchUser(cluster string, tenant string, user *User, password string) bool {
	sum := sha256.Sum256([]byte(cluster + tenant + user.Username + password))
	hash := fmt.Sprintf("%x", sum)
	return (strings.Compare(user.Hash, hash) == 0)
}

func UserKey(username string) string {
	return ("user-" + username)
}

func AuthKey(authkey string) string {
	return ("key-" + authkey)
}

func CacheUserKey(cluster string, tenant string, user *User) string {
	return (cluster + "@" + tenant + "@" + user.Username)
}

func CacheAuthKey(cluster string, tenant string, user *User) string {
	return (cluster + "@" + tenant + "@" + user.Authkey)
}

func SaveUser(cluster string, tenant string, user *User) error {
	value, err := json.Marshal(*user)
	if err != nil {
		return err
	}

	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	conf, e := GetLibccowConf()
	if e != nil {
		return e
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

	c_user := C.CString(UserKey(user.Username))
	defer C.free(unsafe.Pointer(c_user))

	c_key := C.CString(AuthKey(user.Authkey))
	defer C.free(unsafe.Pointer(c_key))

	c_value := C.CString("" + string(value))
	defer C.free(unsafe.Pointer(c_value))

	var io C.struct_iovec
	ret = C.ccow_user_get(tc, c_user, C.strlen(c_user)+1, &io)
	if ret == 0 {
		return fmt.Errorf("User '%s' already exists", user.Username)
	}

	p := C.msgpack_pack_init()
	defer C.msgpack_pack_free(p)

	var ver C.uint8_t = 2

	ret = C.int(C.msgpack_pack_uint8(p, ver))
	if ret != 0 {
		return fmt.Errorf("msgpack_pack_uint8 err=%d", ret)
	}

	ret = C.int(C.msgpack_pack_str(p, c_value))
	if ret != 0 {
		return fmt.Errorf("msgpack_pack_str err=%d", ret)
	}

	var uv_b C.uv_buf_t
	C.msgpack_get_buffer(p, &uv_b)

	var iov [2]C.struct_iovec
	iov[0].iov_base = unsafe.Pointer(c_user)
	iov[0].iov_len = C.strlen(c_user) + 1

	iov[1].iov_base = unsafe.Pointer(uv_b.base)
	iov[1].iov_len = uv_b.len

	ret = C.ccow_user_put(tc, &iov[0])
	if ret != 0 {
		return fmt.Errorf("ccow_user_put1 err=%d", ret)
	}

	iov[0].iov_base = unsafe.Pointer(c_key)
	iov[0].iov_len = C.strlen(c_key) + 1

	ret = C.ccow_user_put(tc, &iov[0])
	if ret != 0 {
		return fmt.Errorf("ccow_user_put2 err=%d", ret)
	}

	return nil
}

func LoadUser(cluster string, tenant string, key string) (*User, error) {
	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	conf, e := GetLibccowConf()
	if e != nil {
		return nil, e
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return nil, fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))

	var iov C.struct_iovec
	ret = C.ccow_user_get(tc, c_key, C.strlen(c_key)+1, &iov)
	if ret != 0 {
		return nil, fmt.Errorf("Get user error=%d", ret)
	}

	var ver C.uint8_t

	u := C.msgpack_unpack_init(iov.iov_base, C.uint(iov.iov_len), 0)
	ret = C.int(C.msgpack_unpack_uint8(u, &ver))
	if ret != 0 {
		return nil, fmt.Errorf("Unpack user error=%d", ret)
	}

	if ver != 2 {
		return nil, fmt.Errorf("Unpack user version error=%d", ver)
	}

	const buf_size = 4096
	c_buf := (*C.char)(C.malloc(C.ulong(buf_size)))
	defer C.free(unsafe.Pointer(c_buf))

	ret = C.int(C.msgpack_unpack_str(u, c_buf, buf_size-1))
	if ret != 0 {
		return nil, fmt.Errorf("Unpack user buffer error=%d", ret)
	}

	buf := C.GoString(c_buf)

	user := new(User)
	err := json.Unmarshal([]byte(buf), user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func DeleteUser(cluster string, tenant string, user *User) error {
	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	conf, e := GetLibccowConf()
	if e != nil {
		return e
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

	c_key := C.CString(UserKey(user.Username))
	defer C.free(unsafe.Pointer(c_key))

	ret = C.ccow_user_delete(tc, c_key, C.strlen(c_key)+1)
	if ret != 0 {
		return fmt.Errorf("Delete user error=%d", ret)
	}

	c_auth := C.CString(AuthKey(user.Authkey))
	defer C.free(unsafe.Pointer(c_auth))

	ret = C.ccow_user_delete(tc, c_auth, C.strlen(c_auth)+1)
	if ret != 0 {
		return fmt.Errorf("Delete user auth error=%d", ret)
	}

	return nil
}

func ListUser(cluster string, tenant string, count int, name string) error {
	c_cluster := C.CString(cluster)
	defer C.free(unsafe.Pointer(c_cluster))

	c_tenant := C.CString(tenant)
	defer C.free(unsafe.Pointer(c_tenant))

	conf, e := GetLibccowConf()
	if e != nil {
		return e
	}

	var marker string = "user-" + name

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	var tc C.ccow_t

	ret := C.ccow_tenant_init(c_conf, c_cluster, C.strlen(c_cluster)+1,
		c_tenant, C.strlen(c_tenant)+1, &tc)
	if ret != 0 {
		return fmt.Errorf("ccow_tenant_init err=%d", ret)
	}
	defer C.ccow_tenant_term(tc)

	c_marker := C.CString(marker)
	defer C.free(unsafe.Pointer(c_marker))

	var iter C.ccow_lookup_t
	ret = C.ccow_user_list(tc, c_marker, C.strlen(c_marker)+1, C.int(count), &iter)
	if ret != 0 {
		return fmt.Errorf("Get user list error=%d", ret)
	}

	defer C.ccow_lookup_release(iter)
	var kv *C.struct_ccow_metadata_kv

	fmt.Printf("%-12s\t%-7s %-9s %s\n", "NAME", "TYPE", "IDENTITY", "ADMINISTRATOR")
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
		cmpRes := strings.Compare(gkey, marker)
		if cmpRes < 0 {
			continue
		}

		var ver C.uint8_t
		u, _ := C.msgpack_unpack_init(kv.value, C.uint(kv.value_size), 0)
		if u == nil {
			return fmt.Errorf("%s: unpack init err=%d", GetFUNC(), ret)
		}
		defer C.msgpack_unpack_free(u)

		r, _ := C.msgpack_unpack_uint8(u, &ver)
		if r != 0 {
			return fmt.Errorf("%s: unpack version err=%d", GetFUNC(), ret)
		}

		if ver != 2 {
			return fmt.Errorf("Unpack user version error=%d", ver)
		}

		const buf_size = 4096
		c_buf := (*C.char)(C.malloc(C.ulong(buf_size)))
		defer C.free(unsafe.Pointer(c_buf))

		ret = C.int(C.msgpack_unpack_str(u, c_buf, buf_size-1))
		if ret != 0 {
			return fmt.Errorf("Unpack user buffer error=%d", ret)
		}

		buf := C.GoString(c_buf)

		user := new(User)
		err := json.Unmarshal([]byte(buf), user)
		if err != nil {
			return err
		}
		var admin string = ""
		if user.Admin == 1 {
			admin = "A"
		}
		fmt.Printf("%-12s\t%-7s %-9s %s\n", user.Username, user.Type, user.Identity, admin)
	}
	fmt.Printf("\n")

	return nil
}
