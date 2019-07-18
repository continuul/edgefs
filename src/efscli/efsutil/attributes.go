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
*/
import "C"

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/im-kulikov/sizefmt"
	"github.com/spf13/cobra"
)

const CUSTOM_ATTRIBUTES int = -1

type FlagValue struct {
	Name  string
	Value string
	Short string
	Def   string
	Desc  string
	Reg   string
	Ctype string
	Attr  int
}

type ECMode struct {
	Data    int
	Parity  int
	DodecID int
}

var ECCodecString = [...]string {"none","xor", "rs", "cauchy"}

func (m *ECMode) String() string {
	return fmt.Sprintf("%v:%v:%v", m.Data, m.Parity, ECCodecString[m.DodecID])
}

func (m *ECMode) Encode() int {
	return m.DodecID << 16 | m.Data << 8 | m.Parity
}

func (m *ECMode) Decode(code int) error {
	id := (code >> 16) & 0xF
	if id == 0 || id >= len(ECCodecString) {
		return fmt.Errorf("Invalid CodecID %v", id)
	}
	data := (code >> 8) & 0x0F
	if data == 0 || data > 10 {
		return fmt.Errorf("Number of data bits has to be in range 1..10, provided value %v", data)
	}
	parity := code & 0x0F;
	if parity == 0 || parity > 3 {
		return fmt.Errorf("Number of parity bits has to be in range 1..3, provided value %v", parity)
	}

	m.DodecID = id
	m.Data = data
	m.Parity = parity
	return nil
}

func (m *ECMode) DecodeString(code string) error {
	s := strings.Split(code, ":")
	if len(s) != 3 {
		return fmt.Errorf("Invalid EC encode string %v", code)
	}
	data, err := strconv.Atoi(s[0])
	if err != nil || data <= 0 || data > 10 {
		return fmt.Errorf("Number of data bits has to be in range 1..10, provided value %v", s[0])
	}
	parity, err := strconv.Atoi(s[1])
	if data <= 0 || data > 3 {
		return fmt.Errorf("Number of parity bits has to be in range 1..3, provided value %v", s[1])
	}
	id := 0
	for i,val := range(ECCodecString) {
		if val == s[2] {
			id = i
			break
		}
	}

	if id == 0 {
		return fmt.Errorf("Unknown EC coded name %s", s[2])
	}
	m.Data = data
	m.Parity = parity
	m.DodecID = id

	return nil
}

var flagMap = map[string]FlagValue{
	"chunk-size": {"chunk-size", "", "s", "", "Chunk size 2^n (from 8K to 4M). E.g 1M",
		"8192|16384|32768|65536|131072|262144|524288|1048576|2097152|4194304|[0-9]+K|[0-9]+M|[0-9]+k|[0-9]+m",
		"uint32", C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE},
	"number-of-versions":       {"number-of-versions", "", "n", "", "Number of versions", "[1-9][0-9]*", "uint16", C.CCOW_ATTR_NUMBER_OF_VERSIONS},
	"replication-count":        {"replication-count", "", "r", "", "Replication count (1-4). E.g. 2", "[1-4]", "uint8", C.CCOW_ATTR_REPLICATION_COUNT},
	"sync-put":                 {"sync-put", "", "R", "", "Sync put (1-4). E.g. 1", "[1-4]", "uint8", C.CCOW_ATTR_SYNC_PUT},
	"select-policy":            {"select-policy", "", "S", "", "Data placement policy (latency or capacity). E.g. capacity", "latency|capacity", "uint8", C.CCOW_ATTR_SELECT_POLICY},
	"file-object-transparency": {"file-object-transparency", "", "t", "", "NFS - S3 transparency (set value to 1 to enable)", "[0-1]", "uint8", C.CCOW_ATTR_FILE_OBJECT_TRANSPARANCY},
	"ec-data-mode": {"ec-data-mode", "", "c", "", "Erasure coding data mode. E.g 4:2:rs, 3:1:xor, 4:2:rs, 6:2:rs, 9:3:rs",
		"2:1:xor|2:2:rs|3:1:xor|3:2:rs|4:1:xor|4:2:rs|6:2:rs|9:3:rs", "uint32", C.CCOW_ATTR_EC_ALGORITHM},
	"ec-trigger-policy-timeout": {"ec-trigger-policy-timeout", "", "C", "", "Erasure coding trigger policy timeout in seconds (4 hours - default). E.g 2h, 50m, 3600",
		"[0-9]+|[0-9]+h|[0-9]+m|[0-9]+s", "uint64", C.CCOW_ATTR_EC_TRG_POLICY},
	"encryption-enabled": {"encryption-enabled", "", "e", "", "Encryption enable flag (set value to 1 to enable)", "1", "uint8", C.CCOW_ATTR_HASH_TYPE},
	"quota":              {"container-meta-quota-bytes", "", "q", "", "Quota value in bytes", "[1-9][0-9]*", "uint64", CUSTOM_ATTRIBUTES},
	"quota-count":        {"container-meta-quota-count", "", "", "", "Quota count value", "[1-9][0-9]*", "uint64", CUSTOM_ATTRIBUTES},
	"options":            {"options", "", "o", "", "Additional custom options. E.g. one=foo,two=boo", ".+", "", CUSTOM_ATTRIBUTES},
}

func ReadAttributes(cmd *cobra.Command, flagNames []string, flags []FlagValue) {
	for i := 0; i < len(flagNames); i++ {
		f, exists := flagMap[flagNames[i]]
		if exists {
			flags[i] = f
			cmd.Flags().StringVarP(&flags[i].Value, flagNames[i],
				flags[i].Short, flags[i].Def, flags[i].Desc)
		} else {
			fmt.Printf("Flag %s not found!\n", flagNames[i])
			return
		}
	}
	return
}

func isNumber(s string) bool {
	r, _ := regexp.Compile("^[0-9]+$")
	return r.MatchString(s)
}

func GetBytes(s string) (int64, error) {
	if isNumber(s) {
		return strconv.ParseInt(s, 10, 64)
	}

	i, err := sizefmt.ToBytes(s)
	return int64(i), err
}

func CompletionAttribute(c unsafe.Pointer, name string) (string, error) {

	if name == "ec-enabled" {
		v := C.uint8_t(0)
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.CCOW_ATTR_EC_ENABLE,
			unsafe.Pointer(&v))
		return strconv.Itoa(int(v)), nil
	}

	flag, ok := flagMap[name]
	if !ok {
		return "", fmt.Errorf("Value %v not found", name)
	}

	if strings.Compare(flag.Ctype, "uint8") == 0 {
		v := C.uint8_t(0)
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v))
		return strconv.Itoa(int(v)), nil
	} else if strings.Compare(flag.Ctype, "uint16") == 0 {
		v := C.uint16_t(0)
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v))
		return strconv.Itoa(int(v)), nil
	} else if strings.Compare(flag.Ctype, "uint32") == 0 {
		v := C.uint32_t(0)
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v))
		return strconv.Itoa(int(v)), nil
	} else if strings.Compare(flag.Ctype, "uint64") == 0 {
		v := C.uint64_t(0)
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v))
		return strconv.Itoa(int(v)), nil
	} else if strings.Compare(flag.Ctype, "char") == 0 {
		var v *C.char = (*C.char)(C.malloc(256))
		defer C.free(unsafe.Pointer(v))
		C.ccow_get_default_attribute(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v))
		return C.GoString(v), nil
	}
	return "", fmt.Errorf("Entry not found")
}

func modifyDefaultAttribute(c unsafe.Pointer, flag *FlagValue) error {
	var ret C.int

	if strings.Compare(flag.Ctype, "uint8") == 0 {
		i, err := strconv.ParseInt(flag.Value, 10, 8)
		if err != nil {
			return err
		}
		v := C.uint8_t(i)
		ret = C.ccow_attr_modify_default(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v), nil)
	} else if strings.Compare(flag.Ctype, "uint16") == 0 {
		i, err := strconv.ParseInt(flag.Value, 10, 16)
		if err != nil {
			return err
		}
		v := C.uint16_t(i)
		ret = C.ccow_attr_modify_default(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v), nil)
	} else if strings.Compare(flag.Ctype, "uint32") == 0 {
		i, err := GetBytes(flag.Value)
		if err != nil {
			return err
		}
		v := C.uint32_t(i)
		ret = C.ccow_attr_modify_default(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v), nil)
	} else if strings.Compare(flag.Ctype, "uint64") == 0 {
		i, err := GetBytes(flag.Value)
		if err != nil {
			return err
		}
		v := C.uint64_t(i)
		ret = C.ccow_attr_modify_default(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v), nil)
	} else if strings.Compare(flag.Ctype, "char") == 0 {
		v := C.CString(flag.Value)
		defer C.free(unsafe.Pointer(v))
		ret = C.ccow_attr_modify_default(C.ccow_completion_t(c), C.ccow_default_attr_t(flag.Attr),
			unsafe.Pointer(&v), nil)
	} else {
		return fmt.Errorf("Invalid attribute type: %s", flag.Ctype)
	}

	if ret != 0 {
		return fmt.Errorf("modify default attribute '%s' failed, err: %d", flag.Name, ret)
	}

	return nil
}

func HasCustomAttributes(flags []FlagValue) bool {
	for i := 0; i < len(flags); i++ {
		if strings.Compare(flags[i].Value, "") != 0 && flags[i].Attr == CUSTOM_ATTRIBUTES {
			return true
		}
	}
	return false
}


func ModifyCustomAttributes(cl string, tn string, bk string, obj string, flags []FlagValue) error {
	par := []KeyValue{}
	for i := 0; i < len(flags); i++ {
		if strings.Compare(flags[i].Value, "") == 0 || flags[i].Attr != CUSTOM_ATTRIBUTES {
			continue
		}

		if strings.Compare(flags[i].Name, "options") == 0 {
			attrs := strings.Split(flags[i].Value, ",")
			for _, e := range attrs {
				s := strings.Split(e, "=")
				if len(s) < 2 {
					return fmt.Errorf("Invalid custom attribute '%s'", e)
				}
				if s[0] == "volsize" || s[0] == "blocksize" {
					bytes, err := sizefmt.ToBytes(s[1])
					if err == nil {
						s[1] = strconv.FormatInt(bytes, 10)
					}
				}
				kv := KeyValue{"X-" + s[0], s[1]}
				par = append(par, kv)
			}
			continue
		}

		kv := KeyValue{"X-" + flags[i].Name, flags[i].Value}
		par = append(par, kv)
	}
	return UpdateMDMany(cl, tn, bk, obj, par)
}

func ModifyDefaultAttributes(c unsafe.Pointer, flags []FlagValue) error {
	for i := 0; i < len(flags); i++ {

		// ignore empty attributes
		if strings.Compare(flags[i].Value, "") == 0 || flags[i].Attr == CUSTOM_ATTRIBUTES {
			continue
		}
		if strings.Compare(flags[i].Name, "encryption-enabled") == 0 {
			flags[i].Name = "hash-type"
			flags[i].Value = "129"
		} else if strings.Compare(flags[i].Name, "chunk-size") == 0 {
			i, err := GetBytes(flags[i].Value)
			if err != nil {
				return err
			}
			if i <= 0 {
				return fmt.Errorf("Invalid chunk size value: %v", i)
			}
			if (i & (i - 1)) != 0 {
				return fmt.Errorf("Invalid chunk size: value is not 2^n")
			}
		} else if strings.Compare(flags[i].Name, "ec-trigger-policy-timeout") == 0 {
			if isNumber(flags[i].Value) {
				t, err := strconv.ParseInt(flags[i].Value, 10, 64)
				if err != nil {
					return err
				}
				flags[i].Value = strconv.FormatInt(int64(t<<4), 10)
			} else {
				t, err := time.ParseDuration(flags[i].Value)
				if err != nil {
					return err
				}
				flags[i].Value = strconv.FormatInt(int64((t/1000000000)<<4), 10)
			}
		} else if strings.Compare(flags[i].Name, "ec-data-mode") == 0 {
			// Add enable attribute
			var f = FlagValue{"ec-enabled", "1", "", "", "", "", "uint8", C.CCOW_ATTR_EC_ENABLE}
			e := modifyDefaultAttribute(unsafe.Pointer(c), &f)
			if e != nil {
				return e
			}
			// Set mode
			var mode = map[string]string{
				"2:1:xor": "66049",
				"2:2:rs":  "131586",
				"3:1:xor": "66305",
				"3:2:rs":  "131842",
				"4:1:xor": "66561",
				"4:2:rs":  "132098",
				"6:2:rs":  "132610",
				"9:3:rs":  "133379",
			}
			flags[i].Value = mode[flags[i].Value]
		}  else if strings.Compare(flags[i].Name, "select-policy") == 0 {
			if strings.Compare(flags[i].Value, "capacity") == 0 {
				flags[i].Value = "2"
			} else if strings.Compare(flags[i].Value, "latency") == 0 {
				flags[i].Value = "4"
			} else {
				return fmt.Errorf("Invalid select policy value %v", flags[i].Value)
			}
		}
		e := modifyDefaultAttribute(unsafe.Pointer(c), &flags[i])
		if e != nil {
			return e
		}
	}
	return nil
}

func InheritBucketAttributes(c unsafe.Pointer, bucket map[string]string) error {
	var f FlagValue
	var e error

	// Chunk size
	f.Attr = C.CCOW_ATTR_CHUNKMAP_CHUNK_SIZE
	f.Ctype = "uint32"
	f.Value = bucket["ccow-chunkmap-chunk-size"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Btree marker
	f.Attr = C.CCOW_ATTR_BTREE_MARKER
	f.Ctype = "uint8"
	f.Value = bucket["ccow-chunkmap-btree-marker"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Replication count
	f.Attr = C.CCOW_ATTR_REPLICATION_COUNT
	f.Ctype = "uint8"
	f.Value = bucket["ccow-replication-count"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Sync put
	f.Attr = C.CCOW_ATTR_SYNC_PUT
	f.Ctype = "uint8"
	f.Value = bucket["ccow-sync-put"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Number of versions
	f.Attr = C.CCOW_ATTR_NUMBER_OF_VERSIONS
	f.Ctype = "uint16"
	f.Value = bucket["ccow-number-of-versions"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// EC data mode
	f.Attr = C.CCOW_ATTR_EC_ALGORITHM
	f.Ctype = "uint32"
	f.Value = bucket["ccow-ec-data-mode"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// EC trigger policy
	f.Attr = C.CCOW_ATTR_EC_TRG_POLICY
	f.Ctype = "uint64"
	f.Value = bucket["ccow-ec-trigger-policy"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// EC Enabled
	f.Attr = C.CCOW_ATTR_EC_ENABLE
	f.Ctype = "uint8"
	f.Value = bucket["ccow-ec-enabled"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Encryption enable flag
	f.Attr = C.CCOW_ATTR_HASH_TYPE
	f.Ctype = "uint8"
	f.Value = bucket["ccow-hash-type"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	// Select polciy flag
	f.Attr = C.CCOW_ATTR_SELECT_POLICY
	f.Ctype = "uint8"
	f.Value = bucket["ccow-select-policy"]
	e = modifyDefaultAttribute(unsafe.Pointer(c), &f)
	if e != nil {
		return e
	}

	return nil
}
