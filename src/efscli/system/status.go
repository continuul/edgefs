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
package system

/*
#include "errno.h"
#include "ccow.h"
#include "auditd.h"
#include "private/trlog.h"
*/
import "C"
import "unsafe"

import (
	"bufio"
	"fmt"
	"time"
	"../efsutil"
	"github.com/spf13/cobra"
	"github.com/im-kulikov/sizefmt"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
)

const (
	dbStatExpiration = 20
)

func readTrlogMarker() (int64, error) {
	conf, err := efsutil.GetLibccowConf()
	if err != nil {
		return -1, err
	}

	c_conf := C.CString(string(conf))
	defer C.free(unsafe.Pointer(c_conf))

	cl := C.CString("")
	defer C.free(unsafe.Pointer(cl))

	var tc C.ccow_t

	ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
	if ret != 0 {
		return -1, fmt.Errorf("%s: ccow_admin_init err=%d", efsutil.GetFUNC(), ret)
	}
	defer C.ccow_tenant_term(tc)

	shard := C.CString(C.SHARD_LEADER_PREFIX)
	defer C.free(unsafe.Pointer(shard))

	var trlog_seq_ts C.uint64_t = 0
	var trlog_seq_prev_ts C.uint64_t = 0
	ret = C.trlog_read_marker_seq_tss(tc, nil, shard, &trlog_seq_ts, &trlog_seq_prev_ts)
	if ret != 0 {
		return -1, fmt.Errorf("%s: cannot read '%s' marker, err=%d", efsutil.GetFUNC(), C.SHARD_LEADER_PREFIX, ret)
	}

	return int64(trlog_seq_prev_ts), nil
}

func SystemStatus(isSummary bool) error {
	var lock *C.void = nil
	l := unsafe.Pointer(lock)
	rc := C.auditd_stats_sharedlock(&l)
	if rc != 0 {
		return fmt.Errorf("Couldn't acquire a lock on stats.db")
	}
	defer C.auditd_stats_sharedunlock(l)
	f, err := os.OpenFile(os.Getenv("NEDGE_HOME")+"/var/run/stats.db", os.O_RDONLY, os.ModePerm)
	if err != nil {
		fmt.Printf("error opening file: %v\n", err)
		return err
	}
	defer f.Close()

	sdmap := make(map[string]map[string]string)
	vdmap := make(map[string]map[string]string)
	smap := make(map[string]map[string]map[string]string)
	// Try to init servermap from checkpoint
	cp_buf, err := ioutil.ReadFile(os.Getenv("NEDGE_HOME") + "/var/run/flexhash-checkpoint.json")
	if err == nil {
		var cp interface{}
		err = json.Unmarshal(cp_buf, &cp)
		if err == nil {
			cp_kv := cp.(map[string]interface{})
			// Loading VDEVs
			if vdev_if, ok := cp_kv["vdevlist"]; ok {
				if vdevs, ok := vdev_if.([]interface{}); ok {
					for _, vdev_if := range(vdevs) {
						if vdev_kv, ok := vdev_if.(map[string]interface{}); ok {
							sid := vdev_kv["serverid"].(string)
							vid := vdev_kv["vdevid"].(string)
							if _, ok := smap[sid]; !ok {
								smap[sid] = map[string]map[string]string{}
							}
							if _, ok := smap[sid][vid]; !ok {
								smap[sid][vid] = map[string]string{}
							}
							if _, ok := sdmap[sid]; !ok {
								sdmap[sid] = map[string]string{}
								sdmap[sid]["hostname"] = "-"
								sdmap[sid]["containerid"] = "-"
							}
							smap[sid][vid]["state"] = "FAULTED"
						}
					}
				}
			}
		}
	}

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			fmt.Printf("read file line error: %v\n", err)
			return err
		}

		pattern := regexp.MustCompile(`^gauges\.ccow\.clengine\.server\.(?P<sid>\w+).(?P<ipaddr>\w+).(?P<vdevid>\w+)\|(?P<state>\d+\.\d+)\|(?P<ts>\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			sid := m[0][1]
			vdevid := m[0][3]
			st := m[0][4]
			ts, err := strconv.Atoi(m[0][5])
			if err != nil {
				return err
			}
			state := "ONLINE"
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				state = "FAULTED"
			} else {
				v, err := strconv.ParseFloat(st, 64)
				if err != nil {
					return fmt.Errorf("VDEV %v status parse error %v, value %v", vdevid, err, st)
				}
				if v == 0 {
					state = "FAULTED"
				} else if v == 2 {
					state = "READONLY"
				} else if v != 1 {
					return fmt.Errorf("VDEV %v undefined status %v", vdevid, st)
				}
			}

			if _, ok := smap[sid]; !ok {
				smap[sid] = map[string]map[string]string{}
			}
			if _, ok := smap[sid][vdevid]; !ok {
				smap[sid][vdevid] = map[string]string{}
			}
			smap[sid][vdevid]["state"] = state
		}
	}

	f.Seek(0, 0)
	rd = bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			fmt.Printf("read file line error: %v\n", err)
			return err
		}
		// number values
		pattern := regexp.MustCompile(`^gauges\.ccow\.host.(\w+)\.(\w+)\.(\w+)\|(\d+\.\d+)\|(\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			key := m[0][1]
			sid := m[0][2]
			val := m[0][4]
			ts, err := strconv.Atoi(m[0][5])
			if err != nil {
				return err
			}
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				continue
			}
			if _, ok := sdmap[sid]; !ok {
				sdmap[sid] = map[string]string{}
			}
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				sdmap[sid][key] = strconv.FormatInt(int64(0), 10)
			} else {
				sdmap[sid][key] = strconv.FormatInt(int64(v), 10)
			}
		}
		// string values
		pattern = regexp.MustCompile(`^gauges\.ccow\.host.(\w+)\.(\w+)\.(\w+)\.(.*)\|(\d+\.\d+)\|(\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			key := m[0][1]
			sid := m[0][2]
			strval := m[0][4]
			ts, err := strconv.Atoi(m[0][6])
			if err != nil {
				return err
			}
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				continue
			}
			if _, ok := sdmap[sid]; !ok {
				sdmap[sid] = map[string]string{}
			}
			sdmap[sid][key] = strval
		}
	}

	f.Seek(0, 0)
	rd = bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			fmt.Printf("read file line error: %v\n", err)
			return err
		}
		// gauges number values
		pattern := regexp.MustCompile(`^gauges\.ccow\.reptrans\.(\w+)\.(\w+)\.(\w+)\|(\d+\.\d+)\|(\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			key := m[0][1]
			vdevid := m[0][3]
			val := m[0][4]
			ts, err := strconv.Atoi(m[0][5])
			if err != nil {
				return err
			}
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				continue
			}
			if _, ok := vdmap[vdevid]; !ok {
				vdmap[vdevid] = map[string]string{}
			}
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				vdmap[vdevid][key] = strconv.FormatInt(int64(0), 10)
			} else {
				vdmap[vdevid][key] = strconv.FormatInt(int64(v), 10)
			}
		}
		// timer number values
		pattern = regexp.MustCompile(`^timers\.ccow\.reptrans\.(\w+)\.(\w+)\.(\w+).(\w+)\|(\d+\.\d+)\|(\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			key := m[0][1]
			vdevid := m[0][3]
			val := m[0][5]
			ts, err := strconv.Atoi(m[0][6])
			if err != nil {
				return err
			}
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				continue
			}
			if _, ok := vdmap[vdevid]; !ok {
				vdmap[vdevid] = map[string]string{}
			}
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				vdmap[vdevid][key] = strconv.FormatInt(int64(0), 10)
			} else {
				vdmap[vdevid][key] = strconv.FormatInt(int64(v), 10)
			}
		}
		// string values
		pattern = regexp.MustCompile(`^gauges\.ccow\.reptrans.(\w+)\.(\w+)\.(\w+)\.(.*)\|(\d+\.\d+)\|(\d+)`)
		if m := pattern.FindAllStringSubmatch(line, -1); m != nil {
			key := m[0][1]
			vdevid := m[0][3]
			strval := m[0][4]
			ts, err := strconv.Atoi(m[0][6])
			if err != nil {
				return err
			}
			now := int(time.Now().Unix())
			if now > ts + dbStatExpiration {
				continue
			}
			if _, ok := vdmap[vdevid]; !ok {
				vdmap[vdevid] = map[string]string{}
			}
			vdmap[vdevid][key] = strval
		}
	}

	if isSummary {
		totalCapacity := int64(0)
		totalUsed := int64(0)
		totalNumObjects := int64(0)
		for sid, vdevs := range smap {
			capacity := int64(0)
			used := int64(0)
			numObjects := int64(0)
			for vdevid, vals := range vdevs {
				if vals["state"] != "ONLINE" {
					continue
				}
				for key, val := range vdmap[vdevid] {
					if key == "capacity" {
						v, err := strconv.ParseInt(val, 10, 64)
						if err == nil {
							capacity += v
						}
					} else if key == "used" {
						v, err := strconv.ParseInt(val, 10, 64)
						if err == nil {
							used += v
						}
					} else if key == "num_objects" {
						v, err := strconv.ParseInt(val, 10, 64)
						if err == nil {
							numObjects += v
						}
					}
				}
			}
			sdmap[sid]["capacity"] = strconv.FormatInt(int64(capacity), 10)
			sdmap[sid]["used"] = strconv.FormatInt(int64(used), 10)
			sdmap[sid]["numObjects"] = strconv.FormatInt(int64(numObjects), 10)
			totalCapacity += capacity
			totalUsed += used
			totalNumObjects += numObjects
		}
		totalAvailable := totalCapacity - totalUsed
		totalUtilization := float64(100 * totalUsed / totalCapacity)
		fmt.Printf("capacity %+v %+v\n", totalCapacity, sizefmt.ByteSize(float64(totalCapacity)))
		fmt.Printf("used %+v %+v\n", totalUsed, sizefmt.ByteSize(float64(totalUsed)))
		fmt.Printf("available %+v %+v\n", totalAvailable, sizefmt.ByteSize(float64(totalAvailable)))
		fmt.Printf("utilization %+v %+v%%\n", totalUtilization, totalUtilization)
		fmt.Printf("versions %+v %+vM\n", totalNumObjects, totalNumObjects / int64(1000000))
		m, _ := readTrlogMarker()
		if err != nil {
			fmt.Printf("trlogmark err=%v\n", err)
		} else if m > 0 && m != -1 {
			cursec := time.Now().UnixNano() / 1000000000
			fmt.Printf("trlogmark %+v -%+vs\n", m / int64(1000000), cursec - (m / int64(1000000)))
		}

		conf, err := efsutil.GetLibccowConf()
		if err != nil {
			return err
		}

		c_conf := C.CString(string(conf))
		defer C.free(unsafe.Pointer(c_conf))

		cl := C.CString("")
		defer C.free(unsafe.Pointer(cl))

		var tc C.ccow_t

		ret := C.ccow_admin_init(c_conf, cl, 1, &tc)
		if ret != 0 {
			return fmt.Errorf("%s: ccow_admin_init err=%d", efsutil.GetFUNC(), ret)
		}
		defer C.ccow_tenant_term(tc)

		fmt.Printf("guid %+s\n", C.GoString(C.ccow_get_system_guid_formatted(tc)));

		return nil
	}

	for sid, vdevs := range smap {
		state := "ONLINE"
		vdevOfflineCount := 0
		vdevReadOnlyCount := 0
		for _, vdev := range vdevs {
			if vdev["state"] == "FAULTED" {
				vdevOfflineCount++
			} else if vdev["state"] == "READONLY" {
				vdevReadOnlyCount++
			}
		}

		if vdevOfflineCount == len(vdevs) {
			state = "FAULTED"
		} else if vdevOfflineCount > 0 || vdevReadOnlyCount > 0 {
			state = "DEGRADED"
		}

		if contId, ok := sdmap[sid]["containerid"]; ok {
			fmt.Printf("ServerID %s %s:%s %s\n", sid, sdmap[sid]["hostname"], contId, state)
		} else {
			fmt.Printf("ServerID %s %s %s\n", sid, sdmap[sid]["hostname"], state)
		}
		if verbose > 0 {
			if verbose > 1 {
				for key, val := range sdmap[sid] {
					fmt.Printf("  - %s %+v\n", key, val)
				}
			}
			for vdevid, vals := range vdevs {
				// Don not show GW's pseudo VDEV
				if vdevid == "00000000000000000000000000000000" {
					continue
				}
				fmt.Printf("  VDEVID %s %s %s\n", vdevid, vdmap[vdevid]["devname"], vals["state"])
				if verbose > 2 {
					for key, val := range vdmap[vdevid] {
						fmt.Printf("    - %s %+v\n", key, val)
					}
				}
			}
		}
	}
	return nil
}

var (
	verbose int = 0

	StatusCmd = &cobra.Command{
		Use:   "status",
		Short: "display status of physical cluster",
		Long:  "display status of physical cluster",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemStatus(false)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				os.Exit(1)
			}
		},
	}

	SummaryCmd = &cobra.Command{
		Use:   "summary",
		Short: "display summary of physical cluster",
		Long:  "display summary of physical cluster",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemStatus(true)
			if err != nil {
				os.Exit(1)
			}
		},
	}
)

func init() {
	StatusCmd.Flags().IntVarP(&verbose, "verbose", "v", 0, "increase display verbosity level, range (0..3)")
	SystemCmd.AddCommand(StatusCmd)
	SystemCmd.AddCommand(SummaryCmd)
}
