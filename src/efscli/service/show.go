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
package service

/*
#include "ccow.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"github.com/Nexenta/edgefs/src/efscli/validate"

	"github.com/im-kulikov/sizefmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

// Stat - general stat structure
type Stat struct {
	Timestamp            int64  `json:"timestamp"`
	Status               string `json:"status"`
	State                string `json:"state"`
	Mode                 int64  `json:"mode"`
	Delay                int64  `json:"delay"`
	Version_manifests    int64  `json:"version_manifests"`
	Requests             int64  `json:"requests"`
	Chunk_manifests      int64  `json:"chunk_manifests"`
	Data_chunks          int64  `json:"data_chunks"`
	Snapviews            int64  `json:"snapviews"`
	Bytes                int64  `json:"bytes"`
	Received_data_chunks int64  `json:"received_data_chunks"`
	Received_bytes       int64  `json:"received_bytes"`
	Latency              int64  `json:"latency"`
	Send_throughput      int64  `json:"send_throughput"`
	Receive_throughput   int64  `json:"receive_throughput"`
	Network_errors       int64  `json:"network_errors"`
	Local_io_errors      int64  `json:"local_io_errors"`
	Remote_io_errors     int64  `json:"remote_io_errors"`
}

func FormatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%vms", ms)
	}
	s := ms / 1000
	if s < 60 {
		return fmt.Sprintf("%vs", s)
	}
	m := s / 60
	s -= m * 60
	if m < 60 {
		return fmt.Sprintf("%vm %vs", m, s)
	}
	h := m / 60
	m -= h * 60
	return fmt.Sprintf("%vh %vm %vs", h, m, s)
}

func FormatMode(m int64) string {
	if m == 2 {
		return "vmonly"
	} else if m == 1 {
		return "mdonly"
	} else {
		return "complete"
	}
}

func FormatBytes(b int64) string {
	return strings.Trim(sizefmt.ByteSize(float64(b)), " ")
}

func Show(name string, stat bool) error {
	ret := efsutil.PrintMDPat("", "svcs", name, "", "X-")
	if ret != nil {
		return ret
	}
	fmt.Printf("[\n")
	ret = efsutil.PrintKeys("", "svcs", name, "", 1000)
	fmt.Printf("]\n")
	if ret != nil {
		return ret
	}

	if stat {
		sname := name + ".stat"
		kv, err := efsutil.GetKeyValues("", "svcs", sname, "", "", 4096, 1000)
		if err == nil {
			for i := 0; i < len(kv); i++ {
				stat := new(Stat)
				e := json.Unmarshal([]byte(kv[i].Value), stat)
				if e == nil {
					fmt.Printf("\nStats for %s:\n\n", kv[i].Key)
					table := tablewriter.NewWriter(os.Stdout)
					table.SetBorder(false)
					table.SetHeader([]string{"Parameter", "Value"})

					t := time.Unix(stat.Timestamp/1000, 0)
					table.Append([]string{"Timestamp", sizefmt.Time(t)})
					table.Append([]string{"Status", stat.Status})
					table.Append([]string{"State", stat.State})
					table.Append([]string{"Mode", FormatMode(stat.Mode)})
					table.Append([]string{"Processing delay", FormatDuration(stat.Delay)})
					table.Append([]string{"Latency", FormatDuration(stat.Latency)})
					table.Append([]string{"Requests", fmt.Sprintf("%-16d", stat.Requests)})
					table.Append([]string{"Version manifests", fmt.Sprintf("%-16d", stat.Version_manifests)})
					table.Append([]string{"Chunk manifests", fmt.Sprintf("%-16d", stat.Chunk_manifests)})
					table.Append([]string{"Data chunks sent", fmt.Sprintf("%-16d", stat.Data_chunks)})
					table.Append([]string{"Data chunks received", fmt.Sprintf("%-16d", stat.Received_data_chunks)})
					table.Append([]string{"Snapviews", fmt.Sprintf("%-16d", stat.Snapviews)})
					table.Append([]string{"Bytes sent", fmt.Sprintf("%-16s", FormatBytes(stat.Bytes))})
					table.Append([]string{"Bytes received", fmt.Sprintf("%-16s", FormatBytes(stat.Received_bytes))})
					table.Append([]string{"Send throughput per sec", fmt.Sprintf("%-16s", FormatBytes(stat.Send_throughput))})
					table.Append([]string{"Receive throughput per sec", fmt.Sprintf("%-16s", FormatBytes(stat.Receive_throughput))})
					table.Append([]string{"Network errors", fmt.Sprintf("%-16d", stat.Network_errors)})
					table.Append([]string{"Local io errors", fmt.Sprintf("%-16d", stat.Local_io_errors)})
					table.Append([]string{"Remote io errors", fmt.Sprintf("%-16d", stat.Remote_io_errors)})

					table.Render()
					fmt.Println()
				} else {
					fmt.Errorf("Stats %s: decoding error: %v", kv[i].Key, e)
				}

			}
		}
	}
	return ret
}

var (
	stat bool

	showCmd = &cobra.Command{
		Use:   "show <service name>",
		Short: "show service",
		Long:  "show parameters of existing service",
		Args:  validate.Service,
		Run: func(cmd *cobra.Command, args []string) {
			err := Show(args[0], stat)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	showCmd.Flags().BoolVarP(&stat, "stat", "s", false, "Show service stats")
	ServiceCmd.AddCommand(showCmd)
}
