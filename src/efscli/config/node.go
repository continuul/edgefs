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
package config

import (
	"fmt"
	"os"
	"path"
	"encoding/json"

	"../efsutil"
	"github.com/spf13/cobra"
)

var (
	ipv6           bool
	isGateway      bool
	serverIfName   string
	brokerIfName   string
	nodelist       []string
	dirlist        []string
	zone           int
	replication    int
	syncPut        int
	skipConfirm    bool
	diskdriver     string
	diskprofile    string
	diskopts       string
	trlogKeepDays  int
	trlogInterval  int
	chunkHoldHours int
)

func ConfigNodeFnc(cmd *cobra.Command, args []string) {

	if brokerIfName == "" {
		brokerIfName = serverIfName
	}

	if nodename == "" {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("Error resolving local hostname: %s\n", err)
			os.Exit(1)
		}
		nodename = hostname
	}

	nodeConfig = &NodeConfig{
		Ccow: CcowConf{
			Trlog: CcowTrlog{
				Interval: 10,
			},
			Tenant: CcowTenant{
				FailureDomain: 1,
			},
			Network: CcowNetwork{
				BrokerInterfaces: brokerIfName,
				ServerUnixSocket: nedgeHome + CcowdUnixSocketFile,
			},
		},
		Ccowd: CcowdConf{
			BgConfig: CcowdBgConfig{
				TrlogDeleteAfterHours: 24*7,
				SpeculativeBackrefTimeout: 24*3600*1000,
			},
			Network: CcowdNetwork{
				ServerInterfaces: serverIfName,
				ServerUnixSocket: nedgeHome + CcowdUnixSocketFile,
			},
			Transport: []string{"rtlfs"},
		},
		Auditd: AuditdConf{
			IsAggregator: 0,
		},
		IPv4Autodetect: 1,
	}

	fmt.Println("Probing devices... please wait")
	nodeDisks, err := ProbeDevices(false)

	fmt.Println("\nThis node is about to be reconfigured")
	fmt.Println("=====================================\n")

	nodeIP, err := efsutil.LookupDNS(nodename)
	if err != nil {
		fmt.Printf("DNS lookup error: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("NODENAME: %s %s\n", nodename, nodeIP)

	if isGateway {
		nodeConfig.NodeType = "gateway"
		fmt.Printf("  - will use this node as diskless gateway\n")
	} else {
		nodeConfig.NodeType = "target"
		fmt.Printf("  - will use this node as mixed target and gateway\n")
	}

	if replication != 3 && replication > 0 {
		nodeConfig.Ccow.Tenant.ReplicationCount = replication
		nodeConfig.Ccow.Tenant.SyncPutNamed = replication
		fmt.Printf("  - will use broker default replication count %d\n", replication)
	}

	if syncPut > 0 && syncPut < replication {
		nodeConfig.Ccow.Tenant.SyncPut = syncPut
		fmt.Printf("  - will use broker default synchronous writes count %d\n", syncPut)
	}

	if trlogInterval > 0 {
		nodeConfig.Ccow.Trlog.Interval = trlogInterval
		fmt.Printf("  - will set transaction log processing interval to %ds\n", trlogInterval)
	}

	if trlogKeepDays > 0 {
		nodeConfig.Ccowd.BgConfig.TrlogDeleteAfterHours = trlogKeepDays * 24
		fmt.Printf("  - will set to keep transaction log entries for up to %d days\n", trlogKeepDays)
	}

	if chunkHoldHours > 0 {
		nodeConfig.Ccowd.BgConfig.SpeculativeBackrefTimeout = chunkHoldHours * 3600 * 1000
		fmt.Printf("  - will set chunk hold interval to %d hours\n", chunkHoldHours)
	}

	fmt.Printf("\n")

	fmt.Printf("BACKEND NETWORK: (%s)\n", nodeConfig.NodeType)
	if ipv6 {
		fmt.Printf("  - will autoconfigure via IPv6 and multicast\n")
		fmt.Printf("  - will use %s for server I/O\n", serverIfName)
		fmt.Printf("  - will use %s for broker I/O\n", serverIfName)

		nodeConfig.IPv4Autodetect = 0
		clusterConfig = make(map[string]*NodeConfig, 1)
		clusterConfig[nodename] = nodeConfig
	} else {
		if len(nodelist) == 0 {
			fmt.Printf("  - will autodetect IPv4 addresses using first occurance on selected interfaces\n")
			fmt.Printf("  - will use %s for server I/O\n", serverIfName)
			fmt.Printf("  - will use %s for broker I/O\n", serverIfName)
			clusterConfig = make(map[string]*NodeConfig, 1)
			clusterConfig[nodename] = nodeConfig
			nodeConfig.Ccow.Tenant.FailureDomain = 0
		} else {
			fmt.Printf("  - will autodetect IPv4 addresses via DNS lookup\n")
			fmt.Printf("  - the following nodes going to be part of the cluster:\n")
			clusterConfig = make(map[string]*NodeConfig, len(nodelist))
			for i := range nodelist {
				nodeIP, err = efsutil.LookupDNS(nodelist[i])
				if err != nil {
					fmt.Printf("DNS lookup error: %s\n", err)
					os.Exit(1)
				}
				fmt.Printf("    * %s %s\n", nodelist[i], nodeIP)
				clusterConfig[nodelist[i]] = nodeConfig
			}
			if len(nodelist) == 1 {
				nodeConfig.Ccow.Tenant.FailureDomain = 0
			}
		}
	}
	fmt.Printf("\nBACKEND STORAGE:\n")

	if diskdriver == "rtlfs" {
		if len(dirlist) > 0 {
			diskprofile = "rtlfsDirs"
		}
		if diskprofile == "rtlfsAuto" {
			fmt.Printf("  - will autoconfigure /data\n")
			// TODO: add verification that /data is a mountpoint
			nodeConfig.RtlfsAutodetect = "/data"
		} else if diskprofile == "rtlfsDirs" {
			rtdevs := make([]RtlfsDevice, 0)
			params := DefaultRTParams()

			if diskopts != "{}" {
				var rtlfsOpts RTDeviceParams
				err = json.Unmarshal([]byte(diskopts), &rtlfsOpts)
				if err != nil {
					fmt.Printf("Error unmarshalling JSON options object %s %v", diskopts, err)
					os.Exit(1)
				}
				fmt.Printf("\n  DEVICE OPTIONS\n")
				if rtlfsOpts.LmdbPageSize > 0 {
					params.LmdbPageSize = rtlfsOpts.LmdbPageSize
					fmt.Printf("  - will use LMDB PageSize=%d\n", params.LmdbPageSize)
				}
				if rtlfsOpts.MaxSizeGB > 0 {
					params.MaxSizeGB = rtlfsOpts.MaxSizeGB
					fmt.Printf("  - will limit usage of directories to MaxSize=%vGB\n", params.MaxSizeGB)
				}
				if rtlfsOpts.RtPlevelOverride > 0 {
					params.RtPlevelOverride = rtlfsOpts.RtPlevelOverride
					fmt.Printf("  - will prepare %d directory partitions\n", params.RtPlevelOverride)
				}
				if rtlfsOpts.Sync > 0 {
					params.Sync = rtlfsOpts.Sync
					fmt.Printf("  - will enable sync mode=%d\n", params.Sync)
				} else if rtlfsOpts.NoSync {
					params.Sync = 0
					fmt.Printf("  - will disable sync\n")
				}
				if rtlfsOpts.RtVerifyChid > 0 {
					params.RtVerifyChid = rtlfsOpts.RtVerifyChid
					fmt.Printf("  - will enable CHID verfication mode=%d\n", rtlfsOpts.RtVerifyChid)
				} else if rtlfsOpts.DisableVerifyChid {
					params.RtVerifyChid = 0
					fmt.Printf("  - will disable CHID verfication\n")
				}
			}

			fmt.Printf("\n  DEVICES\n")
			for i := range dirlist {
				d := dirlist[i]
				if stat, err := os.Stat(d); err == nil && stat.IsDir() {
				} else {
					fmt.Printf("Cannot find directory %s\n", d)
					os.Exit(1)
				}
				device := RtlfsDevice{
					Name:                path.Base(d),
					Path:                d,
					CheckMountpoint:     0,
					JournalMaxChunkSize: 65536,
					Sync:                params.Sync,
					PlevelOverride:      params.RtPlevelOverride,
					Psize:               params.LmdbPageSize,
					VerifyChid:          params.RtVerifyChid,
					MaxSize:             params.MaxSizeGB*1024*1024*1024,
				}

				fmt.Printf("  - will use directory %s\n", d)
				rtdevs = append(rtdevs, device)
			}

			nodeConfig.Ccowd.Transport = []string{"rtlfs"}
			nodeConfig.Rtlfs = RtlfsDevices{
				Devices: rtdevs,
			}
		} else {
			fmt.Printf("Wrong combination: driver=%s and profile=%s\n", diskdriver, diskprofile)
			os.Exit(1)
		}
	} else if diskdriver == "rtrd" {
		params := DefaultRTParams()
		if diskprofile == "rtrdAllSSD" {
			// all-SSD
			fmt.Printf("  - selected profile \"All SSD/NVMe\"\n")

			params.UseMetadataOffload = false
			params.UseAllSSD = true
		} else if diskprofile == "rtrdMDOffload" {
			// hybrid HDD/SSD
			fmt.Printf("  - selected profile \"Hybrid HDD with Metadata Offload on SSD\"\n")

			params.UseMetadataOffload = true
			params.UseAllSSD = false
		} else {
			// all HDD
			fmt.Printf("  - selected profile \"All HDD (capacity, cold archive)\"\n")

			params.UseMetadataOffload = false
			params.UseAllSSD = false
		}
		if diskopts != "{}" {
			var rtrdOpts RTDeviceParams
			err = json.Unmarshal([]byte(diskopts), &rtrdOpts)
			if err != nil {
				fmt.Printf("Error unmarshalling JSON options object %s %v", diskopts, err)
				os.Exit(1)
			}
			fmt.Printf("\n  DEVICE OPTIONS\n")
			if rtrdOpts.MDReserved > 0 {
				params.MDReserved = rtrdOpts.MDReserved
				fmt.Printf("  - will reserve usage of SSD for Metadata to %d%%\n", params.MDReserved)
			}
			if rtrdOpts.HDDReadAhead > 0 {
				params.HDDReadAhead = rtrdOpts.HDDReadAhead
				fmt.Printf("  - will set HDD ReadAhead to %dKB\n", params.HDDReadAhead)
			}
			if rtrdOpts.LmdbPageSize > 0 {
				params.LmdbPageSize = rtrdOpts.LmdbPageSize
				fmt.Printf("  - will use LMDB PageSize=%d\n", params.LmdbPageSize)
			}
			if rtrdOpts.UseBcache {
				params.UseBcache = rtrdOpts.UseBcache
				fmt.Printf("  - will enable Read Cache\n")
			}
			if rtrdOpts.UseBcacheWB {
				params.UseBcacheWB = rtrdOpts.UseBcacheWB
				fmt.Printf("  - will enable Write Back Cache\n")
			}
			if rtrdOpts.UseMetadataMask != "" {
				params.UseMetadataMask = rtrdOpts.UseMetadataMask
				fmt.Printf("  - will use MetadataMask=%s\n", params.UseMetadataMask)
			}
			if rtrdOpts.RtPlevelOverride > 0 {
				params.RtPlevelOverride = rtrdOpts.RtPlevelOverride
				fmt.Printf("  - will prepare %d disk partitions\n", params.RtPlevelOverride)
			}
			if rtrdOpts.Sync > 0 {
				params.Sync = rtrdOpts.Sync
				fmt.Printf("  - will enable sync mode=%d\n", params.Sync)
			} else if rtrdOpts.NoSync {
				fmt.Printf("  - will disable sync\n")
			}
			if rtrdOpts.RtVerifyChid > 0 {
				params.RtVerifyChid = rtrdOpts.RtVerifyChid
				fmt.Printf("  - will enable CHID verfication mode=%d\n", rtrdOpts.RtVerifyChid)
			} else if rtrdOpts.DisableVerifyChid {
				params.RtVerifyChid = 0
				fmt.Printf("  - will disable CHID verfication\n")
			}
		}
		fmt.Printf("\n  DEVICES\n")
		rtdevs, err := GetRTDevices(nodeDisks, params)
		if err != nil {
			fmt.Printf("Disk discovery failed: %s\n", err)
			os.Exit(1)
		}
		for i := range rtdevs {
			if rtdevs[i].Journal != "" {
				fmt.Printf("  - will use %s MD on %s\n", rtdevs[i].Name, rtdevs[i].Journal)
			} else {
				fmt.Printf("  - will use %s\n", rtdevs[i].Name)
			}
		}

		nodeConfig.Ccowd.Transport = []string{"rtrd"}
		nodeConfig.Rtrd = RTDevices{
			Devices: rtdevs,
		}
	} else {
		fmt.Printf("Unsupported combination: driver=%s and profile=%s\n", diskdriver, diskprofile)
		os.Exit(1)
	}

	fmt.Println("")

	if !skipConfirm {
		c := efsutil.AskForConfirmation("Do you really want to change this cluster node config at this time?")
		if !c {
			fmt.Println("Operation canceled")
			os.Exit(1)
		}
	}

	if zone > 0 {
		nodeConfig.Ccow.Tenant.FailureDomain = 2
	}

	ConfigNode()
}

var (
	NodeCmd = &cobra.Command{
		Use:   "node",
		Short: "configure cluster node",
		Long:  "Setup cluster node be part of local site\n\nDisk Options:\n" +
		       "  MDReserved         (rtrd)(int) override default reserved 60% Metadata of Offload SSD/NVMe capacity\n" +
		       "  HDDReadAhead       (rtrd)(int) override default 256KB read-ahead for HDD\n" +
		       "  LmdbPageSize       (both)(int) 4096, 8192, 16384 (default) or 32768\n" +
		       "  UseBcache          (rtrd)(bool) enable use of read cache\n" +
		       "  UseBcacheWB        (rtrd)(bool) enable use of write back cache (needs UseBcache)\n" +
		       "  UseMetadataMask    (rtrd)(string) what guts needs to go to SSD and what not. See extended doc\n" +
		       "  UseMetadataOffload (rtrd)(bool) when useAllSSD mode is false, enable metadata offload on SSD\n" +
		       "  RtPlevelOverride   (both)(int) override automatic partitioning numbering logic\n" +
		       "  DisableVerifyChid  (both)(bool) force RtVerifyChid be 0, that is to disable CHID verification\n" +
		       "  RtVerifyChid       (both)(int) 0 (disabled), 1 (default, verify on write) or 2 (verify on read/write)\n" +
		       "  NoSync             (both)(int) force Sync be 0, that is to I/O fully asyncrhonous\n" +
		       "  Sync               (both)(int) 0 (async), 1 (default, data sync, journal async), 2 (all sync), 3 (sync durable)\n" +
		       "  MaxSizeGB          (rtlfs)(int) maximum per directory size to utilize in gigabytes (default 0, use all available)",
		Run:   ConfigNodeFnc,
	}
)

func init() {

	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = DefaultNedgePrefix
	}

	ConfigCmd.AddCommand(NodeCmd)
	NodeCmd.Flags().IntVarP(&trlogInterval, "trlogInterval", "t", 10, "Transaction log processing interval in seconds")
	NodeCmd.Flags().IntVarP(&trlogKeepDays, "trlogKeepDays", "T", 7, "Number of days to keep transaction log records")
	NodeCmd.Flags().IntVarP(&chunkHoldHours, "chunkHoldHours", "H", 24, "Number of hours to hold metadata and data chunks, a.k.a MDOnly cache hold")
	NodeCmd.Flags().BoolVarP(&skipConfirm, "force-confirm", "f", false, "Force operation and skip confirmation dialog")
	NodeCmd.Flags().BoolVarP(&isGateway, "gateway", "g", false, "Makes this node behave as a gateway")
	NodeCmd.Flags().StringSliceVarP(&nodelist, "nodelist", "l", []string{}, "Resolvable node names for FlexHash ring communication")
	NodeCmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Use IPv6 and enable multicast nodelist autodetect")
	NodeCmd.Flags().StringVarP(&serverIfName, "serverIfName", "i", "eth0", "Server (backend network) interface name")
	NodeCmd.Flags().StringVarP(&brokerIfName, "brokerIfName", "I", "", "Broker (backend network) interface name")
	NodeCmd.Flags().IntVarP(&replication, "replication", "r", 3, "Broker default replication count")
	NodeCmd.Flags().IntVarP(&syncPut, "syncput", "R", 0, "Broker default synchronous writes within configured replication count (default 0, all sync)")
	NodeCmd.Flags().IntVarP(&zone, "zone", "z", 0, "Zone number this node belongs to (default 0, zoning disabled)")
	NodeCmd.Flags().StringVarP(&nodename, "nodename", "n", "", "Optional nodename override. Using hostname if omitted")
	NodeCmd.Flags().StringVarP(&diskdriver, "diskdriver", "d", "rtlfs", "Specifying Disk driver to use. Available choices: rtlfs and rtrd")
	NodeCmd.Flags().StringSliceVarP(&dirlist, "dirlist", "D", []string{}, "List of directories to utilize using rtlfsDirs profile. Also see MaxSizeGB")
	NodeCmd.Flags().StringVarP(&diskprofile, "diskprofile", "p", "rtlfsAuto", "Specifying Disk profile to use. Available choices: rtlfsAuto, rtlfsDirs, rtrdAllSSD, rtrdAllHDD, rtrdMDOffload")
	NodeCmd.Flags().StringVarP(&diskopts, "diskopts", "o", "{}", "Specifying Disk options to use in json format. See Disk Options.")
}
