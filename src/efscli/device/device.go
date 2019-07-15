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
package device

import (
	"github.com/Nexenta/edgefs/src/efscli/config"
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	mStatusOk int = 0
	mNoEntry  int = -2

	diskStatusAlive    int = 0
	diskStatusInit     int = 1
	diskStatusRoData   int = 2
	diskStatusRoFull   int = 3
	diskStatusRoEvac   int = 4
	diskStatusRoForced int = 5
	diskStatusRoFault  int = 6
	diskStatusUnavail  int = 7
	diskStatusNotFound int = -2
	diskStatusPerm     int = -1
	diskStatusOffline  int = -10
//	ccowDaemonStopped  int = -10
	oldDiskRemoved     int = -11

	// Metaloc's state possible values
	rdstateOk          int = 0
	rdstateFault       int = 1
	rdstateReadOnly    int = 2
	rdstateMaintenance int = 3

	metalocMinSupportedVersion int    = 7
	metalocDiskOffset          int64  = (512 * 2032)
	metalocSize                int   = (512*16)
	RtrdConfigPath             string = "/etc/ccow/rt-rd.json"
	ccowdConfigPath             string = "/etc/ccow/ccowd.json"
	diskUnused                        = "UNUSED"
	diskPartitioned                   = "PARTITIONED"
)

var faultIDs = [...]string {"m", "l","o","c","e","i"}

const (
	FaultIDMain = iota
	FaultIDWAL
	FaultIDOffload
	FaultIDMaintenance
	FaultIDExternal
	FaultIDTotal
)

var diskStatusOpts = []struct {
	id   string
	code int
	desc string
}{
	{"ALIVE", diskStatusAlive, "Disk is on-line"},
	{"INIT", diskStatusInit, "Initialized, but no attached"},
	{"READONLY_DATA", diskStatusRoData, "Read-only for data"},
	{"READONLY_FULL", diskStatusRoFull, "Read-only: out of space"},
	{"READONLY_ROWEVAC", diskStatusRoEvac, "Read-only: row evacuation is in progress"},
	{"READONLY_FORCED", diskStatusRoForced, "Read-only: maintenance"},
	{"READONLY_FAULT", diskStatusRoFault, "Read-only: disk fault"},
	{"UNAVAILABLE", diskStatusUnavail, "Device in unavailable: faulted or detached"},
	{"NOT_FOUND", diskStatusNotFound, "Disk not found"},
	{"PERM", diskStatusPerm, "Disk access permissions deny"},
}

type DiskMetaloc struct {
	Timestamp uint64 `json:"created-timestamp"`
	// Plevel: number of shards per disk
	Plevel int `json:"plevel"`
	// main disk name, e.g. scsi-35000c500842a615b
	Device string `json:"device"`
	// Index of a the first journal partition
	FirstJournalPart int `json:"jpart"`
	//journal name, e.g. ata-SanDisk_SD6SB2M512G1022I_140751401308
	Journal string `json:"journal"`
	// mdoffload partition, e.g. ata-SanDisk_SD6SB2M512G1022I_140751401308-part10
	Mdoffload string `json:"offload"`
	// The previous device name. Used for disk replacement
	Oldname string `json:"oldname"`
	// EdgeFS' disk ID
	VdevID string `json:"vdevid"`
	// RTRD version
	Version int `json:"version"`
	// Mask of metadata types situated on the mdoffload SSD partition
	Metamask int `json:"metamask"`
	// bcache enable (1) or disable (0)
	Bcache int `json:"bcache"`
	// write-ahead load enabled(1) or disabled(0)
	Wal int `json:"wal"`
	// LMDB environment's page size, main partitions
	Psize uint64 `json:"psize"`
	// LMDB environment's page size, mdoffload partition
	Mdpsize uint64 `json:"mdpsize"`
	// An array of faults signature. Each fault's handler has to add
	//there an entry. The array is cleared when all faults are recovered.
	Faults []string `json:"faults"`
	// Current VDEV state, see the rdStateEnum
	State int `json:"state"`
	//Maintenance command ID. It can be the last performed activity
	//(state == rdstateOk) or pending/running one (state == rdstateMaintenance).
	MaintenanceCmd []string `json:"mtcmd"`
	//  PID of a process which is running the maintenance job.
	// 0 if no such a process,
	// Non-zero if there is (was) a process trying to execute the required
	// maintenance job
	Pid int `json:"pid"`
	//Number of times the maintenance was started,
	//but not finished (interrupted, crashed). Used to avoid
	//endless maintenance loop. The disk must be marked as faulted after a
	//number of attempts
	Retries int `json:"retries"`
}

type RdFaultEntry struct {
	Plevel int
	Id     int
	Code   int
}

func (e* RdFaultEntry) String() string {
	return fmt.Sprintf("%v%v%v", e.Code, faultIDs[e.Id], e.Plevel)
}

type ccowd struct {
	Transport string `json:"transport"`
}

func diskStopBcache(disk *config.LocalDisk) error {
	for _, part := range disk.Partitions {
		path := fmt.Sprintf("/sys/block/%v/%v/bcache/stop", disk.Name, part.Name)
		if _, err := os.Stat(path); err == nil {
			err = ioutil.WriteFile(path, []byte("1"), 0400)
			if err != nil {
				fmt.Println("File", path, "write error:", err)
				return err
			}
		}
	}
	return nil
}

func diskDeleteMetaloc(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0660)
	if err != nil {
		return err
	}
	defer f.Close()
	b := []byte{0, 0, 0, 0, 0}
	_, err = f.WriteAt(b, metalocDiskOffset)
	if err != nil {
		return err
	}
	return nil
}

func ReadMetaloc(path string) (DiskMetaloc, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0660)
	if err != nil {
		return DiskMetaloc{}, err
	}
	defer f.Close()
	buff := make([]byte, 1024)
	_, err = f.ReadAt(buff, metalocDiskOffset)
	if err != nil {
		return DiskMetaloc{}, err
	}
	var meta DiskMetaloc
	lastIdx := bytes.Index(buff, []byte("}"))
	if lastIdx < 0 {
		return DiskMetaloc{}, fmt.Errorf("The metaloc record not found, the device must be new or formatted")
	}
	buff = buff[6 : lastIdx+1]

	err = json.Unmarshal(buff, &meta)
	if err != nil {
		return DiskMetaloc{}, err
	}
	if meta.Version < metalocMinSupportedVersion {
		return DiskMetaloc{}, fmt.Errorf("Unsupported metaloc version %v", meta.Version)
	}
	return meta, nil
}

func (meta *DiskMetaloc) DecodeMetalocFaults() ([]RdFaultEntry, error) {
	var ret []RdFaultEntry
	for _,e := range(meta.Faults) {
		fault := RdFaultEntry{0,0,0}
		faultStr := ""
		n, err := fmt.Sscanf(e, "%d%1s%d", &fault.Code, &faultStr, &fault.Plevel)
		if err != nil || n != 3 {
			return ret, fmt.Errorf("Unable to parse the fault code %v", e)
		}
		fault.Id = FaultIDTotal
		for i,v := range (faultIDs) {
			if v == faultStr {
				fault.Id = i
				break
			}
		}
		if fault.Id == FaultIDTotal {
			return ret, fmt.Errorf("Couldn't decode fault string %v", e)
		}
		ret = append(ret, fault)
	}
	return ret, nil
}

func WriteMetaloc(path string, meta *DiskMetaloc) error {
	buff, err := json.MarshalIndent(meta, "    ", "    ")
	if err != nil {
		return err
	}
	buff = append([]byte("NEFMT1"), buff...)
	f, err := os.OpenFile(path, os.O_WRONLY, 0660)
	if err != nil {
		return err
	}
	defer func () {
		f.Close()
		// Give the udev time to re-create /dev/ entries
		i := 0
		for ;i < 600; i++ {
			time.Sleep(100 * time.Millisecond)
			_,err = os.Stat(path)
			if err == nil {
				break
			}
		}
	}()
	for i := len(buff); i < metalocSize; i++ {
		buff = append(buff, 0)
	}
	_, err = f.WriteAt(buff, metalocDiskOffset)
	if err != nil {
		return err
	}
	return err
}

func diskDestroyGPT(disk *config.LocalDisk) error {
	err := diskStopBcache(disk)
	if err != nil {
		return err
	}
	for _, part := range disk.Partitions {
		if part.Size < 10*1024*1024 {
			continue
		}
		kdev := "/dev/" + part.Name
		err := exec.Command("/bin/dd", "if=/dev/zero", "of="+kdev, "bs=1M", "count=10").Run()
		if err != nil {
			fmt.Println("Error while executing a dd command for partition", part.Name, ":", err)
			return err
		}
	}

	if err = diskDeleteMetaloc("/dev/" + disk.Name); err != nil {
		fmt.Println("Error deleting a metaloc record:", err)
		return err
	}
	if err = exec.Command("sgdisk", "-Z", "/dev/"+disk.Name).Run(); err != nil {
		fmt.Println("Partition table destroying error:", err)
		return err
	}
	for cnt := 0; cnt < 10; cnt++ {
		err = exec.Command("partprobe", "/dev/"+disk.Name).Run()
		if err != nil {
			log.Print("Error while partptobe" + err.Error())
			time.Sleep(3000)
		} else {
			break
		}
	}
	return err
}

func diskDetach(diskID string) (int, error) {
	rc := -1
	ch, err := efsutil.CreateCcowdChannel(20 * 60 * 1000)
	if ch == nil {
		return -1, fmt.Errorf("Channel create error: %v", err)
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("DISK_DETACH_%s", diskID)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			return -1, fmt.Errorf("Channel request error: %v", err)
		}
		n, _ := fmt.Sscanf(string(resp), "DISK_DETACH_REPLY%d", &rc)
		if n != 1 {
			return -1, fmt.Errorf("Server returned unknown response %v",
				string(resp))
		}
	}
	return rc, nil
}

func diskStatus(diskID string) (int, error) {
	ch, err := efsutil.CreateCcowdChannel(3000)
	if ch == nil {
		fmt.Println("Channel create error:", err)
		return -1, fmt.Errorf("Channel create error: %v", err)
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("DISK_STATUS_%s", diskID)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			return -1, err
		} else {
			var status string
			fmt.Sscanf(string(resp), "DISK_STATUS_REPLY_%s", &status)
			for _, v := range diskStatusOpts {
				if strings.HasPrefix(status, v.id) {
					return v.code, nil
				}
			}
			return -1, fmt.Errorf("Unknown status: %v", status)
		}
	}
	return -1, fmt.Errorf("Never happens")
}

func diskAttach(diskID string) (int, error) {
	ch, err := efsutil.CreateCcowdChannel(20 * 60 * 1000)
	if err != nil {
		return -1, err
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("DISK_ATTACH_%s", diskID)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			return -1, fmt.Errorf("Channel request error:%v", err)
		} else {
			var status int = -1
			n, _ := fmt.Sscanf(string(resp), "DISK_ATTACH_REPLY%d", &status)
			if n != 1 {
				return -1, fmt.Errorf("Invalid response: %v", string(resp))
			}
			return status, nil
		}
	}
	return -1, fmt.Errorf("Never happens")
}

func diskSetReadOnly(diskID string) (int, error) {
	ch, err := efsutil.CreateCcowdChannel(10 * 1000)
	if ch == nil {
		return -1, fmt.Errorf("Channel create error: %v", err)
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("DISK_ROFORCE_%s", diskID)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			return -1, fmt.Errorf("Channel request error: %v", err)
		}
		status := -1
		n, _ := fmt.Sscanf(string(resp), "DISK_ROFORCE_REPLY%d", &status)
		if n != 1 {
			return -1, fmt.Errorf("Unknow server response: %v", string(resp))
		}
		return status, nil
	}
	return -1, fmt.Errorf("Never happens")
}

func diskDiscovery(diskID string) (int, error) {
	ch, err := efsutil.CreateCcowdChannel(20 * 60 * 1000)
	if ch == nil {
		return -1, fmt.Errorf("Channel create error: %v", err)
	} else {
		defer ch.Close()
		cmd := fmt.Sprintf("DISK_DISCOVERY_%s", diskID)
		resp, err := ch.Request(cmd, 256)
		if err != nil {
			return -1, fmt.Errorf("Channel request error: %v", err)
		}
		status := -1
		n, _ := fmt.Sscanf(string(resp), "DISK_DISCOVERY_REPLY%d", &status)
		if n != 1 {
			return -1, fmt.Errorf("Server returned unknown response %v", string(resp))
		}
		return status, nil
	}
	return -1, fmt.Errorf("Never happens")
}

func GetRTDevices(path string) ([]config.RTDevice, error) {
	var rtDevs config.RTDevices
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &rtDevs)
	if err != nil {
		return nil, err
	}
	return rtDevs.Devices, nil
}

// Fetch array of LocalDisk whose basic parameters corresponds the reference device
func getLocalDeviceListByRef(ref_disk_name string) (localDisks []config.LocalDisk, err error) {
	// Get all local disks, except partitions
	tmpDisks, err := config.DiscoverDevicesPred(func(disk *config.LocalDisk) bool {
		if disk.Type == "part" || disk.Type == "md" {
			return false
		}
		return true
	})
	if err != nil {
		fmt.Errorf("Couldn't fetch locad disks:%v", err)
		return nil, err
	}
	expType := ""
	rotational := false
	// Looking for refrence disk
	// to get its type and rotational flag
	for _, tmpDisk := range tmpDisks {
		links := strings.Split(tmpDisk.DevLinks, " ")
		for _, link := range links {
			id := strings.Replace(link, "/dev/disk/by-id/", "", 1)
			if id == ref_disk_name {
				expType = tmpDisk.Type
				rotational = tmpDisk.Rotational
				break
			}
		}
		if len(expType) > 0 {
			break
		}
	}

	if len(expType) == 0 {
		return nil, fmt.Errorf("ERROR: Couldn't identify a reference disk type as it is missing in /dev/disk/by-id.\n"+
		                       "       If you running in Kubernetes, execute this command within Target Pod")
	}
	// Creating new slice according to disk's internals
	for _, tmpDisk := range tmpDisks {
		if tmpDisk.Type == expType && tmpDisk.Rotational == rotational {
			tmpDisk.Partitions, _, err = config.GetDevicePartitions(tmpDisk.Name)
			skip := false
			for _, part := range tmpDisk.Partitions {
				if len(part.MountPoint) > 0 {
					skip = true
					break
				}
			}
			if !skip {
				localDisks = append(localDisks, *tmpDisk)
			}
		}
	}
	return localDisks, nil
}

var (
	nedgeHome string
	diskCmd   = &cobra.Command{
		Use:   "device",
		Short: "The disk management",
	}

	diskDetachCmd = &cobra.Command{
		Use:   "detach <disk-name>",
		Short: "Detach a disk from its key-value backend(s)",
		Long:  "Detach a disk from its key-value backend(s)",
		Run: func(cmd *cobra.Command, args []string) {
			if 0 == len(args) {
				fmt.Println("ERROR: disk ID isn't specified\n")
				os.Exit(1)
			}
			status, err := diskStatus(args[0])
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}
			if status == diskStatusNotFound {
				fmt.Println("ERROR: Disk", args[0], "not found\n")
				os.Exit(1)
			} else if status == diskStatusUnavail {
				fmt.Println("ERROR: Disk", args[0], "is detached already\n")
				os.Exit(1)
			}
			rc, err := diskDetach(args[0])
			if err != nil {
				fmt.Println("ERROR: ", err)
				os.Exit(1)
			}
			if rc == mStatusOk {
				fmt.Println("INFO: Disk", args[0], "is successfully detached")
			} else {
				fmt.Println("ERROR: Disk", args[0], "detach failed with code", rc)
			}
		},
	}

	diskAttachCmd = &cobra.Command{
		Use:   "attach <disk-name>",
		Short: "Attach a disk to its key-value backend(s)",
		Long:  "Attach a disk to its key-value backend(s)",
		Run: func(cmd *cobra.Command, args []string) {
			if 0 == len(args) {
				fmt.Println("ERROR: disk ID isn't specified")
				os.Exit(1)
			}
			status, err := diskStatus(args[0])
			if err != nil {
				fmt.Println("ERROR: status request returned", err)
				os.Exit(1)
			}
			if status == diskStatusNotFound {
				fmt.Println("ERROR: Disk", args[0], "not found\n")
				os.Exit(1)
			} else if status != diskStatusUnavail &&
				status != diskStatusRoForced &&
				status != diskStatusInit {
				fmt.Println("ERROR: Disk", args[0], "is attached already\n")
				os.Exit(1)
			}
			fmt.Println("INFO: Trying to attach, it can take several minutes...")
			res, err := diskAttach(args[0])
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}
			if res != mStatusOk {
				fmt.Println("ERROR: command returned a code ", res)
				os.Exit(1)
			}
			fmt.Println("INFO: Disk", args[0], "is successfully attached")
		},
	}
	diskStatusCmd = &cobra.Command{
		Use:   "status <disk-name>",
		Short: "Shows current disk status",
		Long:  "Shows current disk status",
		Run: func(cmd *cobra.Command, args []string) {
			if 0 == len(args) {
				fmt.Println("Error: disk ID isn't specified")
				os.Exit(1)
			}
			status, err := diskStatus(args[0])
			if err != nil {
				fmt.Println("ERROR: status request returned", err)
				os.Exit(1)
			}

			if status == mNoEntry {
				fmt.Println("ERROR: Disk not found")
				os.Exit(1)
			} else {
				for _, v := range diskStatusOpts {
					if v.code == status {
						fmt.Println("\n", v.desc, "\n")
						os.Exit(0)
					}
				}
				fmt.Println("ERROR: Uknown status code", status)
				os.Exit(1)
			}
		},
	}
	diskReadOnlyCmd = &cobra.Command{
		Use:   "readonly <disk-name>",
		Short: "Set a disk Read-Only",
		Long: "Set a disk Read-Only for maintenance purpose. Use an \"Attach\" " +
			"command to reset this state",
		Run: func(cmd *cobra.Command, args []string) {
			if 0 == len(args) {
				fmt.Println("ERROR: disk ID isn't specified")
				os.Exit(1)
			}
			status, err := diskStatus(args[0])
			if err != nil {
				fmt.Println("ERROR: status request returned", err)
				os.Exit(1)
			}
			if status == mNoEntry {
				fmt.Println("ERROR: Disk not found")
				os.Exit(1)
			} else if status == diskStatusUnavail {
				fmt.Println("ERROR: Disk", args[0], "is unavailable\n")
				os.Exit(1)
			} else {
				status, err = diskSetReadOnly(args[0])
				if err != nil {
					fmt.Println("ERROR: %v", err)
					os.Exit(1)
				}
				if status == diskStatusPerm {
					fmt.Println("ERROR: disk", args[0], "cannot be set read-only at the moment\n")
					os.Exit(1)
				} else if status == mStatusOk {
					fmt.Println("INFO: Disk", args[0], "set read-only.")
				} else {
					fmt.Println("ERROR: unknown error code", int(status))
				}
			}
		},
	}
	diskList = &cobra.Command{
		Use:   "list",
		Short: "Show disks in use/available",
		Long:  "Show disks in use/available",
		Run: func(cmd *cobra.Command, args []string) {
			rtDevs, err := GetRTDevices(nedgeHome + RtrdConfigPath)
			if err != nil {
				fmt.Println("ERROR: Cannot fetch devices list from rt-rd.json:", err)
				os.Exit(1)
			}

			localDisks, err := getLocalDeviceListByRef(rtDevs[0].Name)
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}
			offline := false
			table := tablewriter.NewWriter(os.Stdout)
			if !simple_output {
				table.SetBorder(false)
				table.SetHeader([]string{"Name", "VDEV ID", "Path", "Status"})
			}
			nConfigured := 0;
			knownNames := make(map[string]int)

			for _, disk := range localDisks {
				var rtDev config.RTDevice
				var diskName string
				var vdevID string
				status := diskUnused
				for _, rtd := range rtDevs {
					if strings.Contains(disk.DevLinks, rtd.Name) {
						rtDev = rtd
						diskName = rtd.Name
						break
					}
				}
				if (rtDev.Detached != 0) || (!append_spare && (len(rtDev.Device) == 0)) {
					continue
				}
				if len(diskName) == 0 {
					if status == diskUnused && len(disk.Partitions) > 0 {
						status = diskPartitioned
					}
					links := strings.Split(disk.DevLinks, " ")
					if len(links) == 0 {
						fmt.Println("WARN: the disk", disk.Name, "doesn't have a symlink in the /dev folder")
						continue
					}
					for _, link := range links {
						if strings.Contains(link, "/dev/disk/by-id") &&
							!strings.Contains(link, "wwn-") &&
							!strings.Contains(link, "uuid") {
							diskName = strings.TrimPrefix(link, "/dev/disk/by-id/")
							break
						}
					}
				}
				if _,ok := knownNames[diskName]; ok {
					// already shown to usr
					continue
				} else {
					path, err := diskPathById(diskName)
					if err != nil || path != "/dev/" + disk.Name {
						// Workaround for dualport disks
						// Make sure the symlink points at the /dev entry we
						// are processing
						continue
					}
				}
				if len(rtDev.Device) > 0 {
					// Getting VDEV ID
					var meta DiskMetaloc
					meta, err = ReadMetaloc(rtDev.Device)
					if err != nil {
						fmt.Println("WARN: a metaloc not found on disk", rtDev.Name)
					} else {
						vdevID = meta.VdevID
					}
					if !offline {
						st, err := diskStatus(rtDev.Name)
						if err != nil {
							status = "OFFLINE"
							offline = true
						} else {
							if st == mNoEntry {
								status = "UNKNOWN"
							} else {
								for _, v := range diskStatusOpts {
									if v.code == st {
										if st != diskStatusAlive {
											status = v.id
										} else {
											status = "ONLINE"
										}
									}
								}
							}
						}
					} else {
						status = "OFFLINE"
					}
				}
				nConfigured++
				knownNames[diskName] = 1
				if !simple_output {
					table.Append([]string{diskName, vdevID, "/dev/" + disk.Name, status})
				} else {
					fmt.Println(diskName, vdevID, "/dev/"+disk.Name, status)
				}
			}
			if len(rtDevs) > nConfigured {
				/* The RTRD could have some VDEV(s) which weren't detected by the OS */
p1:
				for _,rtDev := range(rtDevs) {
					if rtDev.Detached != 0 {
						continue
					}
					for _, disk := range (localDisks) {
						if strings.Contains(disk.DevLinks, rtDev.Name) {
							continue p1
						}
					}
					if !simple_output {
						table.Append([]string{rtDev.Name, "", "", "NOT FOUND"})
					} else {
						fmt.Println(rtDev.Name, "", "", "NOT FOUND")
					}
				}
			}
			if !simple_output {
				fmt.Println()
				table.Render()
				fmt.Println()
			}
		},
	}
	diskReplace = &cobra.Command{
		Use:   "replace <old-disk-name> <new-disk-name>",
		Short: "Hot disk replacement tool",
		Long:  "Use to replace an HDD with new one without a service interruption",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				fmt.Println("Usage: replace <old_disk_id> <new_disk_id>")
				os.Exit(1)
			}
			var old_disk, new_disk = args[0], args[1]

			// Make sure the old disk is configured and is in use
			rtdevs, err := GetRTDevices(nedgeHome + RtrdConfigPath)
			if err != nil {
				fmt.Println("ERROR: Cannot fetch devices list from rt-rd.json:", err)
				os.Exit(1)
			}
			if len(rtdevs) == 0 {
				fmt.Println("ERROR: The RTRD configuration is empty")
				os.Exit(1)
			}
			var old_rtdisk config.RTDevice
			for _, dev := range rtdevs {
				if dev.Name == new_disk {
					fmt.Println("ERROR: the disk", new_disk, "is in RTRD configuration already")
					os.Exit(1)
				} else if dev.Name == old_disk {
					old_rtdisk = dev
				}
			}
			if len(old_rtdisk.Device) == 0 {
				fmt.Println("ERROR: Could find source device", old_disk, "in RTRD configuration file")
				os.Exit(1)
			}
			// Checking presence of a new disk
			// Fetch list of local disks
			ldisks, err := getLocalDeviceListByRef(old_disk)
			var new_disk_cfg, old_disk_cfg config.LocalDisk

			if err != nil {
				fmt.Println("ERROR: fetching local devices:", err)
				os.Exit(1)
			}
			found := false
			for _, ldisk := range ldisks {
				if strings.Contains(ldisk.DevLinks, old_disk) {
					old_disk_cfg = ldisk
					if found {
						break
					} else {
						continue
					}
				}
				if !strings.Contains(ldisk.DevLinks, new_disk) {
					continue
				}
				links := strings.Split(ldisk.DevLinks, " ")
				if len(links) == 0 {
					fmt.Println("WARN: the disk", ldisk.Name, "doesn't have a symlink in the /dev folder")
					continue
				}
				for _, link := range links {
					if strings.Contains(link, "/dev/disk/by-id") &&
						!strings.Contains(link, "wwn-") &&
						!strings.Contains(link, "uuid") {
						ldisk.DevLinks = link
						break
					}
				}
				new_disk_cfg = ldisk
				found = true
			}
			if !found {
				fmt.Println("ERROR: Couldn't find a disk", new_disk)
				os.Exit(1)
			}
			// There are 3 possible situations:
			// a) The ccow-daemon is running and the old disk is attached.
			//    this is a normal flow
			// b) The ccow-daemon is stopped, old disk is present in the system
			//    and accessible. Just modify all the configuration paramters and
			//    the new disk will be attached on the next start
			// c) Old disk is physically removed from the system or cannot be read.
			//    In such a case we need to find its fringerprints in
			//    rt-rd.json and in backup metaloc file. Otherwise the automatic
			//    replacement will be impossible
			var ccowd_running, old_disk_removed = true, false
			if len(old_disk_cfg.Name) == 0 {
				fmt.Println("INFO: The old disk seems to be removed")
				old_disk_removed = true
			}
			old_disk_status, err := diskStatus(old_disk)
			if err != nil {
				ccowd_running = false
				fmt.Println("INFO: the ccow-daemon isn't running")
			} else if old_disk_status == mNoEntry {
				fmt.Println("ERROR: the disk", old_disk, "isn't attached to ccow-daemon. Internal error")
				os.Exit(1)
			}
			// Both devices are here. However the destination VDEV has to be wiped out.
			// Make sure it's not mounted and ask user for a permittion to destroy
			// a partition table
			if len(new_disk_cfg.Partitions) > 0 {
				for _, part := range new_disk_cfg.Partitions {
					if len(part.MountPoint) > 0 {
						fmt.Println("ERROR: The partition /dev/", part.Name,
							"mounted. Umount the partition and try again")
						os.Exit(1)
					}
				}
				if !force_replace {
					fmt.Printf("ERROR: the disk %v has partitions and cannot be used."+
						" Use -f option to override this restriction.\n", new_disk)
					os.Exit(1)
				} else if !accept_all {
					msg := fmt.Sprintf("WARNING: The disk /dev/%v has %v partitions."+
						" The partition table will be DESTROYED.\nDo you want to continue?",
						new_disk_cfg.Name, len(new_disk_cfg.Partitions))
					c := efsutil.AskForConfirmation(msg)
					if !c {
						fmt.Println("INFO: Operation canceled")
						os.Exit(1)
					}
				}
				err = diskDestroyGPT(&new_disk_cfg)
				if err != nil {
					fmt.Println("ERROR: error while destroying GPT of", new_disk_cfg.Name)
					os.Exit(1)
				}
			} else {
				diskDeleteMetaloc("/dev/" + new_disk_cfg.Name)
			}
			// Read old disk metaloc table
			var meta DiskMetaloc
			meta, err = ReadMetaloc(old_rtdisk.Device)
			if err != nil {
				// Try to get info from a reserve copy
				if !old_disk_removed {
					fmt.Println("WARN: main metaloc record not found, trying to find a backup copy")
				}
				buff, err := ioutil.ReadFile(nedgeHome + "/var/run/disk/" + old_disk + ".metaloc")
				if err != nil {
					fmt.Println("ERROR: couldn't find any metaloc copies," +
						"automatic replacement is impossible")
					os.Exit(1)
				}
				err = json.Unmarshal(buff, &meta)
				if err != nil {
					fmt.Println("ERROR: parsing backup metaloc.")
					fmt.Println(string(buff))
					os.Exit(1)
				}
			}
			// Update and store a metaloc on a new disk
			meta.Device = new_disk
			meta.Oldname = old_disk
			meta.MaintenanceCmd = []string{"diskReplace"}
			meta.State = rdstateMaintenance
			meta.Faults = []string{}
			err = WriteMetaloc("/dev/"+new_disk_cfg.Name, &meta)
			if err != nil {
				fmt.Println("ERROR: new metaloc write error", err)
				os.Exit(1)
			}

			if ccowd_running && !old_disk_removed && old_disk_status != diskStatusUnavail {
				// Detach the old disk, if still attached
				fmt.Println("INFO: Detaching the disk", old_disk, ". This can take a while..")
				rc, err := diskDetach(old_disk)
				if err != nil {
					fmt.Println("ERROR: couldn't detach:", err)
					os.Exit(1)
				} else if rc != mStatusOk {
					fmt.Println("ERROR: detach error code", rc)
				}
			}
			// Replace disk name in RTRD config file
			read, err := ioutil.ReadFile(nedgeHome + RtrdConfigPath)
			if err != nil {
				fmt.Println("ERROR: couldn't read thr rt-rd.json file", err)
				os.Exit(1)
			}
			newContents := strings.Replace(string(read), old_disk, new_disk, 1)
			newContents = strings.Replace(newContents, old_rtdisk.Device,
				"/dev/"+new_disk_cfg.Name, 1)
			err = ioutil.WriteFile(nedgeHome+RtrdConfigPath, []byte(newContents), 0)
			if err != nil {
				fmt.Println("ERROR: couldn't overwrite thr rt-rd.json file", err)
				os.Exit(1)
			}
			// Remove old disk's backup metaloc
			os.Remove(nedgeHome + "/var/run/disk/" + old_disk + ".metaloc")
			// Format mdoffload (for hybrid only)
			if len(meta.Mdoffload) > 0 {
				mdPath, err := diskPathById(meta.Mdoffload)
				if err != nil {
					fmt.Println("ERROR: couldn't resolve metaloc partition path %v", meta.Mdoffload)
					os.Exit(1)
				}
				err = exec.Command("dd", "if=/dev/zero", "of=" + mdPath, "bs=1M", "count=10").Run()
				if err != nil {
					fmt.Println("ERROR: metaloc partition format error %v", err)
					os.Exit(1)
				}
				fmt.Printf("INFO: formatted metaloc partition at %v\n", mdPath)
			}
			if ccowd_running {
				// Probbing new device
				fmt.Println("INFO: Probbing disk", new_disk)
				if rc, err := diskDiscovery(new_disk); err != nil || rc != mStatusOk {
					if err != nil {
						fmt.Println("ERROR: probe of the device", new_disk, "failed:", err)
					} else {
						fmt.Println("ERROR: probe of the device", new_disk, "failed:", rc)
					}
					os.Exit(1)
				}
				fmt.Println("INFO: Attaching disk", new_disk)
				// And finally attaching the new disk
				if rc, err := diskAttach(new_disk); err != nil || rc != mStatusOk {
					if err != nil {
						fmt.Println("ERROR: while attaching", new_disk, ":", err)
					} else {
						fmt.Println("ERROR: while attaching", new_disk, ":", rc)
					}
					os.Exit(1)
				}
				fmt.Println("INFO: The disk is replaced succefully")
			} else {
				fmt.Println("INFO: The new disk is configured and will be " +
					"attached on the next ccow-daemon start")
			}
		},
	}
	force_replace = false
	accept_all    = false
	simple_output = false
	append_spare  = false

	DeviceCommand = &cobra.Command{
		Use:   "device",
		Short: "Devices management tools",
		Long:  "Devices management tools",
	}
	IsRTRD bool = true
)

func init() {
	nedgeHome = os.Getenv("NEDGE_HOME")
	if nedgeHome == "" {
		nedgeHome = config.DefaultNedgePrefix
	}
	buff,err := ioutil.ReadFile(nedgeHome + ccowdConfigPath)
	if err == nil {
		var cfg ccowd
		err = json.Unmarshal(buff, &cfg)
		if err == nil {
			IsRTRD = cfg.Transport == "rtrd"
		}
	}
	
	DeviceCommand.AddCommand(diskDetachCmd)
	DeviceCommand.AddCommand(diskAttachCmd)
	DeviceCommand.AddCommand(diskStatusCmd)
	if (IsRTRD) {
		DeviceCommand.AddCommand(diskReadOnlyCmd)
		DeviceCommand.AddCommand(diskList)
		DeviceCommand.AddCommand(diskReplace)
		diskReplace.Flags().BoolVarP(&force_replace, "force", "f", false, "Force device replacement")
		diskReplace.Flags().BoolVarP(&accept_all, "yes", "y", false, "Answer `Y` to all questions")
		diskList.Flags().BoolVarP(&simple_output, "ascetic", "a", false, "Use machine-readable format")
		diskList.Flags().BoolVarP(&append_spare, "spare", "s", false, "Show also spare disks")
	}
}
