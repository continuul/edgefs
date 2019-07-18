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
	"../efsutil"
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"sort"
)

type LMDBDbiInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Entries uint64 `json:"entries"`
	Pages   uint64 `json:"pages"`
}

type LMDBEnvInfo struct {
	Psize        uint64        `json:"psize"`
	MapSize      uint64        `json:"mapsize"`
	MapUsed      uint64        `json:"mapused"`
	Entries      uint64        `json:"entries"`
	FreelistSize uint64        `json:"freelist_size"`
	Error        int           `json:"error"`
	ErrorString  string        `json:"errorstr"`
	Dbis         []LMDBDbiInfo `json:"dbi"`
}

func (info *LMDBEnvInfo) Capacity() uint64 {
	return info.MapSize * info.Psize
}

func (info *LMDBEnvInfo) Used() uint64 {
	return (info.MapUsed - info.FreelistSize) * info.Psize
}

type LMDBEnv struct {
	// Disk is as in /dev/disk/by-id
	id string
	// Path in /dev/
	path string
	// Disk available space
	capacity uint64
	// To distinguish raw device and filesystem's env
	isRaw bool
	// Is env environment detected and ::info is a valid field
	isValid bool
	// The environment is clean (formatted)
	formatted bool
	// Uses a bcache
	bcache bool
	// Role in the device structure.
	// -1 - undefined, 0 - mdoffload, 1 and more - plevel
	role int
	// Faults list
	faults []RdFaultEntry
	// Result of the last environment structure verification
	verifyResult structCheckResult
	// Environment information (if available)
	info LMDBEnvInfo
	// The FREE_DBI corrupted flag
	freeListCorrupted bool
	// Container for prost-processing commands
	actions map[string]int
}

const (
	gDbiUtilErrorNone = iota
	gDbiUtilErrorOpenDB
	gDbiUtilErrorReadDBInternals
	gDbiUtilErrorReadDBStructure
	gDbiUtilErrorReadKey
	gDbiUtilErrorReadValue
	gDbiUtilErrorPut
	gDbiUtilErrorCopySrcCorrupted
	gDbiUtilErrorCopyDstCorrupted
	gDbiUtilErrorInProgress
	gDbiUtilErrorFreeDBICorrupted
	gDbiUtilErrorFormatted
	// Internal errors
	gDbiUtilErrorParse
	gDbiUtilErrorMaxCorrupted
	gDbiUtilErrorSkipped
	gDbiUtilErrorCrash = -10
)

type dbiCheckResult struct {
	openError        int
	readError        int
	writeError       int
	corruptedEntries uint64
	errorStr         string
	policy           dbiCheckPolicy
}

type structCheckResult struct {
	// Error happened on env open
	envOpenFailed bool
	// Error explanation
	errorStr string
	// A fatal error has been detected
	hasFatalError bool
	// A non-fatal error has been detected
	hasError bool
	// Per-DBI's check result
	dbis map[string]dbiCheckResult
}

type dbiUtilState struct {
	Error     int    `json:"error"`
	ErroStr   string `json:"errorstr"`
	Corrupted uint64 `json:"corrupted"`
	Entries   uint64 `json:"entries"`
	Progress  int    `json:"progress"`
}

const (
	defaultCheckPolicyPath = "/etc/ccow/deviceCheckPolicy.json"
	checkPolicySkip        = "skip"
	checkPolicyAll         = "all"
	checkPolicyFailAfter   = "failAfter:"
	errorPolicySkip        = "skip"
	errorPolicySkipOnError = "skipOnError"
	errorPolicyFatalError  = "fatalError"
)

type dbiCheckPolicy struct {
	//
	// A rexep to match DBI name which is a subject of current policy
	NamePattern []string `json:"name_pattern"`
	//
	// Key/value pair check seerity. 0..3
	RdCheckComplexity int `json:"rd_check_level"`
	//
	// An allowed probability for a DBI to contain undiscovered damages
	// Expressed in % of total number of entries.
	// The number of entries in array defines number of verification passes to be done
	// Example: 0% all entries to be checked
	//          0.001% to check 10000 entries
	//          1% to check only 100 entries
	// Note: entries to be checked are taken randomly and cover whole key/value range
	RdCheckFactor []float64 `json:"rd_check_factor"`
	//
	// The same as RdCheckFactor, but for write test
	WrCheckFactor []float64 `json:"wr_check_factor"`
	//
	// Read test policy can be set to
	// "skip" to never validate such kind to DBI.
	// "failAfter:<n>" to validate the DBI and mark it as failed if <n> or more
	//                 values didn't pass validation.
	//                 allowed <n> range from 1 to any reasonable integer number
	RdCheckPolicy string `json:"rd_check_policy"`
	//
	// Write test policy can be set to
	// "skip" to never validate such kind to DBI.
	//  "all" execute the test
	WrCheckPolicy string `json:"wr_check_policy"`
	//
	// Error policy is from set:
	// "skip" ignore any DBI errors. Never copy/compactify this DBI
	// "skipOnError" skip DBI copy/compaction if verification failed
	//  "fatalError" the verirification error is vital for whole environment.
	ErrorPolicy string `json:"error_policy"`
	//
	// A special post-process action ID to be added to metaloc if copying of the DBI
	// was skipped due to error (ErrorPolicy == "skipOnError")
	// The action will be detected and executed by the ccow-daemon
	PostActionCmd string `json:"post_action,omitempty"`
	//
	// If the DBI check has failed, then do not repeat verification with the last
	// LMDB transaction rolled out
	SkipRollback bool `json:"skip_rollback"`
}

type dbiCheckPolicies struct {
	//
	// Maximum allowed FREE_DBI size expresses in pages.
	// Start compaction if bigger than that
	FreeListMaxSize uint64 `json:"free_list_max_size,omitempty"`
	//
	// The same as previous, but relative to LMDB's map size
	// This one has priority over freeListMaxSize
	FreeListMaxSizeRel uint64                    `json:"free_list_max_size_rel,omitempty"`
	ForceYes           bool  `json:"force_yes,omitempty"`
	Policies           map[string]dbiCheckPolicy `json:"dbi_policies"`
}

var defaultCheckPolicy = dbiCheckPolicy{
	NamePattern:       []string{"."},
	RdCheckComplexity: 2,
	RdCheckFactor:     []float64{0}, // 0% means check every entry
	WrCheckFactor:     []float64{1}, // 1% to check at least 100 entries per DBI, usually in range 100..200
	RdCheckPolicy:       "failAfter:1",
	WrCheckPolicy:     checkPolicyAll,
	ErrorPolicy:       errorPolicyFatalError,
}

var defaultCheckPolicies = dbiCheckPolicies{
	FreeListMaxSize: 10000000,
	Policies: map[string]dbiCheckPolicy{
		"payload": dbiCheckPolicy{
			NamePattern:       []string{"^TT_CHUNK_PAYLOAD", "bd-part[0-9]+-TT_CHUNK_PAYLOAD"},
			RdCheckComplexity: 3,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"cm": dbiCheckPolicy{
			NamePattern:       []string{"^TT_CHUNK_MANIFEST", "bd-part[0-9]+-TT_CHUNK_MANIFEST"},
			RdCheckComplexity: 3,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"vm": dbiCheckPolicy{
			NamePattern:       []string{"^TT_VERSION_MANIFEST", "bd-part[0-9]+-TT_VERSION_MANIFEST"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"pm": dbiCheckPolicy{
			NamePattern:       []string{"^TT_PARITY_MANIFEST", "bd-part[0-9]+-TT_PARITY_MANIFEST"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"vbr": dbiCheckPolicy{
			NamePattern:       []string{"^TT_VERIFIED_BACKREF", "bd-part[0-9]+-TT_VERIFIED_BACKREF"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10000",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"nameindex": dbiCheckPolicy{
			NamePattern:       []string{"^TT_NAMEINDEX", "bd-part[0-9]+-TT_NAMEINDEX"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:10",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"hashcount": dbiCheckPolicy{
			NamePattern:       []string{"^TT_HASHCOUNT", "bd-part[0-9]+-TT_HASHCOUNT"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:1",
			WrCheckPolicy:      checkPolicySkip,
			ErrorPolicy:       errorPolicyFatalError,
		},
		"rdkeys": dbiCheckPolicy{
			NamePattern:       []string{"keys-.*"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:1",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicySkipOnError,
			PostActionCmd:     "rebuildRdKeys",
			SkipRollback:      true,
		},
		"mdcache": dbiCheckPolicy{
			NamePattern:       []string{"mdcache-.*"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:1",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicySkipOnError,
			PostActionCmd:     "rebuildRdKeys",
			SkipRollback:      true,
		},
		"temporary_md": dbiCheckPolicy{
			NamePattern: []string{
				"^TT_BATCH_QUEUE", "bd-part[0-9]+-TT_BATCH_QUEUE",
				"^TT_BATCH_INCOMING_QUEUE", "bd-part[0-9]+-TT_BATCH_INCOMING_QUEUE",
				"^TT_VERIFICATION_QUEUE", "bd-part[0-9]+-TT_VERIFICATION_QUEUE",
				"^TT_ENCODING_QUEUE", "bd-part[0-9]+-TT_ENCODING_QUEUE",
				"^TT_TRANSACTION_LOG", "bd-part[0-9]+-TT_TRANSACTION_LOG",
				"^TT_REPLICATION_QUEUE", "bd-part[0-9]+-TT_REPLICATION_QUEUE"},
			RdCheckComplexity: 2,
			RdCheckFactor:     []float64{1, 0.1, 0},
			WrCheckFactor:     []float64{10},
			RdCheckPolicy:       "failAfter:1",
			WrCheckPolicy:     checkPolicySkip,
			ErrorPolicy:       errorPolicySkipOnError,
			SkipRollback:      true,
		},
	},
}

type envError uintptr

const (
	envErrorCorrupted envError = 1
)

func (e envError) Error() (ret string) {
	switch e {
	case envErrorCorrupted:
		ret = "The environment structure corrupted"
	}
	return
}

type envSlice []*LMDBEnv

func (p envSlice) Len() int {
	return len(p)
}
func (p envSlice) Less(i, j int) bool{
	return p[i].role > p[j].role
}
func (p envSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// convert size in bytes to a human-readable format
func toCapacityStr(size uint64) (ret string) {
	if size > 1024*1024*1024 {
		ret = strconv.FormatFloat(float64(size)/(1024*1024*1024), 'f', 2, 32) + "G"
	} else if size > 1024*1024 {
		ret = strconv.FormatFloat(float64(size)/(1024*1024), 'f', 2, 32) + "M"
	} else if size > 1024 {
		ret = strconv.FormatFloat(float64(size)/1024, 'f', 2, 32) + "K"
	} else {
		ret = strconv.FormatFloat(float64(size), 'f', 2, 32)
	}
	return
}

// A trivial console progress bar implementation
func progressBar(cur, max uint64) {
	progresLen := uint64(32)
	perc := uint64(0)
	if max > 0 {
		perc = 100 * cur / max
		if perc > 100 {
			perc = 100
		}
	}
	active := progresLen * perc / 100
	fmt.Print("[")
	if active > 1 {
		for i := uint64(0); i < active-1; i++ {
			fmt.Print("=")
		}
	}
	if active > 0 && active < progresLen {
		fmt.Print(">")
	}
	for i := active; i < progresLen; i++ {
		fmt.Print("_")
	}
	fmt.Print("]")
}

// Convert a diskID string to its /dev path
func diskPathById(id string) (string, error) {
	link := "/dev/disk/by-id/" + id
	s, err := os.Stat(link)
	if err != nil {
		return "", fmt.Errorf("symlink not found")
	}
	if (s.Mode() & (os.ModeSymlink | os.ModeDevice)) == 0 {
		return "", fmt.Errorf("%v not a symlink, mode %v", link, uint32(s.Mode()))
	}
	return filepath.EvalSymlinks(link)
}

// An auxiliary function for getDiskParams
func parseKeyValuePairString(propsRaw string) map[string]string {
	// first split the single raw string on spaces and initialize a map of
	// a length equal to the number of pairs
	propsRaw = strings.TrimSuffix(propsRaw, "\n")
	props := strings.Split(propsRaw, " ")
	propMap := make(map[string]string, len(props))

	for _, kvpRaw := range props {
		// split each individual key value pair on the equals sign
		kvp := strings.Split(kvpRaw, "=")
		if len(kvp) == 2 {
			// first element is the final key, second element is the final value
			// (don't forget to remove surrounding quotes from the value)
			propMap[kvp[0]] = strings.Replace(kvp[1], `"`, "", -1)
		}
	}

	return propMap
}

// Get disk size and a mount point
func getDiskParams(kpath string) (size uint64, mountpoint string, err error) {
	output, err := exec.Command("lsblk", kpath,
		"--bytes", "--nodeps", "--pairs", "--output", "SIZE,MOUNTPOINT").Output()
	if err != nil {
		return
	}

	props := parseKeyValuePairString(string(output))
	size, err = strconv.ParseUint(props["SIZE"], 10, 64)
	if err != nil {
		err = fmt.Errorf("Internal: absent or invalie SIZE property: %v", err)
		return
	}
	mountpoint = props["MOUNTPOINT"]
	return
}

// Get the diskInfo structure retuned by a `dbi_util -i` call
func EnvInfo(kpath string) (info LMDBEnvInfo, err error) {
	out, err := exec.Command(nedgeHome+"/sbin/dbi_util", "-i", kpath).Output()
	if len(out) > 0 {
		err = json.Unmarshal(out, &info)
		return
	}
	return
}

func showMetalocInfo(meta *DiskMetaloc) error {
	var faults []RdFaultEntry
	var err error
	if len(meta.Faults) > 0 {
		faults, err = meta.DecodeMetalocFaults()
		if err != nil {
			return err
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetBorder(false)
	table.SetHeader([]string{"Name", "Type", "ID", "Path", "Capacity", "Used",
		"PSIZE", "Bcache", "Status"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	for i := 1; i <= meta.Plevel; i++ {
		path, err := filepath.EvalSymlinks("/dev/disk/by-id/" + meta.Device + "-part" + strconv.Itoa(i))
		if err != nil {
			return fmt.Errorf("Couldn't find location of the plevel%v: %v", i, err)
		}
		size, _, err := getDiskParams(path)
		if err != nil {
			return err
		}
		faultStr := "None"
		for _, e := range faults {
			if e.Id == FaultIDMain && e.Plevel == i {
				faultStr = "CORRUPTED"
				break
			}
		}
		bcacheStr := "n/a"
		if len(meta.Journal) > 0 {
			if meta.Bcache != 0 {
				bpath, err := getBcache(path)
				if err != nil {
					bcacheStr = "DETACHED"
				} else {
					bcacheStr = bpath
				}
			} else {
				bcacheStr = "OFF"
			}
		}
		used := 0
		info, err := EnvInfo(path)
		if err == nil {
			used = int(info.Used()*100/size)
		}
		table.Append([]string{"PLEVEL" + strconv.Itoa(i), "Main",
			meta.Device + "-part" + strconv.Itoa(i), path,
			toCapacityStr(size), strconv.Itoa(used)+"%", strconv.Itoa(int(meta.Psize)/1024) + "k",
			bcacheStr, faultStr})
		if meta.Wal != 0 {
			wlink := ""
			if len(meta.Journal) > 0 {
				wlink = meta.Journal + "-part" + strconv.Itoa(meta.FirstJournalPart+i-1)
			} else {
				wlink = meta.Device + "-part" + strconv.Itoa(meta.FirstJournalPart+i-1)
			}
			wpath, err := filepath.EvalSymlinks("/dev/disk/by-id/" + wlink)
			if err != nil {
				return fmt.Errorf("Couldn't find location of a journal for plevel%v: %v", i, err)
			}

			wFaultStr := "None"
			for _, e := range faults {
				if e.Id == FaultIDWAL && e.Plevel == i {
					wFaultStr = strconv.Itoa(e.Code)
					break
				}
			}
			wsize, _, err := getDiskParams(wpath)
			if err != nil {
				return err
			}
			table.Append([]string{"", "WAL", wlink, wpath, toCapacityStr(wsize), "",
				strconv.Itoa(4096/1024) + "k", "n/a", wFaultStr})
		}
	}
	if len(meta.Mdoffload) > 0 {
		mpath, err := filepath.EvalSymlinks("/dev/disk/by-id/" + meta.Mdoffload)
		if err != nil {
			return fmt.Errorf("Couldn't find location of a mdoffload: %v", err)
		}
		mFaultStr := "None"
		for _, e := range faults {
			if e.Id == FaultIDOffload {
				mFaultStr = "CORRUPTED"
				break
			}
		}
		msize, _, err := getDiskParams(mpath)
		if err != nil {
			return err
		}
		used := 0
		info, err := EnvInfo(mpath)
		if err == nil {
			used = int(info.Used()*100/msize)
		}
		table.Append([]string{"OFFLOAD", "", meta.Mdoffload, mpath,
			toCapacityStr(msize), strconv.Itoa(used)+"%", strconv.Itoa(int(meta.Mdpsize)/1024) + "k", "n/a",
			mFaultStr})
	}
	fmt.Println()
	table.Render()
	fmt.Println()
	return nil
}

func partPathFromArgs(diskID, argOpt string) (string, bool, error) {
	ret := ""
	srcKdev, err := diskPathById(diskID)
	if err != nil {
		return "", false, fmt.Errorf("Couldn't find device name for disk %v: %v", diskID, err)
	}
	meta, err := ReadMetaloc(srcKdev)
	if err != nil {
		return "", false, err
	}
	envType := 'p'
	if argOpt == "m" {
		if len(meta.Journal) == 0 {
			return "", false, fmt.Errorf("Current device configuration doesn't support metadata offload")
		} else {
			ret = meta.Mdoffload
		}
	} else {
		plevel := 0
		n, err := fmt.Sscanf(argOpt, "%c%d", &envType, &plevel)
		if err != nil || n != 2 {
			return "", false, fmt.Errorf("Cannot parse part specificator %v", argOpt)
		}
		if envType != 'p' && envType != 'w' {
			return "", false, fmt.Errorf("Invalid environment specifier %c, expected a value `w` or `p`",
				envType)
		}
		if envType == 'w' && 0 == meta.Wal {
			return "", false, fmt.Errorf("Environment doesn't support WAL")
		}
		if plevel == 0 || plevel > meta.Plevel {
			return "", false, fmt.Errorf("Invalid plevel %v, expected a value in range 1..%v",
				meta.Plevel)
		}
		if envType == 'p' {
			ret = diskID + "-part" + strconv.Itoa(plevel)
		} else {
			if len(meta.Journal) > 0 {
				ret = meta.Journal
			} else {
				ret = diskID
			}
			ret +=  "-part" + strconv.Itoa(meta.FirstJournalPart+plevel-1)
		}
	}
	return ret, envType == 'w', nil
}

func getScratchAreaPath() (string, error) {
	path := ""
	if len(scratchArea) > 0 {
		// User has specified scratch area path or diskID
		return scratchArea, nil
	} else {
		// Trying to find scratch are location
		var rtScr struct {
			Scratch string `json:"scratch"`
		}
		b, err := ioutil.ReadFile(nedgeHome + RtrdConfigPath)
		if err != nil {
			return "", fmt.Errorf("Coudln't read RTRD configuration file: %v", err)
		}
		err = json.Unmarshal(b, &rtScr)
		if err != nil {
			return "", fmt.Errorf("Coudln't parse RTRD configuration file: %v", err)
		}
		path = rtScr.Scratch
	}
	if len(path) == 0 {
		return "", fmt.Errorf("Cannot establish a scratch are location. " +
			"Use `-s <path>` or add path to RTRD configuration")
	}
	return path, nil
}

func saveCheckPolicies(path string, policies *dbiCheckPolicies) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("    ", "    ")
	if err = enc.Encode(policies); err != nil {
		return err
	}
	return nil
}

func loadCheckPolicies(path string) (dbiCheckPolicies, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return dbiCheckPolicies{}, err
	}
	var ret dbiCheckPolicies
	err = json.Unmarshal(buf, &ret)
	if err != nil {
		return dbiCheckPolicies{}, err
	}
	for name, policy := range ret.Policies {
		if len(policy.NamePattern) == 0 {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `name_pattern` mustn't be empty", name)
		}
		for _, pattern := range policy.NamePattern {
			if _, err := regexp.Compile(pattern); err != nil {
				return dbiCheckPolicies{}, fmt.Errorf("[%v] the `name_pattern` invalid regexp %v", name, pattern)
			}
		}
		if policy.RdCheckComplexity < 0 || policy.RdCheckComplexity > 3 {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_level` mustn't be in range 0..3", name)
		}
		failAfter := 0
		n, err := fmt.Sscanf(policy.RdCheckPolicy, checkPolicyFailAfter+"%d", &failAfter)
		if err == nil {
			if n != 1 {
				return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_policy` invalid argument %v",
					name, policy.RdCheckPolicy)
			} else if failAfter < 1 {
				return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_policy` value `failAfter:<n>` where <n> must be greater or equal 1",
					name)
			}
		} else if policy.RdCheckPolicy != checkPolicySkip {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_policy` invalid value %v",
				name, policy.RdCheckPolicy)
		}

		if policy.WrCheckPolicy != checkPolicySkip && policy.WrCheckPolicy != checkPolicyAll {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `wr_check_policy` invalid value %v",
				name, policy.WrCheckPolicy)
		}

		if policy.ErrorPolicy != errorPolicySkip &&
			policy.ErrorPolicy != errorPolicySkipOnError &&
			policy.ErrorPolicy != errorPolicyFatalError {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `copy_policy` invalid value %v",
				name, policy.ErrorPolicy)
		}

		if len(policy.RdCheckFactor) == 0 {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_factor` must be non-zero lenght array of float values",
				name)
		}
		for _, f := range policy.RdCheckFactor {
			if f < 0 || f > 100.0 {
				return dbiCheckPolicies{}, fmt.Errorf("[%v] the `rd_check_factor` value %v is out of range 0...100.0",
					name)
			}
		}

		if len(policy.WrCheckFactor) == 0 {
			return dbiCheckPolicies{}, fmt.Errorf("[%v] the `wr_check_factor` must be non-zero lenght array of float values",
				name)
		}
		for _, f := range policy.WrCheckFactor {
			if f < 0 || f > 100.0 {
				return dbiCheckPolicies{}, fmt.Errorf("[%v] the `wr_check_factor` value %v is out of range 0...100.0",
					name)
			}
		}
	}
	return ret, nil
}

func getBcache(path string) (string, error) {
	var re = regexp.MustCompile(`/dev/(?:((.+)p\d+)|((\D+)\d+))$`)
	res := re.FindStringSubmatch(path)
	if len (res) == 0 {
		return "",fmt.Errorf("Invalid disk or partition path %v", path)
	}
	// if matches:
	// res[0] whole capture
	// res[1] and res[2] are non-zero if path format is /dev/sda1
	// res[3] and res[4] are non-zero of path format is /dev/md0p1 or /dev/mmcblk0p1
	sysPath := ""
	if len(res[1]) > 0 && len(res[2]) > 0 {
		sysPath = "/sys/block/"+res[2]+"/"+res[1]
	} else if len(res[3]) > 0 && len(res[4]) > 0 {
		sysPath = "/sys/block/"+res[4]+"/"+res[3]
	} else {
		panic(fmt.Sprintf("(internal regexp for disk path) invalid capture slice for path %v\n", path))
	}
	sysPath += "/bcache/dev/uevent"
	file, err := os.Open(sysPath)
	if err != nil {
		// The bache not found
		return "",err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.Split(line, "=")
		if len(tokens) != 2 {
			panic(fmt.Sprintf("(internal) read %v line format error: %v", sysPath, line))
		}
		if tokens[0] == "DEVNAME" {
			return "/dev/" + tokens[1], nil
		}
	}

	panic(fmt.Sprintf("(internal) parisng %v: couldn't find token 'DEVMANE'", sysPath))
	return "",nil
}

// Create a new LMDBEnv instance
// @param path can be either raw disk path, either a symlink to a raw disk
// or a filesystem mount path
func NewLMDBEnv(path string) (env LMDBEnv, err error) {
	env.id = path
	env.actions = make(map[string]int)
	env.path, err = diskPathById(path)
	if err != nil {
		// Not a symlink in /dev/disk/by-id folder
		// Must be real RAW disk or filesystem path
		env.path = path
	}

	bcache, err := getBcache(env.path)
	if err == nil {
		// The partiotion is attached to bcache
		env.path = bcache
		env.bcache = true
	}
	sStat, err1 := os.Stat(env.path)
	if err1 == nil && (sStat.Mode()&os.ModeDevice) != 0 {
		// Looks like a RAW disk path
		destSize, destMountPoint, err1 := getDiskParams(env.path)
		if err1 != nil {
			err = fmt.Errorf("Internal error: %v", err)
			return
		}
		if len(destMountPoint) > 0 {
			err = fmt.Errorf("The sratch partition is moounted at %v", destMountPoint)
			return
		}
		env.isRaw = true
		env.capacity = destSize
	} else {
		// Path within filesystem
		// Make sure it points to a file within an existsing folder
		dir := filepath.Dir(env.path)
		if dir == env.path {
			err = fmt.Errorf("LMDB environment path within filesystem has " +
				"to point to a regular file")
			return
		}
		s := syscall.Statfs_t{}
		err = syscall.Statfs(dir, &s)
		if err != nil {
			err = fmt.Errorf("The folder %v doesn't exists", dir)
			return
		}
		env.isRaw = false
	}
	// Getting environment info (if available)
	env.info, err = EnvInfo(env.path)
	if err != nil {
		return
	}
	env.isValid = true
	env.formatted = false
	if env.info.Error == gDbiUtilErrorFormatted {
		env.isValid = false
		env.formatted = true
	} else if env.info.Error != gDbiUtilErrorNone &&
		env.info.Error != gDbiUtilErrorFreeDBICorrupted {
		env.isValid = false
	} else if env.info.Error == gDbiUtilErrorFreeDBICorrupted {
		env.freeListCorrupted = true
	}
	return
}

func (env *LMDBEnv) Capacity() (uint64, error) {
	if !env.isRaw {
		dir := filepath.Dir(env.path)
		s := syscall.Statfs_t{}
		err := syscall.Statfs(dir, &s)
		if err != nil {
			return 0, fmt.Errorf("The folder %v doesn't exists", dir)
		}
		return uint64(s.Bsize) * uint64(s.Bfree), nil
	} else {
		return env.capacity, nil
	}
}

func (env *LMDBEnv) UpdateInfo() error {
	info, err := EnvInfo(env.path)
	if err != nil {
		return fmt.Errorf("Cannot find LMDB environment's header")
	}
	env.info = info
	return nil
}

func (env *LMDBEnv) Format() error {
	if env.isRaw {
		env.formatted = true
		return exec.Command("dd", "if=/dev/zero", "of="+env.path, "bs=1M", "count=20").Run()
	} else {
		//On a filesystem it's enough to remove the underlaying file
		os.Remove(env.path)
		return nil
	}
}

func (env *LMDBEnv) Copy(scratch *LMDBEnv, compactify bool) error {
	cmdArgs := []string{"-n"}
	if scratch.isRaw {
		cmdArgs = append(cmdArgs, "-r")
	}
	if compactify {
		cmdArgs = append(cmdArgs, "-c")
	}
	cmdArgs = append(cmdArgs, env.path, scratch.path)
	return exec.Command(nedgeHome+"/sbin/mdb_copy", cmdArgs...).Run()
}

func (env *LMDBEnv) DBICopy(scratch *LMDBEnv, dbiName string) error {

	dbiMaxEntries := uint64(0)
	for _, dbi := range env.info.Dbis {
		if dbi.Name == dbiName {
			dbiMaxEntries = dbi.Entries
			break
		}
	}
	if dbiMaxEntries == 0 {
		fmt.Printf("DBI %30v: ", dbiName)
		fmt.Printf(" zero lenght, skipped\n")
		return nil
	}
	args := []string{"-d", "-l", "1", "-n", dbiName}
	if scratch.isRaw {
		args = append(args, "-r")
	}
	args = append(args, env.path, scratch.path)
	cmd := exec.Command(nedgeHome+"/sbin/dbi_util", args...)
	stdout, _ := cmd.StdoutPipe()
	rd := bufio.NewReader(stdout)
	if err := cmd.Start(); err != nil {
		return err
	}
	var dState dbiUtilState
	for line, err1 := rd.ReadString('\n'); err1 == nil; line, err1 = rd.ReadString('\n') {
		if err := json.Unmarshal([]byte(line), &dState); err != nil {
			return fmt.Errorf("read check JSON unmarshal error: %v", line)
		}
		fmt.Printf("DBI %30v: ", dbiName)
		progressBar(dState.Entries, dbiMaxEntries)
		fmt.Printf("  %v%%", 100*dState.Entries/dbiMaxEntries)
		if dState.Error != gDbiUtilErrorInProgress {
			fmt.Printf("\n")
			break
		}
		fmt.Printf("\r")
	}
	cmd.Wait()
	if dState.Error != gDbiUtilErrorNone {
		return fmt.Errorf("%v", dState.ErroStr)
	}
	return nil
}

func (env *LMDBEnv) VerifyStructure(pol *dbiCheckPolicies, prevSnapshot bool, wal bool) (res structCheckResult, err error) {
	// Fetch DBI info
	if !env.isValid {
		res.envOpenFailed = true
		res.errorStr = "The environment is absent or corrupted"
		err = fmt.Errorf(res.errorStr)
		return
	}
	res.envOpenFailed = false

	maxEntries := uint64(0)
	checkedEntries := uint64(0)
	var dbiResult dbiUtilState

	// Calulate total number of entries
	for _, dbi := range env.info.Dbis {
		ents := dbi.Entries
	pol_loop:
		for _, v := range pol.Policies {
			for _, pat := range v.NamePattern {
				valid := regexp.MustCompile(pat)
				if valid.Match([]byte(dbi.Name)) {
					ents *= uint64(len(v.RdCheckFactor) + len(v.WrCheckFactor))
					break pol_loop
				}
			}
		}
		maxEntries += ents
	}

	res.dbis = make(map[string]dbiCheckResult)
	for _, dbi := range env.info.Dbis {
		var dRes dbiCheckResult
		dbiCheckedEntries := uint64(0)
		entries := dbi.Entries
		dRes.policy = defaultCheckPolicy

		// Trying to find policy entry for current DBI
	pol_loop2:
		for _, v := range pol.Policies {
			for _, pat := range v.NamePattern {
				valid := regexp.MustCompile(pat)
				if valid.Match([]byte(dbi.Name)) {
					dRes.policy = v
					break pol_loop2
				}
			}
		}
		if len(dRes.policy.RdCheckFactor) > 1 {
			entries *= uint64(len(dRes.policy.RdCheckFactor))
		}
		var maxCorrupted uint64 = 0
		// Aplly the `skip` policy
		if dRes.policy.RdCheckPolicy == checkPolicySkip {
			checkedEntries += entries
			dRes.readError = gDbiUtilErrorSkipped
			res.dbis[dbi.Name] = dRes
			goto ModifyTest
		}
		// the `failAfter:<n>` policy allows up to <n> corrupted values (not keys!)

		if n, err1 := fmt.Sscanf(dRes.policy.RdCheckPolicy, checkPolicyFailAfter+"%d", &maxCorrupted); n != 1 || err1 != nil {
			err = fmt.Errorf("Uknown chek policy: %v", dRes.policy.RdCheckPolicy)
			return
		}

		for _, factor := range dRes.policy.RdCheckFactor {
			// Transform factor expressed in % into entries
			dbiUtilFactor := int(float64(dbi.Entries) * factor / 100.0)
			if dbiUtilFactor == 0 {
				// Check each entry
				dbiUtilFactor = 1
			}
			args := []string{"-c", strconv.Itoa(dRes.policy.RdCheckComplexity), "-f",
				strconv.Itoa(dbiUtilFactor), "-l", "1", "-n", dbi.Name}
			if maxCorrupted > 0 {
				args = append(args, "-s")
			}
			if prevSnapshot {
				args = append(args, "-p")
			}
			if wal {
				args = append(args, "-W")
			}
			args = append(args, env.path)
			cmd := exec.Command(nedgeHome+"/sbin/dbi_util", args...)
			stdout, _ := cmd.StdoutPipe()
			rd := bufio.NewReader(stdout)
			if err = cmd.Start(); err != nil {
				return
			}
			for line, err1 := rd.ReadString('\n'); err1 == nil; line, err1 = rd.ReadString('\n') {
				if err = json.Unmarshal([]byte(line), &dbiResult); err != nil {
					err = fmt.Errorf("read check JSON unmarshal error: %v", line)
					return
				}
				fmt.Printf("Progress: ")
				progressBar(dbiResult.Entries+dbiCheckedEntries+checkedEntries, maxEntries)
				perc := uint64(100)
				if maxEntries > 0 {
					perc = 100*(dbiResult.Entries+dbiCheckedEntries+checkedEntries)/maxEntries
				}
				fmt.Printf("  %v%%    \r", perc)
				if dbiResult.Error != gDbiUtilErrorInProgress {
					break
				}
			}
			cmd.Wait()
			if dbiResult.Error == gDbiUtilErrorInProgress {
				// Something went wrong. the dbi_util must be crashed or killed
				err = fmt.Errorf("Internal: dbi_util has been terminated")
				return
			}
			dbiCheckedEntries += dbiResult.Entries
			dRes.readError = dbiResult.Error
			dRes.errorStr = dbiResult.ErroStr
			if (dbiResult.Error == gDbiUtilErrorReadValue || dbiResult.Error == gDbiUtilErrorReadKey) &&
				dbiResult.Corrupted > 0 {
				dRes.corruptedEntries = dbiResult.Corrupted
				if dRes.corruptedEntries >= maxCorrupted {
					dRes.readError = gDbiUtilErrorMaxCorrupted
					break
				} else {
					dRes.readError = gDbiUtilErrorNone
				}
			} else if dRes.readError != gDbiUtilErrorNone {
				break
			}
		}
		checkedEntries += entries
		if dRes.readError != gDbiUtilErrorSkipped &&
			dRes.readError != gDbiUtilErrorNone {
			res.hasError = true
			if dRes.policy.ErrorPolicy == errorPolicyFatalError {
				res.hasFatalError = true
			}
		}

ModifyTest:
		entries = dbi.Entries
		if len(dRes.policy.WrCheckFactor) > 1 {
			entries *= uint64(len(dRes.policy.WrCheckFactor))
		}

		// Aplly the `skip` policy
		// Also skip the test for a previous snapshot
		if dRes.policy.WrCheckPolicy == checkPolicySkip || prevSnapshot || wal{
			checkedEntries += entries
			dRes.writeError = gDbiUtilErrorSkipped
			res.dbis[dbi.Name] = dRes
			continue
		}

		// Write test
		dbiCheckedEntries = 0
		for _, factor := range dRes.policy.WrCheckFactor {
			// Transform factor expressed in % into entries
			dbiUtilFactor := int(float64(dbi.Entries) * factor / 100.0)
			if dbiUtilFactor == 0 {
				dbiUtilFactor = 1
			}
			cmd := exec.Command(nedgeHome+"/sbin/dbi_util", "-w", "-f",
				strconv.Itoa(dbiUtilFactor), "-l", "1", "-n", dbi.Name, env.path)
			stdout, _ := cmd.StdoutPipe()
			rd := bufio.NewReader(stdout)
			if err = cmd.Start(); err != nil {
				return
			}
			for line, err1 := rd.ReadString('\n'); err1 == nil; line, err1 = rd.ReadString('\n') {
				if err = json.Unmarshal([]byte(line), &dbiResult); err != nil {
					err = fmt.Errorf("read check JSON unmarshal error: %v", err)
					return
				}
				fmt.Printf("Progress: ")
				progressBar(dbiResult.Entries+dbiCheckedEntries+checkedEntries, maxEntries)
				perc := uint64(100)
				if maxEntries > 0 {
					perc = 100*(dbiResult.Entries+dbiCheckedEntries+checkedEntries)/maxEntries
				}
				fmt.Printf("  %v%%    \r", perc)
				if dbiResult.Error != gDbiUtilErrorInProgress {
					break
				}
			}
			cmd.Wait()
			if dbiResult.Error == gDbiUtilErrorInProgress {
				// Something went wrong. the dbi_util must be crashed or killed
				err = fmt.Errorf("Internal: dbi_util has been terminated")
				return
			}
			dbiCheckedEntries += dbiResult.Entries
			dRes.writeError = dbiResult.Error
			dRes.errorStr = dbiResult.ErroStr
			if dRes.writeError != gDbiUtilErrorNone {
				break
			}
		}
		checkedEntries += entries
		if dRes.writeError != gDbiUtilErrorNone && dRes.writeError != gDbiUtilErrorSkipped {
			res.hasError = true
			if dRes.policy.ErrorPolicy == errorPolicyFatalError {
				res.hasFatalError = true
			}
		}
		// Finish
		res.dbis[dbi.Name] = dRes
	}
	return
}

func (env *LMDBEnv) ShowVerificationResults() (err error) {
	if !env.isValid {
		return fmt.Errorf("environment structure corrupted or absent")
	}
	if env.verifyResult.envOpenFailed {
		fmt.Println("ERROR:", env.verifyResult.errorStr)
		fmt.Printf("INFO: The LMDB environment on %v got corrupted. Format is recomended\n",
			env.path)
		os.Exit(1)
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetBorder(false)
	table.SetHeader([]string{"DBI Name", "Entries", "Open test", "Read test", "Corrupted", "Write test"})
	for dbiName, dbiResult := range env.verifyResult.dbis {
		openResult := "PASSED"
		readResult := "N/A"
		writeResult := "N/A"
		corrupted := "N/A"
		entries := uint64(0)
		for _,dbi := range(env.info.Dbis) {
			if dbi.Name == dbiName {
				entries = dbi.Entries
				break
			}
		}
		if dbiResult.openError != gDbiUtilErrorNone {
			openResult = "FAILED"
			table.Append([]string{dbiName, strconv.Itoa(int(entries)), openResult,
				readResult, corrupted, writeResult})
			continue
		}
		if dbiResult.corruptedEntries > 0 {
			corrupted = strconv.Itoa(int(dbiResult.corruptedEntries))
		}
		if dbiResult.readError != gDbiUtilErrorNone {
			switch dbiResult.readError {
			case gDbiUtilErrorSkipped:
				readResult = "SKIPPED"
			case gDbiUtilErrorReadDBInternals:
				readResult = "INTERNAL ERROR"
			case gDbiUtilErrorReadDBStructure:
				readResult = "DB STRUCTURE ERROR"
			case gDbiUtilErrorReadKey:
				readResult = "KEY FORMAT ERROR"
			case gDbiUtilErrorReadValue:
				readResult = "VALUE FORMAT ERROR"
			case gDbiUtilErrorCrash:
				readResult = "CORRUPTED (CRASH)"
			case gDbiUtilErrorOpenDB:
				readResult = "DB OPEN ERROR"
			case gDbiUtilErrorMaxCorrupted:
				readResult = "TOO MANY CORRUPTED VALUES"
			default:
				readResult = "UNKNOWN CODE " + strconv.Itoa(dbiResult.readError)
			}
			table.Append([]string{dbiName, strconv.Itoa(int(entries)), openResult,
				readResult, corrupted, writeResult})
			continue
		}
		readResult = "PASSED"
		switch dbiResult.writeError {
		case gDbiUtilErrorSkipped:
			writeResult = "SKIPPED"
		case gDbiUtilErrorReadDBStructure:
			writeResult = "FETCH ERROR"
		case gDbiUtilErrorPut:
			writeResult = "PUT ERROR"
		case gDbiUtilErrorOpenDB:
			writeResult = "OPEN ERROR"
		case gDbiUtilErrorNone:
			writeResult = "PASSED"
		case gDbiUtilErrorCrash:
			readResult = "CORRUPTED"
		default:
			writeResult = "UNKNOWN CODE " + strconv.Itoa(dbiResult.writeError)
		}

		table.Append([]string{dbiName, strconv.Itoa(int(entries)), openResult,
			readResult, corrupted, writeResult})
	}
	fmt.Println()
	table.Render()
	fmt.Println()
	return nil
}

func (env *LMDBEnv) AppendPostCommand(cmd string) {
	if _, ok := env.actions[cmd]; !ok {
		env.actions[cmd] = 1
	} else {
		env.actions[cmd] = env.actions[cmd] + 1
	}
}

//
// The first stage of compaction: copy from source to scratch area
func (env *LMDBEnv) CompactionCopyTo(scratch string) error {
	tgtEnv, err := NewLMDBEnv(scratch)
	if err != nil {
		return err
	}

	tgtCap, err := tgtEnv.Capacity()
	if err != nil {
		return fmt.Errorf("scratch area capacity calculation error %v", err)
	}
	tgtEnv.Format()
	if tgtCap < env.info.Used() {
		return fmt.Errorf("capacity of the scratch area %v cannot fit source environment data %v",
			toCapacityStr(tgtCap), toCapacityStr(env.info.Used()))
	}
	for name, dbiRes := range env.verifyResult.dbis {
		if dbiRes.policy.ErrorPolicy == errorPolicySkip {
			// Handle "Skip" policy
			continue
		} else if dbiRes.openError != gDbiUtilErrorNone ||
			(dbiRes.readError != gDbiUtilErrorNone && dbiRes.readError != gDbiUtilErrorSkipped) ||
			(dbiRes.writeError != gDbiUtilErrorNone && dbiRes.writeError != gDbiUtilErrorSkipped) {
			if dbiRes.policy.ErrorPolicy == errorPolicySkipOnError {
				if len(dbiRes.policy.PostActionCmd) > 0 {
					env.AppendPostCommand(dbiRes.policy.PostActionCmd)
				}
				continue
			} else if dbiRes.policy.ErrorPolicy == errorPolicyFatalError {
				return fmt.Errorf("ERROR: unexpected policy %v on compaction",
					errorPolicyFatalError)
			}
		}
		err = env.DBICopy(&tgtEnv, name)
		if err != nil {
			return fmt.Errorf("(DBI %v copy) %v", name, err)
		}
	}
	return nil
}

func (env *LMDBEnv) CompactionCopyFrom(scratch string) error {
	tgtEnv, err := NewLMDBEnv(scratch)
	if err != nil {
		return err
	}
	if !tgtEnv.isValid {
		return fmt.Errorf("the scratch area doesn't contain a valid LMDB environment")
	}
	env.Format()
	// Temporary block SIGINT/SIGTERM
	// Otherwise the source environment WILL BE corrupted
	var sigChannel = make(chan os.Signal)
	signal.Notify(sigChannel, syscall.SIGTERM)
	signal.Notify(sigChannel, syscall.SIGINT)
	go func() {
		for _, ok := <-sigChannel; ok; _, ok = <-sigChannel {
			fmt.Println("Compaction is in progress. Do NOT try interrupt it!")
		}
	}()
	// Restoring
	err = tgtEnv.Copy(env, true)
	signal.Stop(sigChannel)
	close(sigChannel)
	if err != nil {
		return fmt.Errorf("scratch to source copy error. The scratch environment is still contain valid data")
	}
	// Cleaning scratch partition
	tgtEnv.Format()
	return nil
}

func deviceHeal(diskId, scratch string) error {
	kpath, err := diskPathById(diskId)
	if err != nil {
		return fmt.Errorf("couldn't find device name for disk %v: %v", diskId, err)
	}
	meta, err := ReadMetaloc(kpath)
	if err != nil {
		return fmt.Errorf("(read metaloc) %v", err)
	}
	metaOrig := meta

	fmt.Printf("INFO: checking disk %v. Stored metaloc record info:\n", kpath)
	err = showMetalocInfo(&meta)
	if err != nil {
		return fmt.Errorf("(metaloc decode) %v", err)
	}
	// Figure out whether the device configured
	rtDevs, err := GetRTDevices(nedgeHome + RtrdConfigPath)
	if err != nil {
		return fmt.Errorf("(gettng RTRD devices) %v", err)
	} else if len(rtDevs) == 0 {
		return fmt.Errorf("configured RTRD devices not found")
	}

	diskConfigured := false
	for _,dev := range rtDevs {
		if dev.Name == diskId {
			diskConfigured = true
			break
		}
	}

	// Loading policies
	ppath := policyPath
	if len(ppath) == 0 {
		ppath = nedgeHome + defaultCheckPolicyPath
	}
	policies, err := loadCheckPolicies(ppath)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			if len(policyPath) > 0 {
				return fmt.Errorf("couldn't find specified policy file %v\n", policyPath)
			}
			fmt.Printf("WARN: Couldn't find default policies config at %v, creating default\n",
				nedgeHome+defaultCheckPolicyPath)
			policies = defaultCheckPolicies
			saveCheckPolicies(nedgeHome+defaultCheckPolicyPath, &policies)
		} else {
			return fmt.Errorf("(policy parse)", err)
		}
	}

	forceYes := policies.ForceYes || accept_all

	// Preparing array of partitions used by the device
	// 0..Plevel-1 - main envs
	// Plevel..2*Plevel-1 WAL(s)
	// 2*Plevel = mdoffload
	var envs []*LMDBEnv
	// Put here environments to be validated
	validate := map[string]*LMDBEnv{}
	// Map of envs to be formatted
	format := map[string]*LMDBEnv{}
	// REcovered envs
	recovery := map[string]int{}
	// Compactified envs
	compact := map[string]int{}
	hybrid := false
	for i := 1; i <= meta.Plevel; i++ {
		env, err := NewLMDBEnv(meta.Device + "-part" + strconv.Itoa(i))
		if err != nil {
			return fmt.Errorf("(create envObject for %v) %v\n",
				meta.Device+"-part"+strconv.Itoa(i), err)
		}
		if env.formatted {
			fmt.Printf("INFO: PLEVEL%v environment on %v formatted, skipping\n",
				i, env.path)
			continue
		}
		// Roles: 
		//        N+1..2*N WAL plevels
		//        1..N main plevels
		//        0 - mdoffload env (if used)
		env.role = i
		envs = append(envs, &env)
	}
	/* Adding WALs environments */
	if meta.Wal != 0 {
		wal_path := meta.Device
		if len(meta.Journal) > 0 {
			wal_path = meta.Journal
		}
		for i := 0; i < meta.Plevel; i++ {
			wal := fmt.Sprintf("%v-part%v", wal_path, i + meta.FirstJournalPart)
			env, err := NewLMDBEnv(wal)
			if err != nil {
				return fmt.Errorf("(create envObject for WAL %v) %v\n",
					wal, err)
			}
			if env.formatted {
				fmt.Printf("INFO: WAL%v environment on %v formatted, skipping\n",
					i, env.path)
				continue
			}
			env.role = i + meta.Plevel + 1
			envs = append(envs, &env)
		}
	}
	if len(meta.Journal) > 0 && diskConfigured {
		// The hybrid configuration always has a dedicated journals SSD
		// However we won't check it if the device is not configured
		// because the SSD partition can be in use
		env, err := NewLMDBEnv(meta.Mdoffload)
		if err != nil {
			return fmt.Errorf("(create envObject for mdofflod %v) %v\n",
				meta.Mdoffload, err)
		}
		hybrid = true
		env.role = 0
		// The metaloc env is always the last one in the slice
		envs = append(envs, &env)
	}
	if len(meta.Journal) > 0 && !diskConfigured {
		fmt.Printf("WARN: disk %v not found in RT-RD configuration file.\n"+ 
			"      Its mdoffload partition can be in use and won't be checked\n",
			diskId)
	}
	// Looking for faults and dispathing them to corresponding env
	faults, err := meta.DecodeMetalocFaults()
	if err == nil {
		for _, fault := range faults {
			if fault.Id == FaultIDMain && fault.Plevel <= meta.Plevel {
				idx := fault.Plevel-1
				envs[idx].faults = append(envs[idx].faults, fault)
				// Append the env to a validation map
				validate[envs[idx].path] = envs[idx]
				fmt.Printf("WARN: a fault record is detected for plevel%v (%v)\n",
					fault.Plevel, envs[idx].path)
			} else if hybrid && fault.Id == FaultIDOffload {
				idx := len(envs) - 1
				envs[idx].faults = append(envs[idx].faults, fault)
				validate[envs[idx].path] = envs[idx]
				fmt.Printf("WARN: a fault record is detected for mdoffload (%v)\n",
					envs[idx].path)
			} else if meta.Wal != 0 && fault.Id == FaultIDWAL && fault.Plevel <= meta.Plevel {
				idx := meta.Plevel + fault.Plevel - 1
				envs[idx].faults = append(envs[idx].faults, fault)
				// Append the env to a validation map
				validate[envs[idx].path] = envs[idx]
				fmt.Printf("WARN: a WAL fault record is detected for plevel%v (%v)\n",
					fault.Plevel, envs[idx].path)
			} else {
				switch fault.Id {
				case FaultIDMaintenance:
					fmt.Printf("WARN: last maintenance command had failed. All environments will be re-checked.\n")
					for _, v := range envs {
						validate[v.path] = v
					}
				case FaultIDExternal:
					// External fault is set if a user submitted a disk detach command
					// Not an error
				}
			}
		}
	} else {
		return fmt.Errorf("(metaloc decode) %v", err)
	}
	formatDevice := false
	mainPartDamaged := 0
	walPartDamaged := 0
	onlineStatus := diskStatusNotFound
	newStatus := onlineStatus
	if diskConfigured {
		onlineStatus, err = diskStatus(diskId)
		if err != nil {
			onlineStatus = diskStatusOffline
		}
		for _, v := range diskStatusOpts {
			if v.code == onlineStatus {
				fmt.Printf("INFO: disk %v is %v\n", diskId, v.id)
			}
		}
		newStatus = onlineStatus
		if meta.Pid != 0 {
			// Looks like the device is locked, check PID presence
			if _, err := os.Stat("/proc/"+strconv.Itoa(meta.Pid)); err == nil {
				return fmt.Errorf("(metaloc check) the device seems to be locked by process PID %v", meta.Pid)
			}
		}
	}
	// Lock the device so that nobody can use until it gets released
	fmt.Printf("INFO: locking the device\n")
	meta.Pid = os.Getpid()
	prev := meta.State
	meta.State = rdstateMaintenance
	err = WriteMetaloc(kpath, &meta)
	if err != nil {
		return fmt.Errorf("(write metaloc) %v", err)
	}
	meta.State = prev
	var sigChannel = make(chan os.Signal)

	term := func (oldStatus int, newStatus *int, meta *DiskMetaloc) {
		finished := meta.Pid == 0
		if  !finished {
			// The  check/heal process haven't been finished
			// Restore original metaloc
			err = WriteMetaloc(kpath, &metaOrig)
			if err != nil {
				fmt.Printf("ERROR: (metaloc store on defer) %v\n", err)
			}
		}
		signal.Stop(sigChannel)
		close(sigChannel)
		if oldStatus != diskStatusOffline && oldStatus != diskStatusUnavail &&
			oldStatus != diskStatusNotFound && *newStatus != onlineStatus &&
			(meta.State == rdstateOk || meta.State == rdstateMaintenance) {
				yes := forceYes
				if !yes {
					msg := "INFO: The disk was detached. Do you want to attach it right now?"
					yes = efsutil.AskForConfirmation(msg)
				} else {
					fmt.Printf("INFO: The disk was detached. Re-attaching it\n")
				}
				if yes {
					res, err := diskAttach(diskId)
					if err != nil {
						fmt.Printf("ERROR: Couldn't attach: %v\n", err)
					} else if res != mStatusOk {
						fmt.Printf("ERROR: (on attach) server returned code %v\n", res)
					} else {
						fmt.Printf("INFO: succefully attached\n")
					}
				}
		}
		if finished {
			valstr := []string{}
			formstr := []string{}
			recstr := []string{}
			compstr := []string{}
			maxLen := len(validate)
			for name,_ := range(validate) {
				valstr = append(valstr, name)
			}
			if maxLen < len(format) {
				maxLen = len(format)
			}
			for name,_ := range(format) {
				formstr = append(formstr, name)
			}
			if maxLen < len(recovery) {
				maxLen = len(recovery)
			}
			for name,_ := range(recovery) {
				recstr = append(recstr, name)
			}
			if maxLen < len(compact) {
				maxLen = len(compact)
			}
			for name,_ := range(compact) {
				compstr = append(compstr, name)
			}
			if maxLen > 0 {
				fmt.Println("\nINFO: device examination summary:")
				table := tablewriter.NewWriter(os.Stdout)
				table.SetBorder(false)
				table.SetHeader([]string{"Validated", "Formatted", "Recovered", "Compactified"})
				table.SetAlignment(tablewriter.ALIGN_CENTER)
				for i := 0; i < maxLen; i++ {
					s1 := ""
					if len(valstr) > i {
						s1 = valstr[i]
					}
					s2 := ""
					if len(formstr) > i {
						s2 = formstr[i]
					}
					s3 := ""
					if len(recstr) > i {
						s3 = recstr[i]
					}
					s4 := ""
					if len(compstr) > i {
						s4 = compstr[i]
					}
					table.Append([]string{s1,s2,s3,s4})
				}
				table.Render()
			}
		}
	} 

	signal.Notify(sigChannel, syscall.SIGTERM)
	signal.Notify(sigChannel, syscall.SIGINT)
	go func() {
		for _, ok := <-sigChannel; ok; _, ok = <-sigChannel {
			fmt.Printf("Terminating...\n")
			term(onlineStatus, &newStatus, &meta)
			os.Exit(0)
		}
	}()
	
	defer term(onlineStatus, &newStatus, &meta)

	// Look for completely destroyed records
	for _, env := range envs {
		if !env.isValid {
			envType := "mdoffload"
			if env.role > 0 && env.role <= meta.Plevel {
				envType = "plevel" + strconv.Itoa(env.role)
			} else if env.role > meta.Plevel {
				envType = "WAL" + strconv.Itoa(env.role - meta.Plevel + 1)
			}
			if hybrid && env.role == 0 {
				fmt.Printf("ERROR: the mdoffload environment header corrupted."+
					" This is unrecoverable. Device format is suggested\n")
				formatDevice = true
				goto Format
			}
			if env.role <= meta.Plevel {
				mainPartDamaged++
			} else if env.role > meta.Plevel {
				walPartDamaged++
			}
			if mainPartDamaged >= meta.Plevel {
				fmt.Println("ERROR: Looks like all the main environemnts were corrupted. Device format is suggested\n")
				formatDevice = true
				goto Format
			} else {
				fmt.Printf("ERROR: (%v) the environment header corrupted."+
					" Partition %v needs to be formatted\n", envType, env.path)
				format[env.path] = env
				if _, ok := validate[env.path]; ok {
					delete(validate, env.path)
				}
				if _, ok := format[env.path]; !ok && env.freeListCorrupted {
					fmt.Printf("WARN: (%v) the free list DBI got corrupted."+
						" The environment %v has to be checked and compactified\n",
						envType, env.path)
					validate[env.path] = env
				}
			}
		}
	}
	// Several options here:
	// 1) No faults in metaloc and all envs are passed an "open" test
	//    In this case Ask a user if he wants to do extended data structure validation
	//    if not, then go to disk fragmentation stuff
	// 2) Detected one or several partition faults (meta.State == rdstateFault || meta.State == rdstateReadOnly)
	//    or a maintenance fault.
	//    Solution: affected environments must pass the extended validation test
	//    When done and faults are confirmed, then either format or compaction to be applied
	if len(format) == 0 && len(validate) == 0 {
		yes := forceYes
		if !yes {
			msg := fmt.Sprintf("INFO: Pre-check procedure couldn't detect any known problems.\n" +
				"      An extended data validation is recomended. This can take a long while.\n" +
				"      Do you want to continue?")
			yes = efsutil.AskForConfirmation(msg)
		} else {
			fmt.Printf("INFO: Pre-check procedure couldn't detect any known problems.\n"+
				"       An extended data validation will be executed.\n")
		}
		if !yes {
			goto Format
		} else {
			for _, env := range envs {
				validate[env.path] = env
			}
		}
	} else {
		if len(format) > 0 {
			fmt.Printf("INFO: %v partition(s) needs to be formatted\n", len(format))
		}
		if len (validate) > 0 {
			fmt.Printf("INFO: %v partition(s) needs to be validated\n", len(validate))
		} else {
			yes := forceYes
			if !yes {
				msg := fmt.Sprintf("INFO: No partitions are scheduled for validation.\n" +
				"      However, an exteded validation can help to discover hidden problems.\n"+
				"      Answer `Y` if you want to do an additional check.\n"+
				"      Note: this can take a long while.")
				yes = efsutil.AskForConfirmation(msg)
			} else {
				fmt.Printf("INFO: No partitions are scheduled for validation.\n" +
				"      However, an exteded validation can help to discover hidden problems.\n")
			}
			if yes {
				for _, env := range envs {
					if _,ok := format[env.path]; !ok {
						validate[env.path] = env
					}
				}
			}
		}
	}
	if len(validate) > 0 {
		if onlineStatus == diskStatusRoEvac {
			return fmt.Errorf(" a row evacuation task is active on the disk %v. "+
				"Stop it and run the check again", diskId)
		}
		if onlineStatus != diskStatusUnavail &&
			onlineStatus != diskStatusRoFault &&
			onlineStatus != diskStatusRoForced &&
			onlineStatus != diskStatusOffline &&
			onlineStatus != diskStatusNotFound {
			yes := forceYes
			if !yes {
				msg := fmt.Sprintf("WARN: an extended data validation is about to begin.\n"+
					"      The device %v will be set READ-ONLY.\n      Do you want to continue?",
					diskId)
				yes = efsutil.AskForConfirmation(msg)
			} else {
				fmt.Printf("INFO: set the device READ-ONLY\n")
			}
			if !yes {
				fmt.Println("INFO: Operation canceled")
				return nil
			}
			// Switching a device to read-only-forced
			res, err := diskSetReadOnly(diskId)
			if err != nil || res != mStatusOk {
				return fmt.Errorf("error setting disk %v read-only", diskId)
			}
			newStatus = diskStatusRoForced
		}
		var validateSlice envSlice
		for _,e := range validate {
			validateSlice = append(validateSlice, e)
		}
		sort.Sort(validateSlice);

	validateLoop:
		for _, env := range validateSlice {
			envType := "mdoffload"
			if env.role > 0 && env.role <= meta.Plevel {
				envType = "plevel" + strconv.Itoa(env.role)
			} else if env.role > meta.Plevel {
				envType = "WAL" + strconv.Itoa(env.role - meta.Plevel + 1)
			}

			fmt.Printf("INFO: validating %v at %v\n", envType, env.path)
			res, err := env.VerifyStructure(&policies, false, env.role > meta.Plevel)
			if err != nil {
				fmt.Printf("ERROR: validation process termiated with error %v. The partition will be formatted\n", err)
				format[env.path] = env
				continue
			}
			// If there are any error, then we can repat the validation
			// using the last but one LMDB snaphot
			// Unless it's disabled for a corrupted DBI
			repeat := false
			for _, dbi := range res.dbis {
				if dbi.readError == gDbiUtilErrorSkipped ||
					dbi.writeError == gDbiUtilErrorSkipped {
					continue
				}
				if (dbi.readError != gDbiUtilErrorNone ||
					dbi.writeError != gDbiUtilErrorNone) &&
					!dbi.policy.SkipRollback {
					repeat = true
					break
				}
			}
			if repeat {
				yes := forceYes
				if !yes {
					msg := fmt.Sprintf("\nWARN: detected one or several problems.\n" +
					"      Do you want to repeat the validation with the previous environment snapshot?")
					yes = efsutil.AskForConfirmation(msg)
				} else {
					fmt.Printf("INFO: detected one or several problems. Repeat the check with previos snapshot\n")
				}
				if yes {
					res2, err := env.VerifyStructure(&policies, true, env.role > meta.Plevel)
					if err != nil {
						fmt.Printf("ERROR: previous snapshot validation terminates with error, skipping\n")
					}
					if res2.hasError || res2.hasFatalError {
						fmt.Printf("ERROR: previous snapshot is corrupted as well. Using the most recent one for further processing\n")
					} else {
						yes := forceYes
						if !yes {
							msg := fmt.Sprintf("INFO: the previous snaphot is consistent and can replace the corrupted one.\n" +
							"      The device will be detached (if it's online).\n"+
							"      Do you want to revert the last transaction?")
							yes = efsutil.AskForConfirmation(msg)
						} else {
							fmt.Printf("INFO: the previous snaphot is consistent and will replace the corrupted one\n")
						}
						if yes {
							if onlineStatus != diskStatusOffline && onlineStatus != diskStatusUnavail && newStatus != diskStatusUnavail {
								fmt.Printf("INFO: detaching device %v\n", diskId)
								st, err := diskDetach(diskId)
								if err == nil && st != mStatusOk {
									return fmt.Errorf("couldn't detach disk, server replied with code %v", err)
								} else if err != nil {
									return fmt.Errorf("disk detach error %v", err)
								}
								newStatus = diskStatusUnavail
							}
							err := exec.Command(nedgeHome+"/sbin/dbi_util", "-u", env.path).Run()
							if err == nil {
								fmt.Printf("INFO: the environment on %v has been rolled back\n", env.path)
								env.faults = []RdFaultEntry{}
								env.UpdateInfo()
								continue
							} else {
								fmt.Printf("ERROR: environment rollback error. Continue with current one.\n")
							}
						}
					}
				}
			}
			env.verifyResult = res
			// Show results to user
			err = env.ShowVerificationResults()
			if err != nil {
				return fmt.Errorf("(show verification) %v", err)
			}
			if env.verifyResult.hasFatalError {
				if env.role > 0 {
					yes := forceYes
					if !yes {
						msg := fmt.Sprintf("\nERROR: one or several data tables got unrecoverable damages.\n"+
						"       The environment %v needs to be formatted\n"+
						"       Press `Y` if you want to add it to a format queue", env.path)
						yes = efsutil.AskForConfirmation(msg)
					} else {
						fmt.Printf("ERROR: one or several data tables got unrecoverable damages.\n"+
						"       The environment %v will be formatted\n", env.path)
					}
					if yes {
						format[env.path] = env
					} else {
						fmt.Printf("INFO: healing of environment %v is skipped\n", env.path)
					}
					continue
				} else if hybrid {
					yes := forceYes
					if !yes {
						msg := fmt.Sprintf("ERROR: the mdoffload environment got unrecoverable damages.\n"+
							"       ENTIRE device %v needs to be formatted. All the data will be lost.\n"+
							"       Press `Y` to start", env.path)
						yes = efsutil.AskForConfirmation(msg)
					} else {
						fmt.Printf("ERROR: the mdoffload environment got unrecoverable damages.\n"+
							"       ENTIRE device %v will be FORMATTED\n", env.path)
					}
					if yes {
						for _, env := range envs {
							format[env.path] = env
						}
						break validateLoop
					} else {
						fmt.Printf("INFO: Canceled\n")
						return nil
					}
				}
			} else if env.verifyResult.hasError {
				yes := forceYes
				if !yes {
					msg := fmt.Sprintf("\nINFO: the environment contains one or several corrupted data tables.\n" +
						"      However, those data aren't vital for system and the environment can be recovered.\n" +
						"      The recovery process can take a long while and the device will be unavailbe during second stage of the procedure.\n" +
						"      Do you want to initiate the data recovery right now?")
					yes = efsutil.AskForConfirmation(msg)
				} else {
					fmt.Printf("\nINFO: the environment contains one or several corrupted data tables.\n" +
						"      However, those data aren't vital for system and the environment can be recovered.\n")
				}
				if !yes {
					fmt.Printf("INFO: Recovery of environment %v has been skipped\n", env.path)
					continue
				}
				recovery[env.path] = 1
				err = env.CompactionCopyTo(scratch)
				if err != nil {
					return fmt.Errorf("(recovery stage1) %v", err)
				}
				// Making disk unavailable
				if onlineStatus != diskStatusOffline &&
					onlineStatus != diskStatusUnavail &&
					newStatus != diskStatusUnavail {
					fmt.Printf("INFO: making device %v unavailable\n", diskId)
					st, err := diskDetach(diskId)
					if err == nil && st != mStatusOk {
						return fmt.Errorf("couldn't detach disk, server replied with code %v", err)
					} else if err != nil {
						return fmt.Errorf("disk detach error %v\n", err)
					}
					newStatus = diskStatusUnavail
				}
				err = env.CompactionCopyFrom(scratch)
				if err != nil {
					return fmt.Errorf("(recovery stage2) %v", err)
				}
				env.UpdateInfo()
				fmt.Printf("INFO: the environment has been recovered\n")
			}
			env.faults = []RdFaultEntry{}
			//Finally check freeList size
			maxFreeListSize := uint64(0)
			if policies.FreeListMaxSizeRel > 0 {
				maxFreeListSize = env.info.MapSize * policies.FreeListMaxSizeRel / 100
			} else {
				maxFreeListSize = policies.FreeListMaxSize
			}
			if maxFreeListSize == 0 {
				// Free list check policy skipped
				continue
			}
			if env.info.FreelistSize > maxFreeListSize && env.role <= meta.Plevel {
				yes := forceYes
				if !yes {
					msg := fmt.Sprintf("INFO: the environment got fragmented. FreeList size is %v entries. It may affect the write/delete performance.\n"+
						"      A compaction process is recomended. This can take a long while and device will be unavailbe during second stage of the procedure.\n"+
						"      Do you want to start data compaction right now?", env.info.FreelistSize)
					yes = efsutil.AskForConfirmation(msg)
				} else {
					fmt.Printf("INFO: the environment got fragmented. FreeList size is %v entries."+
						" A compaction process is starting\n", env.info.FreelistSize)
				}
				if !yes {
					fmt.Printf("INFO: environment %v compaction has been skipped\n", env.path)
					continue
				}
			} else {
				if (env.role <= meta.Plevel) {
					fmt.Printf("INFO: environment %v FreeList size is %v entries, compaction isn't required\n",
						env.path, env.info.FreelistSize)
				}
				continue
			}
			compact[env.path] = 1
			fmt.Printf("INFO: copying data from %v to %v\n", env.path, scratch)
			err = env.CompactionCopyTo(scratch)
			if err != nil {
				return fmt.Errorf("(compaction stage1) %v\n", err)
			}
			// Making disk unavailable
			if onlineStatus != diskStatusOffline &&
				onlineStatus != diskStatusUnavail &&
				newStatus != diskStatusUnavail{
				fmt.Printf("INFO: making device %v unavailable\n", diskId)
				st, err := diskDetach(diskId)
				if err == nil && st != mStatusOk {
					return fmt.Errorf("(set unavailable) server replied with code %v/%v", err, st)
				} else if err != nil {
					return fmt.Errorf("disk detach error %v", err)
				}
				newStatus = diskStatusUnavail
			}
			fmt.Printf("INFO: restoring data from %v\n", scratch)
			err = env.CompactionCopyFrom(scratch)
			if err != nil {
				return fmt.Errorf("(compaction stage2) %v", err)
			}
			env.UpdateInfo()
		} // End of a super big validation loop
	}
Format:
	if len(format) > 0 || formatDevice {
		if newStatus != diskStatusOffline &&
			onlineStatus != diskStatusUnavail &&
			newStatus != diskStatusUnavail {
				yes := forceYes
				if !yes {
					msg := fmt.Sprintf("\nWARN: one or several enironments need to be formatted.\n"+
						"      The device has to be detached from server. Do you want to proceed?")
					yes = efsutil.AskForConfirmation(msg)
				} else {
					fmt.Printf("\nWARN: one or several enironments need to be formatted. The device will be detached\n")
				}
				if !yes {
					fmt.Printf("INFO: Operation canceled\n")
					return nil
				}
				res,err := diskDetach(diskId)
				if err == nil && res != mStatusOk {
					return fmt.Errorf("couldn't detach disk, server replied with code %v", res)
				} else if err != nil {
					return fmt.Errorf("disk detach error %v", err)
				}
				newStatus = diskStatusUnavail
		}
		// New enviromnets could be add to the format map after validation
		if !formatDevice {
			plevelsToFormat := 0
			// If need to format all plevels except mdoffload,
			// then whole disk format is required
			for _,env := range (format) {
				if env.role > 0 && env.role <= meta.Plevel {
					plevelsToFormat++
				}
			}
			formatDevice = len(format) == len(envs)
			if !formatDevice && plevelsToFormat == meta.Plevel {
				fmt.Printf("\nWARN: all main environments are damaged. Whole device format is suggested\n.")
				formatDevice = true
			}
		}
		if formatDevice {
			yes := forceYes
			if !yes {
				msg := fmt.Sprintf("\nWARN: the entire device is about to be formatted.\n"+
					"      ALL the data on it will be LOST. Do you want to proceed?")
				yes = efsutil.AskForConfirmation(msg)
			} else {
				 fmt.Printf("\nWARN: the entire device will be FORMATTED.\n"+
					"      ALL the data on it will be LOST\n")
			}
			if !yes {
				fmt.Print("INFO: Operation canceled\n")
				return nil
			}

			// Whole disk format. Already confirmed
			fmt.Printf("INFO: formatting entire device %v\n", diskId)
			err := exec.Command(nedgeHome+"/sbin/nezap", "--do-as-i-say","--disk", diskId).Run()
			if err != nil {
				return fmt.Errorf("nezap returned error %v", err)
			}
			for _, e := range envs {
				e.faults = []RdFaultEntry{}
			}
			fmt.Printf("INFO: format done\n")
		} else {
			for _, e := range format {
				// plevel format
				if e.role <= meta.Plevel {
					fmt.Printf("INFO: formatting plevel%v (%v)\n", e.role, e.path)
					e.Format()
					postCmd := fmt.Sprintf("mdofDropOutdated%d", e.role)
					e.AppendPostCommand(postCmd)
					e.faults = []RdFaultEntry{}
				} else {
					// WAL format
					fmt.Printf("INFO: formatting WAL%v (%v)\n", e.role - meta.Plevel, e.path)
					e.Format()
					e.faults = []RdFaultEntry{}
				}
			}
			fmt.Printf("INFO: format done\n")
		}
	}
	// Finalize changes by updating the metaloc record
	meta.Faults = []string{}
	prevState := meta.State
	meta.State = rdstateOk
	// Updating fault status
	for _, env := range envs {
		// If environment recovery was skipped, we need to restore its fault entries
		if len(env.faults) > 0 {
			for _, fault := range env.faults {
				meta.Faults = append(meta.Faults, fault.String())
				meta.State = prevState
				if prevState == rdstateOk {
					panic("prevState != rdstateOk")
				}
			}
		}
	}
	// Updating post-process commands
	mtcmds := make(map[string]int)
	// Taking old (unprocessed)
	for _, cmd := range meta.MaintenanceCmd {
		mtcmds[cmd] = 1
	}
	// Append new
	for _, env := range envs {
		for cmd, _ := range env.actions {
			mtcmds[cmd] = 1
		}
	}
	// Form a list
	meta.MaintenanceCmd = []string{}
	for cmd, _ := range mtcmds {
		meta.MaintenanceCmd = append(meta.MaintenanceCmd, cmd)
		meta.State = rdstateMaintenance
	}
	meta.Retries = 0
	meta.Pid = 0
	err = WriteMetaloc(kpath, &meta)
	if err != nil {
		return fmt.Errorf("(metaloc store on exit) %v", err)
	}
	return nil
}


var (
	diskCheck = &cobra.Command{
		Use:   "check [options] <disk-ID>",
		Short: "Check/heal a device",
		Long:  "\nAn interractive tool for data integrity validation, device recovery and format",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Println("Usage: efscli deivce check [options] <diskID>")
				os.Exit(1)
			}

			srcPath := args[0]
			srcKpath, err := diskPathById(srcPath)
			if err != nil {
				fmt.Printf("Couldn't find device name for disk %v: %v\n", srcPath, err)
				os.Exit(1)
			}

			if showMetaInfo {
				meta, err := ReadMetaloc(srcKpath)
				if err != nil {
					fmt.Printf("ERROR: (read metaloc) %v,\n", err)
					os.Exit(1)
				}
				err = showMetalocInfo(&meta)
				if err != nil {
					fmt.Println("ERROR:", err)
					os.Exit(1)
				}
			} else if len(compactifyPartitionFlag) > 0 {
				partID, _, err := partPathFromArgs(srcPath, compactifyPartitionFlag)
				if err != nil {
					fmt.Println("ERROR:", err)
					os.Exit(1)
				}
				// Looking for scratch area
				scratch, err := getScratchAreaPath()
				if err != nil {
					fmt.Println("ERROR:", err)
					os.Exit(1)
				}
				// Make sure the source environment isn't attached
				status, err := diskStatus(srcPath)
				if err == nil && (status != diskStatusRoForced ||
					status != diskStatusUnavail ||
					status != diskStatusNotFound ||
					status != diskStatusRoFault) {
					fmt.Printf("ERROR: the device %v is in use\n", srcPath)
					os.Exit(1)
				}
				if !accept_all {
					msg := fmt.Sprintf("WARNING: You are about to start compaction.\n" +
						" This operation will DESTROY all the data on the scratch area.\n" +
						" Do you want to continue?")
					c := efsutil.AskForConfirmation(msg)
					if !c {
						fmt.Println("INFO: Operation canceled")
						os.Exit(1)
					}
				}
				// Opening the source env
				srcEnv, err := NewLMDBEnv(partID)
				if err != nil {
					fmt.Printf("ERROR: on source env open: %v\n", err)
					os.Exit(1)
				}
				if !srcEnv.isValid {
					fmt.Printf("ERROR: the environment not found at %v\n", srcPath)
					os.Exit(1)
				}
				// Opening the scratch env
				tgtEnv, err := NewLMDBEnv(scratch)
				if err != nil {
					fmt.Printf("ERROR: on scratch env open: %v\n", err)
					os.Exit(1)
				}
				tgtCap, err := tgtEnv.Capacity()
				if err != nil {
					fmt.Printf("ERROR: internal env.Capacity() err %v\n", err)
					os.Exit(1)
				}
				// Make sure the scratch can fit the source env content
				if srcEnv.info.Used() > tgtCap {
					fmt.Printf("The scratch area's free size %v less than source environment size %v\n",
						toCapacityStr(tgtCap), toCapacityStr(srcEnv.info.Capacity()))
					os.Exit(1)
				}
				fmt.Printf("INFO: source env size %v, %v available on scratch area\n",
					toCapacityStr(srcEnv.info.Used()), toCapacityStr(tgtCap))
				tgtEnv.Format()
				fmt.Printf("INFO: making a compact copy %v -> %v\n", srcEnv.path, tgtEnv.path)
				for _, dbi := range srcEnv.info.Dbis {
					err = srcEnv.DBICopy(&tgtEnv, dbi.Name)
					if err != nil {
						fmt.Printf("ERROR: DBI %v source to scratch copy error. Reason: %v\n",
							dbi.Name, err)
						os.Exit(1)
					}
				}
				fmt.Println("INFO: restoring source environment")
				// Remove previous enviroment content
				srcEnv.Format()
				// Temporary block SIGINT/SIGTERM
				// Otherwise the source environment WILL BE corrupted
				var sigChannel = make(chan os.Signal)
				signal.Notify(sigChannel, syscall.SIGTERM)
				signal.Notify(sigChannel, syscall.SIGINT)
				go func() {
					for _, ok := <-sigChannel; ok; _, ok = <-sigChannel {
						fmt.Println("Compaction is in progress. Do NOT try interrupt it!")
					}
				}()
				// Restoring
				err = tgtEnv.Copy(&srcEnv, true)
				signal.Stop(sigChannel)
				close(sigChannel)
				// Cleaning scratch partition
				tgtEnv.Format()
				if err != nil {
					fmt.Printf("Scratch to source copy error: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("Compaction done")
			} else if len(validatePart) > 0 {
				srcPartId, wal, err := partPathFromArgs(srcPath, validatePart)
				if err != nil {
					fmt.Println("ERROR:", err)
					os.Exit(1)
				}
				ppath := policyPath
				if len(ppath) == 0 {
					ppath = nedgeHome + defaultCheckPolicyPath
				}
				policies, err := loadCheckPolicies(ppath)
				if err != nil {
					if _, ok := err.(*os.PathError); ok {
						if len(policyPath) > 0 {
							fmt.Printf("ERROR: Couldn't find specified policy file %v\n", policyPath)
							os.Exit(1)
						}
						fmt.Printf("WARN:Couldn't find default policies config at %v, creating default\n",
							nedgeHome+defaultCheckPolicyPath)
						policies = defaultCheckPolicies
						saveCheckPolicies(nedgeHome+defaultCheckPolicyPath, &policies)
					} else {
						fmt.Println("ERROR: (policy parse)", err)
						os.Exit(1)
					}
				}
				env, err := NewLMDBEnv(srcPartId)
				if err != nil {
					fmt.Println("ERROR:", err)
					os.Exit(1)
				}
				res, err := env.VerifyStructure(&policies, false, wal)
				if err != nil {
					fmt.Println("ERROR: (verify)", err)
					os.Exit(1)
				}
				env.verifyResult = res
				err = env.ShowVerificationResults()
				if err != nil {
					fmt.Println("ERROR: (show verification)", err)
					os.Exit(1)
				}
			} else {
				// The device heal procedure starts here
				// Looking for scratch area
				scratchPath, err := getScratchAreaPath()
				if err != nil {
					fmt.Println("ERROR: (scratch path lookup) ", err)
					os.Exit(1)
				}
				err = deviceHeal(srcPath, scratchPath)
				if err != nil {
					fmt.Printf("ERROR: %v\n", err)
					os.Exit(1)
				}
			}
		},
	}
	showMetaInfo            = false
	compactifyPartitionFlag = ""
	scratchArea             = ""
	validatePart            = ""
	policyPath              = ""
)

func init() {
	if IsRTRD {
		DeviceCommand.AddCommand(diskCheck)
		diskCheck.Flags().BoolVarP(&showMetaInfo, "meta", "m", false, "Show device's metaloc information")
		diskCheck.Flags().StringVarP(&scratchArea, "scratch", "s", "", "Scratch area path")
		diskCheck.Flags().StringVarP(&validatePart, "validate", "v", "", "Validate single device part")
		diskCheck.Flags().StringVarP(&policyPath, "policypath", "p", "", "A path to check policy file location")
		diskCheck.Flags().BoolVarP(&accept_all, "yes", "y", false, "Answer `Y` to all questions")
		diskCheck.Flags().StringVarP(&compactifyPartitionFlag, "compact", "c", "", "Compactify a partition of a device")
	}
}
