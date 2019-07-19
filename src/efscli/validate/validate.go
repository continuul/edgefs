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
package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Nexenta/edgefs/src/efscli/efsutil"

	"github.com/spf13/cobra"
)

func Flag(flag *efsutil.FlagValue) error {
	if strings.Compare(flag.Value, "") == 0 {
		return nil
	}

	r, _ := regexp.Compile("^" + flag.Reg + "$")
	if r.MatchString(flag.Value) {
		return nil
	}
	return fmt.Errorf("Flag '%s'(%s) - invalid value specified: %s", flag.Desc, flag.Name, flag.Value)
}

func Flags(flags []efsutil.FlagValue) error {
	for i := 0; i < len(flags); i++ {
		e := Flag(&flags[i])
		if e != nil {
			return e
		}
	}
	return nil
}

func Cluster(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires cluster name")
	}
	r, _ := regexp.Compile("^[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid cluster specified: %s", args[0])
}

func ServiceCreate(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return errors.New("Requires service <type> <name>")
	}
	stype := args[0]
	name := args[1]

	t, _ := regexp.Compile("^nfs$|^s3$|^s3x$|^iscsi$|^isgw|^swift$")
	if !t.MatchString(stype) {
		return fmt.Errorf("Invalid service type specified: %s", stype)
	}

	r, _ := regexp.Compile("^[^/ ]+$")
	if r.MatchString(name) {
		return nil
	}
	return fmt.Errorf("Invalid service name specified: %s", name)
}

func Service(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires <service name>")
	}
	name := args[0]
	r, _ := regexp.Compile("^[^/ ]+$")
	if r.MatchString(name) {
		return nil
	}
	return fmt.Errorf("Invalid service name specified: %s", name)
}

func ServiceConfig(cmd *cobra.Command, args []string) error {
	if len(args) < 3 {
		return errors.New("Requires <service name> <key> <value>")
	}
	ret := Service(cmd, args)
	if ret != nil {
		return ret
	}
	key := args[1]
	r, _ := regexp.Compile("^X-.+$")
	if r.MatchString(key) {
		return nil
	}
	return fmt.Errorf("Invalid parameter name specified: %s", key)
}

func Tenant(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires <cluster>/<tenant>")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid tenant specified: %s, please provide <cluster>/<tenant>", args[0])
}

func Bucket(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires bucket name")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid bucket specified: %s", args[0])
}

func Serve(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return errors.New("Requires <service> <path>")
	}
	ret := Service(cmd, args)
	if ret != nil {
		return ret
	}
	return nil
}

func Object(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires object name")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+/.+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid object specified: %s ", args[0])
}

func ObjectPutGet(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return errors.New("Requires <object name> <file name>")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+/.+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid object specified: %s ", args[0])
}

func ObjectClone(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return errors.New("Requires <src object name> <dst object name>")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+/.+$")
	if !r.MatchString(args[0]) {
		return fmt.Errorf("Invalid source object specified: %s ", args[0])
	}
	if !r.MatchString(args[1]) {
		return fmt.Errorf("Invalid destination object specified: %s ", args[1])
	}
	return nil
}


func ObjectGet(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errors.New("Requires <object name> [<file name>]")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+/.+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid object specified: %s ", args[0])
}

func ObjectOnDemand(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("Requires <object name>")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+/[^/ ]+/.+$")
	if !r.MatchString(args[0]) {
		return fmt.Errorf("Invalid object specified: %s ", args[0])
	}
	return nil
}

func UserCreate(cmd *cobra.Command, args []string) error {
	if len(args) < 3 {
		return errors.New("Requires <cluster>/<tenant> username password [admin|cloud]")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid tenant specified: %s, please provide <cluster>/<tenant> username password [admin|cloud]",
		args[0])
}

func UserShow(cmd *cobra.Command, args []string) error {
	if len(args) < 3 {
		return errors.New("Requires <cluster>/<tenant> username password")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid tenant specified: %s, please provide <cluster>/<tenant> username password",
		args[0])
}

func UserDelete(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return errors.New("Requires <cluster>/<tenant> username")
	}
	r, _ := regexp.Compile("^[^/ ]+/[^/ ]+$")
	if r.MatchString(args[0]) {
		return nil
	}
	return fmt.Errorf("Invalid tenant specified: %s, please provide <cluster>/<tenant> username",
		args[0])
}

func ServiceIscsiOpts(opath, opts string) error {
	s := strings.Split(opath, "/")
	if len(s) < 4 {
		return errors.New("Requires <service> <cluster>/<tenant>/<bucket>/<object>")
	}

	if opts == "" {
		return nil
	}

	for _, p := range strings.Split(opts, ",") {
		s := strings.Split(p, "=")
		if len(s) != 2 {
			return fmt.Errorf("Wrong iSCSI option format %s, expecting coma separated string", p)
		}
		if s[0] != "X-volsize" &&
			s[0] != "X-blocksize" &&
			s[0] != "ccow-chunkmap-chunk-size" {
			return fmt.Errorf("Unknown iSCSI option %s", s[0])
		}
	}
	return nil
}
