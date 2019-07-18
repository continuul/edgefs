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
package user

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

func UserCreate(tpath string, username string, password string, opt string, authkey string, secret string) error {
	s := strings.Split(tpath, "/")

	admin := 0

	if strings.HasPrefix(opt, "admin") {
		admin = 1
	}

	// generate ?
	if len(authkey) == 0 {
		authkey = strings.ToUpper(efsutil.RandomString(20))
	}
	if len(secret) == 0 {
		secret = efsutil.RandomString(40)
	}
	user := efsutil.CreateUser(s[0], s[1], username, password, "object", "nedge", authkey, secret, admin)

	if user == nil {
		return fmt.Errorf("Create user error")
	}

	err := efsutil.SaveUser(s[0], s[1], user)
	if err != nil {
		return err
	}

	efsutil.PrintUser(user)
	return nil
}

var (
	secretFile string

	createCmd = &cobra.Command{
		Use:   "create <cluster>/<tenant> <username> <password> [admin|cloud] [authkey] [secret] [-f secretFile]",
		Short: "create a new user",
		Long:  "create a new user",
		Args:  validate.UserCreate,
		Run: func(cmd *cobra.Command, args []string) {
			opt := ""
			n := 3
			if len(args) > n &&
			   (strings.Compare(args[n], "admin") == 0 ||
			    strings.Compare(args[n], "cloud") == 0) {
				opt = args[n]
				n++
			}
			authkey := ""
			if len(args) > n {
				authkey = args[n]
				n++
			}
			secret := ""
			if len(args) > n {
				secret = args[n]
				n++
			} else if secretFile != "" {
				b, err := ioutil.ReadFile(secretFile)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				secret = string(b)
			}
			err := UserCreate(args[0], args[1], args[2], opt, authkey, secret)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	createCmd.Flags().StringVarP(&secretFile, "secretFile", "f", "", "Provide cloud secret as a file")
	UserCmd.AddCommand(createCmd)
}
