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
	"strings"

	"../efsutil"
	"../validate"
	"github.com/spf13/cobra"
)

func UserDelete(tpath string, username string) error {
	s := strings.Split(tpath, "/")

	user, err := efsutil.LoadUser(s[0], s[1], efsutil.UserKey(username))
	if err != nil {
		return err
	}

	err = efsutil.DeleteUser(s[0], s[1], user)
	if err != nil {
		return err
	}

	fmt.Printf("Deleted user: %s\n\n", username)
	return nil
}

var (
	deleteCmd = &cobra.Command{
		Use:   "delete <cluster>/<tenant> <username>",
		Short: "delete an existing user",
		Long:  "delete an existing user",
		Args:  validate.UserDelete,
		Run: func(cmd *cobra.Command, args []string) {
			err := UserDelete(args[0], args[1])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	UserCmd.AddCommand(deleteCmd)
}
