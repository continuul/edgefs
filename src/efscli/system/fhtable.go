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
#include "ccow.h"
#include "nanomsg/nn.h"
#include "nanomsg/reqrep.h"
*/
import "C"

import (
	"github.com/Nexenta/edgefs/src/efscli/efsutil"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func PrintFHTable(json_fmt bool) error {
	j, err := efsutil.GetFlexhashJson()
	if err != nil {
		return err
	}
	if err != nil {
		fmt.Print(err)
		return err
	}
	if json_fmt {
		fmt.Println(string(j))
		return nil
	}
	var v interface{}
	err = json.Unmarshal(j, &v)
	if err != nil {
		return err
	}
	data := v.(map[string]interface{})
	for k, v := range data {
		switch v := v.(type) {
		case float64:
			fmt.Println(k, uint64(v))
		}
	}
	return nil
}

// 0 - CPSET (init case, genid)
// 1 - CPUPD SIGUSR1 (refresh)
// 2 - CPUPD SIGUSR2 (new set)
func SystemCPSet(mode int, skipConfirm bool) error {

	if !skipConfirm {
		msg := "Do you really want to change cluster wide checkpoint at this time?"
		if mode == 0 {
			msg = "Please confirm initial configuration?"
		}
		c := efsutil.AskForConfirmation(msg)
		if !c {
			return fmt.Errorf("Operation canceled")
		}
	}

	var msg string
	genid := uint64(0)
	if mode == 0 {
		j, err := efsutil.GetFlexhashJson()
		if err != nil {
			return err
		}
		var v interface{}
		err = json.Unmarshal(j, &v)
		if err != nil {
			return err
		}
		data := v.(map[string]interface{})
		for k, v := range data {
			switch v := v.(type) {
			case float64:
				if k == "genid" {
					genid = uint64(v)
					break
				}
			}
		}

		if genid == 0 {
			return fmt.Errorf("Unable to retrieve current GenID")
		}

		msg = fmt.Sprintf("FH_CPSET.%d", genid)
	} else if mode == 1 {
		msg = "FH_CPUPD.SIGUSR1"
	} else if mode == 2 {
		msg = "FH_CPUPD.SIGUSR2"
	} else {
		return fmt.Errorf("Invalid option")
	}
	ch, err := efsutil.CreateCcowdChannel(10000)
	if err != nil {
		return err
	}
	err = ch.Send(msg)
	if err != nil {
		return err
	}
	fmt.Println("Sent message to daemon:", msg)
	time.Sleep(1 * time.Second)
	ch.Close()
	if mode == 0 {
		fmt.Printf("Successfully set FlexHash table to GenID=%d\n", genid)
	} else if mode == 1 {
		fmt.Printf("Successfully refreshed FlexHash table\n")
	} else if mode == 2 {
		fmt.Printf("Successfully re-generated FlexHash table\n")
	}

	return nil
}

var (
	fhtableCmd = &cobra.Command{
		Use:   "fhtable",
		Short: "FlexHash management",
	}

	printCmd = &cobra.Command{
		Use:   "print",
		Short: "print current FlexHash table",
		Long:  "print current FlexHash table",
		Run: func(cmd *cobra.Command, args []string) {
			err := PrintFHTable(false)
			if err != nil {
				os.Exit(1)
			}
		},
	}

	printJsonCmd = &cobra.Command{
		Use:   "print-json",
		Short: "print current FlexHash table in JSON format",
		Long:  "print current FlexHash table in JSON format",
		Run: func(cmd *cobra.Command, args []string) {
			err := PrintFHTable(true)
			if err != nil {
				os.Exit(1)
			}
		},
	}

	rediscoverCmd = &cobra.Command{
		Use:   "rediscover",
		Short: "rediscover and build new FlexHash table",
		Long:  "rediscover and build new FlexHash table",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemCPSet(2, forceConfirm)
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}
		},
	}

	refreshCmd = &cobra.Command{
		Use:   "refresh",
		Short: "refresh existing running FlexHash table",
		Long:  "refresh existing running FlexHash table",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemCPSet(1, forceConfirm)
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}
		},
	}

	setCmd = &cobra.Command{
		Use:   "set",
		Short: "set current FlexHash as a new checkpoint",
		Long:  "set current FlexHash as a new checkpoint",
		Run: func(cmd *cobra.Command, args []string) {
			err := SystemCPSet(0, forceConfirm)
			if err != nil {
				fmt.Println("ERROR:", err)
				os.Exit(1)
			}

		},
	}

	forceConfirm bool
)

func init() {

	fhtableCmd.AddCommand(printCmd)
	fhtableCmd.AddCommand(printJsonCmd)

	setCmd.Flags().BoolVarP(&forceConfirm, "force-confirm", "f", false, "avoid interactive confirmations")
	fhtableCmd.AddCommand(setCmd)

	refreshCmd.Flags().BoolVarP(&forceConfirm, "force-confirm", "f", false, "avoid interactive confirmations")
	fhtableCmd.AddCommand(refreshCmd)

	rediscoverCmd.Flags().BoolVarP(&forceConfirm, "force-confirm", "f", false, "avoid interactive confirmations")
	fhtableCmd.AddCommand(rediscoverCmd)

	SystemCmd.AddCommand(fhtableCmd)
}
