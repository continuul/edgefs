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

import (
	"fmt"
	"net"
	"time"
)

const (
	dnsLookupCount = 5
	dnsRetryTimeout = 10
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func IsPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func LookupDNS(dnsname string) (string, error) {

	for i:=0; i < dnsLookupCount; i++ {
		ips, err := net.LookupIP(dnsname)
		if err == nil {
			for _, ip := range ips {
	                        if ip.To4() != nil {
	                                return ip.String(), nil
		                }
			}
		}

		fmt.Printf("DNS lookup retry %d failed for %s. waiting for next DNS lookup in %d seconds\n", i, dnsname, dnsRetryTimeout)
		time.Sleep(dnsRetryTimeout * time.Second)
	}

	return "", fmt.Errorf("Could't get ip by lookup %s. All retries failed", dnsname)
}

func GetIPv4Address(interfaceName string) (string, error) {

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		fmt.Printf("Could't find interface by name %s, %v\n", interfaceName, err)
		return "", err
	}

	//get iface ips
	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Printf("Can't get addresses by interface: %s %v\n", iface.Name, err)
		return "", err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}

		if !ip.IsLoopback() && (ip.To4() != nil) {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("Could't find any available IPv4 for interface %s", interfaceName)
}
