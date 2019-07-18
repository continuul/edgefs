/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#define IPV6_BINARY_LEN 128

int32_t set_ip_addr(const char *dev, const char *ip, int32_t prefix_len);

int main(int argc, char *argv[])
{
	struct sockaddr_in6 sa;
	int32_t size;
	int32_t sd;
	int32_t ret;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <dev> <ip address> <prefix Length>.\n",
			argv[0]);
		goto out1;
	}

	ret = set_ip_addr(argv[1], argv[2], atoi(argv[3]));
	if (ret == -1) {
		fprintf(stderr, "Unable to set IP address.\n");
		goto out1;
	}

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd == -1) {
		perror("socket");
		goto out1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(49153);
	sa.sin6_scope_id = 0;
	ret = inet_pton(AF_INET6, argv[2], sa.sin6_addr.s6_addr);
	if (ret != 1) {
		perror("inet_pton");
		goto out2;
	}

	ret = bind(sd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret == -1) {
		perror("bind");
		goto out2;
	}

	printf("Bind success!\n");

	close(sd);

	exit(0);
out2:
	close(sd);
out1:
	exit(1);
}

struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t        ifr6_prefixlen;
	int32_t         ifr6_ifindex;
};

int32_t set_ip_addr(const char *dev, const char *ip, int32_t prefix_len)
{
	struct in6_ifreq in6_ifreq;
	struct ifreq ifreq;
	uint8_t ip_bin[IPV6_BINARY_LEN];
	int32_t sd;
	int32_t ret;

	if ((dev == NULL) || (ip == NULL) || (prefix_len < 0)) {
		fprintf(stderr, "%s: Invalid arguments.\n", __func__);
		goto out1;
	}

	ret = inet_pton(AF_INET6, ip, ip_bin);
	if (ret != 1) {
		perror("inet_pton");
		goto out1;
	}

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd == -1) {
		perror("socket");
		goto out1;
	}

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, dev, IFNAMSIZ - 1);
	ret = ioctl(sd, SIOCGIFINDEX, &ifreq);
	if (ret == -1) {
		perror("ioctl");
		goto out2;
	}

	memset(&in6_ifreq, 0, sizeof(in6_ifreq));
	ret = inet_pton(AF_INET6, ip, &in6_ifreq.ifr6_addr.s6_addr);
	if (ret != 1) {
		perror("inet_pton");
		goto out2;
	}

	in6_ifreq.ifr6_ifindex = ifreq.ifr_ifindex;
	in6_ifreq.ifr6_prefixlen = prefix_len;

	ret = ioctl(sd, SIOCSIFADDR, &in6_ifreq);
	if (ret == -1) {
		perror("ioctl");
		goto out2;
	}

	close(sd);

	return 0;
out2:
	close(sd);
out1:
	return -1;
}
