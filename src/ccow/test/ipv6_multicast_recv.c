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
/*	IPv6 multicast example - ipv6_multicast_recv.c
	2012 - Bjorn Lindgren <nr@c64.org>
	https://github.com/bjornl/ipv6_multicast_example
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
 
int
main(int argc, char *argv[])
{
	struct sockaddr_in6 saddr, maddr;
	struct ipv6_mreq mreq;
	char buf[140000];
	ssize_t len;
	int sd, fd, rc, on = 1, flag = 0, hops = 255, ifidx;
	struct timeval tv;
	fd_set fds;

	if (argc < 4) {
		printf("\nUsage: %s <address> <port> <netif>\n\nExample: %s ff02::5:6 12345 eth1\n\n", argv[0], argv[0]);
		return 1;
	}

	ifidx = if_nametoindex(argv[3]);
	printf("ifidx=%d\n", ifidx);

	sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0) {
		perror("socket");
		return 1;
	}
 
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on))) {
		perror("setsockopt REUSEPORT");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx))) {
		perror("setsockopt MULTICAST_IF");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops))) {
		perror("setsockopt HOPS");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on))) {
		perror("setsockopt LOOP");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on))) {
		perror("setsockopt HOPOPTS");
		return 1;
	}
 
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(atoi(argv[2]));;
	saddr.sin6_scope_id = ifidx;
//	saddr.sin6_addr = in6addr_any;
	inet_pton(AF_INET6, argv[1], &maddr.sin6_addr);
 
	if (bind(sd, (struct sockaddr *) &saddr, sizeof(saddr))) {
		perror("bind");
		return 1;
	}
 
	memset(&maddr, 0, sizeof(maddr));
	inet_pton(AF_INET6, argv[1], &maddr.sin6_addr);

	memcpy(&mreq.ipv6mr_multiaddr, &maddr.sin6_addr, sizeof(mreq.ipv6mr_multiaddr));
	mreq.ipv6mr_interface = ifidx;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &mreq, sizeof(mreq))) {
		perror("setsockopt JOIN_GROUP");
		return 1;
	}

//	len = recv(sd, buf, 140000, 0);
//	printf("len=%ld\n", len);

	FD_ZERO(&fds);
	FD_SET(sd, &fds);
	tv.tv_sec  = 10;
	tv.tv_usec = 0;

	fd = open("/dev/stdout", O_WRONLY, NULL);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	while (1) {
		if (flag) {
			rc = select(sd + 1, &fds, NULL, NULL, &tv);
			if (!rc) {
				break;
			}
			tv.tv_sec  = 10;
			tv.tv_usec = 0;
		}
		len = read(sd, buf, 1400);
		buf[len] = '\0';
		/* printf("Read %zd bytes from sd\n", len); */

		if (!len) {
			break;
		} else if (len < 0) {
			perror("read");
			return 1;
		} else {
			len = write(fd, buf, len);
			/* printf("wrote %zd bytes to fd\n", len); */
			flag++;
		}
	}

	close(sd);
	close(fd);

	return 0;
}
