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
/*	IPv6 multicast example - ipv6_multicast_send.c
	2012 - Bjorn Lindgren <nr@c64.org>
	https://github.com/bjornl/ipv6_multicast_example
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
	struct sockaddr_in6 saddr;
	struct ipv6_mreq mreq;
	char buf[140000];
	struct msghdr smsghdr;
	struct iovec iov[2];
	ssize_t len = 1;
	int sd, fd, on = 1, hops = 255, ifidx;

	if (argc < 4) {
		printf("\nUsage: %s <address> <port> <netif>\n\nExample: %s ff02::5:6 12345 eth1\n\n", argv[0], argv[0]);
		return 1;
	}

	ifidx = if_nametoindex(argv[3]);
	printf("ifidx=%d\n", ifidx);

	sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops))) {
		perror("setsockopt");
		return 1;
	}

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on))) {
		perror("setsockopt");
		return 1;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_in6));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(atoi(argv[2]));
	inet_pton(AF_INET6, argv[1], &saddr.sin6_addr);

	memcpy(&mreq.ipv6mr_multiaddr, &saddr.sin6_addr, sizeof(mreq.ipv6mr_multiaddr));
	mreq.ipv6mr_interface = ifidx;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &mreq, sizeof(mreq))) {
		perror("setsockopt");
		return 1;
	}

//	memset(&smsghdr, 0, sizeof(smsghdr));
//	smsghdr.msg_name = (caddr_t)&saddr;
//	smsghdr.msg_namelen = sizeof(saddr);
//	memset(&iov, 0, sizeof(iov));
//	iov[0].iov_base = (caddr_t)buf;
//	iov[0].iov_len = 70000;
//	smsghdr.msg_iov = iov;
//	smsghdr.msg_iovlen = 1;
//	len = sendmsg(sd, &smsghdr, 0);
//	printf("sent=%ld\n", len);

	fd = open("/dev/stdin", O_RDONLY, NULL);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	while (len) {
		len = read(fd, buf, 1400);
		/* printf("read %zd bytes from fd\n", len); */
		if (!len) {
			break;
		} else if (len < 0) {
			perror("read");
			return 1;
		} else {
			len = sendto(sd, buf, len, 0, (const struct sockaddr *) &saddr, sizeof(saddr));
			/* printf("sent %zd bytes to sd\n", len); */
			usleep(10000); /* rate limit, 10000 = 135 kilobyte/s */
		}
	}

	close(sd);
	close(fd);

	return 0;
}
