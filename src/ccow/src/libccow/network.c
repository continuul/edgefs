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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <uv.h>

#include "ccowutil.h"
#include "ccow-impl.h"
#include "network.h"
#include "server-list.h"

/*
 * Parse network section in supplied configuration
 */
static int
ccow_network_parse_config(struct ccow *tc, struct ccow_network *netobj)
{
	int err;
	size_t i;
	json_value *opts = tc->opts;

	/* syntax error */
	if (opts->type != json_object) {
		log_error(lg, "Syntax error: not an object: -EINVAL");
		return -EINVAL;
	}

	json_value *network = NULL;
	for (i = 0; i < opts->u.object.length; i++) {
		if (strncmp(opts->u.object.values[i].name, "network", 7) == 0) {
			network = opts->u.object.values[i].value;
			break;
		}
	}

	/* network section not found? */
	if (!network) {
		log_error(lg, "Config error: networking address is not "
		    "specified: -EINVAL");
		return -EINVAL;
	}

	/* syntax error */
	if (network->type != json_object) {
		log_error(lg, "Syntax error: network section not an object"
		    ": -EINVAL");
		return -EINVAL;
	}

	char *server_ip4addr = NULL;
	char *server_ip6addr = NULL;
	char *broker_ip4addr = NULL;
	char *broker_interfaces = NULL;
	char *unix_socket = NULL;
	int server_port = CCOW_NETWORK_PORT;
	int broker_port = CCOW_BROKER_PORT;
	int mc_ttl = CCOW_NETWORK_MC_TTL;

	size_t j;
	for (j = 0; j < network->u.object.length; j++) {
		char *namekey = network->u.object.values[j].name;
		json_value *v = network->u.object.values[j].value;

		/* broker_port */
		if (strncmp(namekey, "broker_port", 11) == 0) {
			if (v->type != json_integer) {
				err = -EINVAL;
				log_error(lg,
					"Syntax error: broker_port is not an "
					"integer: %d", err);
				return err;
			}
			broker_port = v->u.integer;
		/* broker_ip4addr (optional) */
		} else if (strncmp(namekey, "broker_ip4addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: broker_ip4addr is"
						"not a string: %d", err);
				return err;
			}
			broker_ip4addr = v->u.string.ptr;
			/* server_port */
		/* broker_interfaces */
		} else if (strncmp(namekey, "broker_interfaces", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: broker_interfaces "
				    "is not a string: %d", err);
				return err;
			}
			broker_interfaces = v->u.string.ptr;
		/* server_unix_socket */
		} else if (strncmp(namekey, "server_unix_socket", 18) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_unix_socket is "
				    "not a string: %d", err);
				return err;
			}
			unix_socket = v->u.string.ptr;
		/* server_ip6addr */
		} else if (strncmp(namekey, "server_ip6addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_ip6addr is "
				    "not a string: %d", err);
				return err;
			}
			server_ip6addr = v->u.string.ptr;
		/* server_ip4addr (optional) */
		} else if (strncmp(namekey, "server_ip4addr", 14) == 0) {
			if (v->type != json_string) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_ip4addr is"
						"not a string: %d", err);
				return err;
			}
			server_ip4addr = v->u.string.ptr;
			/* server_port */
		/* server_port */
		} else if (strncmp(namekey, "server_port", 11) == 0) {
			if (v->type != json_integer) {
				err = -EINVAL;
				log_error(lg, "Syntax error: server_port is "
				    "not an integer: %d", err);
				return err;
			}
			server_port = v->u.integer;
		/* multicast ttl */
		} else if (strncmp(namekey, "mc_ttl", 6) == 0) {
			if (v->type != json_integer) {
				log_error(lg,
					"Syntax error: port is not an integer"
					": -EINVAL");
				return -EINVAL;
			}
			mc_ttl = v->u.integer;
		}
	}

	if (broker_ip4addr && !tc->unicastio) {
		err = -EINVAL;
		log_error(lg, "broker_ip4addr specified while unicastio is "
		    "set to 0(Payload Multicast): %d", err);
		return err;
	}

	if (!broker_interfaces && !broker_ip4addr) {
		err = -EINVAL;
		log_error(lg, "neither broker_interfaces or broker_ip4addr "
		    "parameter specified: %d", err);
		return err;
	}

	if (broker_ip4addr) {
		if (!server_ip4addr) {
			server_ip4addr = "127.0.0.1";
			log_warn(lg, "server_ip4addr parameter not specified. Using 127.0.0.1");
		}

		struct sockaddr_in addr4;
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(server_port);
		if (inet_pton(AF_INET, server_ip4addr, &addr4.sin_addr) != 1) {
			err = -EINVAL;
			log_error(lg, "Incorrect network server_ip4addr/server_port "
					"error: %d", err);
			return err;
		}

		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof (addr));
		replicast_ip4_encap(&addr4, &addr);
		addr.sin6_port = htons(server_port);
		netobj->server_sockaddr = addr;

		static char ifname[IFNAMSIZ];
		err = getifname(broker_ip4addr, ifname);
		if (err) {
			log_error(lg, "Cannot get ifname from ip %s "
					"error: %d", broker_ip4addr, err);
			return err;
		}
		broker_interfaces = ifname;
	} else {
		if (!server_ip6addr) {
			server_ip6addr = "::1";
			log_warn(lg, "server_ip6addr parameter not specified. Using ::1");
		}

		/* check for server_ip6addr/server_port correctness */
		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof (addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(server_port);
		char *zone_idx = strchr(server_ip6addr, '%');
		if (zone_idx) {
			*zone_idx = '\0';
			netobj->server_if_index = if_nametoindex(zone_idx + 1);
			if (netobj->server_if_index == 0) {
				err = -errno;
				log_error(lg, "Incorrect network server_ip6addr interface "
				    "index error: %d", err);
				return err;
			}
		}
		if (inet_pton(AF_INET6, server_ip6addr, &addr.sin6_addr) != 1) {
			err = -EINVAL;
			log_error(lg, "Incorrect network server_ip6addr/server_port "
				"error: %d address: %s", err, server_ip6addr);
			return err;
		}
		netobj->server_sockaddr = uv_ip6_addr(server_ip6addr, server_port);
		netobj->server_sockaddr.sin6_scope_id = netobj->server_if_index;

		if (zone_idx)
			*zone_idx = '%';
	}

	char *sp;
	char *ifname = strtok_r(broker_interfaces, ";", &sp);
	int numup = 0;
	i = 0;

	/* walk through all the interface names and fill in if_indexes[] */
	while (ifname != NULL) {

		/* phase one - convert and check availability */
		netobj->if_indexes[i] = if_nametoindex(ifname);
		if (netobj->if_indexes[i] == 0) {
			err = -errno;
			log_error(lg, "Non existing network broker_interfaces "
			    "value at %lu error: %d", i, err);
			return err;
		}

		/* phase two - verify eligibility */
		uint8_t duplex, link_status;
		int mtu;
		err = ethtool_info(ifname, &netobj->if_speeds[i], &duplex,
		    &link_status, &mtu);
		if (err) {
			err = -errno;
			log_error(lg, "Not eligibile network broker_interfaces "
			    "value at %lu error: %d", i, err);
			return err;
		}
		if (duplex < 1) {
			err = -EBADF;
			log_error(lg, "Interface %s in broker_interfaces "
			    "value at %lu error: Full-Duplex mode is "
			    "required", ifname, i);
			return err;
		}
#if 0
		if (mtu < 9000) {
			err = -EBADF;
			log_error(lg, "Interface %s in broker_interfaces "
			    "value at %lu error: minimally MTU 9000 is "
			    "required", ifname, i);
			return err;
		}

		if (netobj->if_speeds[i] < 9000) {
			log_warn(lg, "Interface %s in broker_interfaces "
			    "has speed %u less then 9000", ifname,
			    netobj->if_speeds[i]);
		}
#endif
		err = find_ipv6local(ifname, netobj->broker_ip6addr[i]);
		if (err) {
			log_error(lg, "Interface %s in broker_interfaces "
			    "value at %lu error: cannot resolve link-local "
			    "IPv6 address", ifname, i);
			return err;
		}

		if (link_status == 0) {
			log_warn(lg, "Interface %s in broker_interfaces "
			    "value at %lu error: Link is down", ifname, i);
			/* proceed as long as there are sufficient number
			 * of interfaces */
		} else {
			log_info(lg, "Using interface %s <%s>, %u Mbps",
			    ifname, netobj->broker_ip6addr[i],
			    netobj->if_speeds[i]);
			numup++;
		}

		ifname = strtok_r(NULL, ";", &sp);
		i++;
	}

	if (numup == 0) {
		err = -ENODEV;
		log_error(lg, "All configured networking interfaces are down: %d",
		    err);
		return err;
	}

	if (i == 0) {
		err = -ENODEV;
		log_error(lg, "No configured networking interfaces found: %d",
		    err);
		return err;
	}
	netobj->if_indexes_count = i;

	netobj->broker_interfaces = broker_interfaces;
	netobj->broker_ip4addr = broker_ip4addr;
	netobj->broker_port = broker_port;
	if (server_ip6addr)
		netobj->server_ip6addr = je_strdup(server_ip6addr);
	if (server_ip4addr)
		netobj->server_ip4addr = je_strdup(server_ip4addr);
	netobj->server_port = server_port;
	netobj->mc_ttl = mc_ttl;
	if (unix_socket)
		netobj->unix_socket_addr = je_strdup(unix_socket);

	return 0;
}

struct ccow_network *
ccow_network_init(struct ccow *tc)
{
	int err;

	struct ccow_network *netobj = je_calloc(1, sizeof (*netobj));
	if (!netobj) {
		log_error(lg, "network: out of memory: -ENOMEM");
		return NULL;
	}
	netobj->tc = tc;

	err = ccow_network_parse_config(tc, netobj);
	if (err) {
		je_free(netobj);
		return NULL;
	}

	/*
	 * Initialize TCP/UDP channel
	 */
	ccow_glock();
	netobj->robj[0] = replicast_init("client-0", tc->loop,
	    netobj->broker_ip4addr ? netobj->broker_ip4addr : netobj->broker_ip6addr[0],
	    netobj->broker_port, netobj->unix_socket_addr,
	    netobj->broker_ip4addr ? netobj->broker_ip4addr : netobj->broker_ip6addr[0],
	    netobj->broker_ip4addr ? netobj->broker_ip4addr : "::", CCOW_TRCV_MCBASE_PORT,
	    netobj->mc_ttl, tc);
	if (!netobj->robj[0]) {
		ccow_gunlock();
		je_free(netobj->server_ip6addr);
		je_free(netobj->server_ip4addr);
		je_free(netobj);
		return NULL;
	}
	ccow_gunlock();
	replicast_vbuf_init(&netobj->robj[0]->rvbuf, netobj->if_speeds[0]);
	netobj->robj[0]->client_ctx = tc;
	netobj->robj[0]->loop_thrid = tc->loop_thrid;
	replicast_state_init(netobj->robj[0], RT_SERVER_LIST_GET,
	    server_list_async_fetch);
	replicast_state_init(netobj->robj[0], RT_CLIENT_NOTIFICATION,
			     client_notification_init);

	if (!tc->unicastio) {
		/*
		 * Assign actual MC recv address and port
		 */
		err = ccow_tenant_assign_mcbase(tc, CCOW_TRCV_MCBASE_ADDR,
						netobj->robj[0]->mc_recv_port);
		if (err) {
			log_error(lg, "Unable to assign tenant receive "
				      "multicast group");
			replicast_destroy(netobj->robj[0]);
			replicast_finish_destroy(netobj->robj[0]);
			je_free(netobj->server_ip6addr);
			je_free(netobj->server_ip4addr);
			je_free(netobj);
			return NULL;
		}

		/*
		 * Join the MC group to receive tenant gets
		 */
		err = ccow_tenant_join_rcvaddr(netobj->robj[0], tc,
							netobj->if_indexes[0]);
		if (err) {
			log_error(lg, "Unable to join tenant receive "
				      "multicast group");
			replicast_destroy(netobj->robj[0]);
			replicast_finish_destroy(netobj->robj[0]);
			je_free(netobj->server_ip6addr);
			je_free(netobj->server_ip4addr);
			je_free(netobj);
			return NULL;
		}
	} else {
		if (tc->unicastio == REPLICAST_UNICAST_UDP ||
		    tc->unicastio == REPLICAST_UNICAST_UDP_MCPROXY) {
			memcpy(&tc->tenant_recvaddr,
			       &netobj->robj[0]->msg_origin_udpaddr,
			       sizeof (struct sockaddr_in6));
			tc->tenant_recvport = netobj->robj[0]->udp_recv_port;
		} else {
			memcpy(&tc->tenant_recvaddr,
			       &netobj->robj[0]->msg_origin_tcpaddr,
			       sizeof (struct sockaddr_in6));
			tc->tenant_recvport = netobj->robj[0]->tcp_recv_port;
		}
	}

	return netobj;
}

void
ccow_network_destroy(struct ccow_network *netobj)
{
	struct ccow *tc = netobj->tc;

	if (tc->rcv_joined) {
		ccow_tenant_leave_rcvaddr(tc);
	}
	replicast_destroy(netobj->robj[0]);
}

void
ccow_network_finish_destroy(struct ccow_network *netobj)
{
	replicast_finish_destroy(netobj->robj[0]);
	je_free(netobj->server_ip6addr);
	je_free(netobj->server_ip4addr);
	if (netobj->unix_socket_addr)
		je_free(netobj->unix_socket_addr);
	netobj->tc->netobj = NULL;
	je_free(netobj);
}

uint64_t
lost_response_delay_ms(struct ccow_network *netobj) {
	if (!netobj || !netobj->robj || !netobj->robj[0])
		return 0;
	uint64_t last_recv_time = *(volatile uint64_t *)&netobj->robj[0]->stats.last_receive_time;
	uint64_t last_send_time = *(volatile uint64_t *)&netobj->robj[0]->stats.last_send_time;
	if (!last_recv_time || !last_send_time)
		return 0;
	if (last_recv_time > last_send_time)
		return 0;
	return (last_send_time - last_recv_time)/1000;
}
