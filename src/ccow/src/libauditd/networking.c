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
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <nanomsg/pair.h>
#include <nanomsg/reqrep.h>

#include "auditd.h"
#include "ccowd.h"
#include "ccowutil.h"
#include "replicast.h"
#include "hashmap.h"
#include "auditd-impl.h"
#include "logger.h"
#include "networking.h"
#include "conn_handler.h"

/**
 * Default listen backlog size for
 * our TCP listener.
 */
#define BACKLOG_SIZE 64

/**
 * How big should the default connection
 * buffer size be. One page seems reasonable
 * since most requests will not be this large
 */
#define INIT_CONN_BUF_SIZE 32768

/**
 * This is the scale factor we use when
 * we are growing our connection buffers.
 * We want this to be aggressive enough to reduce
 * the number of resizes, but to also avoid wasted
 * space. With this, we will go from:
 * 32K -> 64K -> 128K
 */
#define CONN_BUF_MULTIPLIER 2


/**
 * Represents a simple circular buffer
 */
typedef struct {
    int write_cursor;
    int read_cursor;
    uint32_t buf_size;
    char *buffer;
} circular_buffer;

/**
 * Stores the connection specific data.
 * We initialize one of these per connection
 */
struct conn_info {
    uv_poll_t client;
    circular_buffer input;
    int nn_fd;
};
typedef struct conn_info conn_info;

/**
 * Defines a structure that is
 * used to store the state of the networking
 * stack.
 */
struct statsite_networking {
    statsite_config *config;
    uv_poll_t ipc_client_rcv;
    int ipc_send_sock;
    uv_poll_t tcp_client;
    uv_poll_t udp_client;
    conn_info *stdin_client;
    uv_timer_t flush_timer;
};

hashmap *g_auditd_clients;
extern statsite_networking *netconf;


// Static typedefs
static void handle_flush_event(uv_timer_t *watcher, int status);
static void handle_new_client(uv_poll_t *watcher, int status, int ready_events);
static void handle_udp_message(uv_poll_t *watch, int status, int ready_events);
static void invoke_event_handler(uv_poll_t *watch, int status, int ready_events);

// Utility methods
static int set_client_sockopts(int client_fd);
static conn_info* get_conn();

// Circular buffer method
static void circbuf_init(circular_buffer *buf);
static void circbuf_clear(circular_buffer *buf);
static void circbuf_free(circular_buffer *buf);
static uint64_t circbuf_avail_buf(circular_buffer *buf);
static uint64_t circbuf_used_buf(circular_buffer *buf);
static void circbuf_grow_buf(circular_buffer *buf);
static void circbuf_setup_readv_iovec(circular_buffer *buf, struct iovec *vectors, int *num_vectors);
static void circbuf_advance_write(circular_buffer *buf, uint64_t bytes);
static void circbuf_advance_read(circular_buffer *buf, uint64_t bytes);
static int circbuf_write(circular_buffer *buf, char *in, uint64_t bytes);

static int read_nn_data(conn_info *conn) {
    /**
     * Figure out how much space we have to write.
     * If we have < 50% free, we resize the buffer using
     * a multiplier.
     */
    uint32_t avail_buf = circbuf_avail_buf(&conn->input);
    if (avail_buf < conn->input.buf_size / 2) {
        circbuf_grow_buf(&conn->input);
    }

    // Build the IO vectors to perform the read
    struct iovec vectors[2];
    int num_vectors;
    circbuf_setup_readv_iovec(&conn->input, (struct iovec*)&vectors, &num_vectors);

    // Issue the read
    struct nn_msghdr hdr;
    memset(&hdr, 0, sizeof (hdr));
    hdr.msg_iov = (struct nn_iovec *)vectors;
    hdr.msg_iovlen = 2;
    ssize_t read_bytes = nn_recvmsg(conn->nn_fd, &hdr, 0);

    // Make sure we actually read something
    if (read_bytes == 0) {
        log_debug(lg, "Closed client connection. [%d]\n", conn->client.io_watcher.fd);
        return 1;
    } else if (read_bytes == -1) {
        // Ignore the error, read again later
        if (errno == EAGAIN || errno == EINTR)
            return 0;

        log_error(lg, "Failed to read() from connection [%d]! %s.",
                conn->client.io_watcher.fd, strerror(errno));
        return 1;
    }

    // Update the write cursor
    circbuf_advance_write(&conn->input, read_bytes);

    // Append \n if missing
    if (conn->input.buffer[conn->input.write_cursor - 1] != '\n')
        circbuf_write(&conn->input, "\n", 1);

    return 0;
}

static void handle_ipc_client(uv_poll_t *watcher, int status, int ready_events) {
    // Read in the data, and close on issues
    conn_info *conn = watcher->data;
    read_nn_data(conn);

    // Invoke the connection handler
    statsite_conn_handler handle = {netconf->config, watcher->data};
    handle_client_connect(&handle);
}

static void handle_auditd_client(uv_poll_t *watcher, int status, int ready_events)
{
    // Read in the data, and close on issues
    conn_info *conn = watcher->data;
    read_nn_data(conn);

    // Invoke the connection handler
    statsite_conn_handler handle = {netconf->config, watcher->data};
    parse_auditd_client(&handle);
}

int
auditserver_subscriber(statsite_config *config, char *auditserver_id,
    char *auditserver_addr, char *topic)
{
	int lsub_fd;
	int err;

	if ((!auditserver_id) || (!auditserver_addr) || (!topic))
		return -EBADF;

	void *val;
	err = hashmap_get(g_auditd_clients, auditserver_id, &val);
	if (err == 0)
		return -EEXIST;

	lsub_fd = nn_socket(AF_SP, NN_SUB);
	if (lsub_fd < 0) {
		log_error(lg, "socket create error : %s [%d]",
		    strerror(errno), (int) errno);
		return -errno;
	}

	/* set the option so we can use ipv6 address */
	int flag = 0;
	err = nn_setsockopt(lsub_fd, NN_SOL_SOCKET , NN_IPV4ONLY, &flag,
	    sizeof(int));
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "setsockopt error: %s [%d]",
		    strerror(errno), errno);
		return -errno;
	}

	/* format of address for nn_connect is: tcp://if_name;[ipv6_addr]:port
	 * we retrieve the interface name from the config
	 * which retrived it previously from ccowd
	 * if there are no interfaces, we return
	 */
	if (!config->if_count) {
		log_error(lg, "Network interfaces not known for "
			"outbound traffic");
		return -EINVAL;
	}

	struct sockaddr_in6 a6;
	err = inet_pton(AF_INET6, auditserver_addr, &a6.sin6_addr);
	if (err != 1) {
		log_error(lg, "Invalid IPv6 address '%s'!", auditserver_addr);
		return -1;
	}

	char addr[256];
	if (REP_IS_4OVER6(&a6)) {
		struct sockaddr_in a4;
		char a4str[INET_ADDRSTRLEN + 1];

		replicast_ip4_decap(&a6, &a4);
		inet_ntop(AF_INET, &a4.sin_addr, a4str, INET_ADDRSTRLEN);

		sprintf(addr, "tcp://%s:%d", a4str, AUDITD_PUB_PORT);
	} else {
		sprintf(addr, "tcp://%s;%s:%d", config->if_name[0],
						auditserver_addr, AUDITD_PUB_PORT);
	}

	err = nn_connect(lsub_fd, addr);
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "Failed to connect to %s : %s [%d]", addr,
						strerror(errno), (int) errno);
		return -errno;
	}

	log_info(lg, "Connected to remote auditserv %s", addr);
	err = nn_setsockopt(lsub_fd, NN_SUB, NN_SUB_SUBSCRIBE, topic,
	    strlen(topic));
	if (err < 0) {
		nn_close(lsub_fd);
		log_error(lg, "setsockopt subscribe error: %s [%d]",
		    strerror(errno), errno);
		return -errno;
	}

	int ipc_fd;
	size_t fdsz = sizeof (ipc_fd);
	err = nn_getsockopt (lsub_fd, NN_SOL_SOCKET, NN_RCVFD,
	    (char *) &ipc_fd, &fdsz);
	if (err < 0) {
		nn_close(lsub_fd);
		log_error (lg, "setsockopt rcv_fd error: %s [%d]",
		    strerror(errno), errno);
		return -errno;
	}

	/* allocate the client for an entry into the hash map */
	auditd_client_handle *client_handle
		= je_calloc(1, sizeof(auditd_client_handle));
	if (!client_handle) {
		nn_close(lsub_fd);
		log_error(lg, "memory allocation error ");
		return -ENOMEM;
	}

	client_handle->conn = get_conn();
	conn_info *lconn = client_handle->conn;
	lconn->nn_fd = lsub_fd;
	hashmap_put(g_auditd_clients, auditserver_id, client_handle);

	// Create the libuv objects
	uv_poll_init(uv_default_loop(), &lconn->client, ipc_fd);
	uv_poll_start(&lconn->client, UV_READABLE, handle_auditd_client);

	return 0;
}


/**
 * Initializes the NanoMsg IPC listener
 * @arg netconf The network configuration
 * @return 0 on success.
 */
static int setup_ipc_listener(statsite_networking *netconf) {
	if (!netconf->config->ipc_endpoint) {
		log_info(lg, "IPC endpoint is disabled");
		return 0;
	}

	int ipc_nn = nn_socket(AF_SP, NN_PAIR);
	if (ipc_nn == -1) {
		log_error(lg, "Failed create socket: %s [%d]",
		    strerror(errno), (int)errno);
		return 1;
	}

	char *address = netconf->config->ipc_endpoint;
	int rc = nn_bind(ipc_nn, address);
	if(rc < 0) {
		log_error(lg, "Failed bind to \"%s\": %s [%d]", address,
		    strerror(errno), (int)errno);
		return 1;
	}

	int ipc_fd;
	size_t fdsz = sizeof (ipc_fd);
	rc = nn_getsockopt (ipc_nn, NN_SOL_SOCKET, NN_RCVFD, (char*) &ipc_fd, &fdsz);

	log_info(lg, "Listening on events on ipc '%s' [%d]", address, ipc_fd);

	conn_info *conn = get_conn();
	conn->nn_fd = ipc_nn;
	netconf->ipc_client_rcv.data = conn;

	// Create the libuv objects
	uv_poll_init(uv_default_loop(), &netconf->ipc_client_rcv, ipc_fd);
	uv_poll_start(&netconf->ipc_client_rcv, UV_READABLE, handle_ipc_client);
	return 0;
}

/*
 * Setup the client end point to the IPC so we can
 * send messages to the ccowd over ipc.
 */
static int
setup_ipc_clientsender(statsite_networking *netconf)
{
    int ipc_nn = nn_socket(AF_SP, NN_REQ);
    if (ipc_nn == -1) {
        log_error(lg, "Failed create socket: %s [%d]",
            strerror(errno), (int)errno);
        return 1;
    }

    int linger = -1;
    nn_setsockopt(ipc_nn, NN_SOL_SOCKET, NN_LINGER, &linger, sizeof (linger));

    char ipc_addr[PATH_MAX];
    snprintf(ipc_addr, sizeof(ipc_addr), CCOWD_IPC_ADDRESS, nedge_path());
    int eid = nn_connect(ipc_nn, ipc_addr);
    if (eid < 0) {
        log_error(lg, "Failed to connect to \"%s\" %s [%d]",
        	ipc_addr, strerror(errno), errno);
        return 1;

    }
    netconf->ipc_send_sock = ipc_nn;
    return 0;

}

int
auditd_send_ccowd_message(statsite_networking *netconf, const char *message)
{
	ssize_t len = strlen(message);
	if ( netconf->ipc_send_sock <= 0) {
		return -EBADF;
	}
	int err = nn_send(netconf->ipc_send_sock, message, len, 0);
	if (len != err) {
		log_warn(lg, "%s : %s", __FUNCTION__, strerror(errno));
		return -errno;
	}
	return 0;
}

static int
auditd_request_ccowd_serverinfo(statsite_networking *netconf)
{
	char request[] = "GET_SERVERINFO";
	int res = auditd_send_ccowd_message(netconf, request);
	if (res != 0) {
		log_error(lg, "Failed on GET_SERVERINFO : [%d]", res);
		return res;
	}

	return 0;
}

/**
 * Initializes the TCP listener
 * @arg netconf The network configuration
 * @return 0 on success.
 */
static int setup_tcp_listener(statsite_networking *netconf) {
    if (netconf->config->tcp_port == 0) {
        log_info(lg, "TCP port is disabled");
        return 0;
    }
    struct sockaddr_in addr;
    struct in_addr bind_addr;
    bzero(&addr, sizeof(addr));
    bzero(&bind_addr, sizeof(bind_addr));
    addr.sin_family = PF_INET;
    addr.sin_port = htons(netconf->config->tcp_port);

    int ret = inet_pton(AF_INET, netconf->config->bind_address, &bind_addr);
    if (ret != 1) {
        log_error(lg, "Invalid IPv4 address '%s'!", netconf->config->bind_address);
        return 1;
    }
    addr.sin_addr = bind_addr;

    // Make the socket, bind and listen
    int tcp_listener_fd = socket(PF_INET, SOCK_STREAM, 0);
    int optval = 1;
    if (setsockopt(tcp_listener_fd, SOL_SOCKET,
                SO_REUSEADDR, &optval, sizeof(optval))) {
        log_error(lg, "Failed to set SO_REUSEADDR! Err: %s", strerror(errno));
        close(tcp_listener_fd);
        return 1;
    }
    if (bind(tcp_listener_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        log_error(lg, "Failed to bind on TCP socket! Err: %s", strerror(errno));
        close(tcp_listener_fd);
        return 1;
    }
    if (listen(tcp_listener_fd, BACKLOG_SIZE) != 0) {
        log_error(lg, "Failed to listen on TCP socket! Err: %s", strerror(errno));
        close(tcp_listener_fd);
        return 1;
    }

    log_info(lg, "Listening on TCP '%s:%d'",
           netconf->config->bind_address, netconf->config->tcp_port);

    // Create the libuv objects
    uv_poll_init(uv_default_loop(), &netconf->tcp_client, tcp_listener_fd);
    uv_poll_start(&netconf->tcp_client, UV_READABLE, handle_new_client);
    return 0;
}

/**
 * Initializes the UDP Listener.
 * @arg netconf The network configuration
 * @return 0 on success.
 */
static int setup_udp_listener(statsite_networking *netconf) {
    if (netconf->config->udp_port == 0) {
        log_info(lg, "UDP port is disabled");
        return 0;
    }
    struct sockaddr_in addr;
    struct in_addr bind_addr;
    bzero(&addr, sizeof(addr));
    bzero(&bind_addr, sizeof(bind_addr));
    addr.sin_family = PF_INET;
    addr.sin_port = htons(netconf->config->udp_port);

    int ret = inet_pton(AF_INET, netconf->config->bind_address, &bind_addr);
    if (ret != 1) {
        log_error(lg, "Invalid IPv4 address '%s'!", netconf->config->bind_address);
        return 1;
    }
    addr.sin_addr = bind_addr;

    // Make the socket, bind and listen
    int udp_listener_fd = socket(PF_INET, SOCK_DGRAM, 0);
    int optval = 1;
    if (setsockopt(udp_listener_fd, SOL_SOCKET,
                SO_REUSEADDR, &optval, sizeof(optval))) {
        log_error(lg, "Failed to set SO_REUSEADDR! Err: %s", strerror(errno));
        close(udp_listener_fd);
        return 1;
    }
    if (bind(udp_listener_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        log_error(lg, "Failed to bind on UDP socket! Err: %s", strerror(errno));
        close(udp_listener_fd);
        return 1;
    }

    // Put the socket in non-blocking mode
    int flags = fcntl(udp_listener_fd, F_GETFL, 0);
    fcntl(udp_listener_fd, F_SETFL, flags | O_NONBLOCK);

    // Allocate a connection object for the UDP socket,
    // ensure a min-buffer size of 64K
    conn_info *conn = get_conn();
    while (circbuf_avail_buf(&conn->input) < 65536) {
        circbuf_grow_buf(&conn->input);
    }
    netconf->udp_client.data = conn;

    log_info(lg, "Listening on UDP '%s:%d'.",
           netconf->config->bind_address, netconf->config->udp_port);

    // Create the libuv objects
    uv_poll_init(uv_default_loop(), &netconf->udp_client, udp_listener_fd);
    uv_poll_start(&netconf->udp_client, UV_READABLE, handle_udp_message);
    return 0;
}

/**
 * Initializes the stdin listener.
 * @arg netconf The network configuration
 * @return 0 on success.
 */
static int setup_stdin_listener(statsite_networking *netconf) {
    if (!netconf->config->parse_stdin) {
        log_info(lg, "STDIN is disabled");
        return 0;
    }

    // Log we are listening
    log_info(lg, "Listening on stdin.");

    // Create an associated conn object
    conn_info *conn = get_conn();
    netconf->stdin_client = conn;

    // Initialize the libuv stuff
    uv_poll_init(uv_default_loop(), &conn->client, STDIN_FILENO);
    uv_poll_start(&conn->client, UV_READABLE, invoke_event_handler);
    return 0;
}

/**
 * Initializes the hashmap that contains the
 * other auditserver clients Daif aggregator mode is enabled
 */

static int setup_auditd_clients(statsite_networking *netconf) {
	if(!netconf->config->is_aggregator) {
		log_info(lg, "Aggregator is disabled");
		return 0;
	}
	log_info(lg, "Aggregator is enabled");
	int res = hashmap_init(0, &g_auditd_clients);
	return res;
}

/**
 * Initializes the networking interfaces
 * @arg config Takes the bloom server configuration
 * @arg mgr The filter manager to pass up to the connection handlers
 * @arg netconf Output. The configuration for the networking stack.
 */
int init_networking(statsite_config *config, statsite_networking **netconf_out) {
    // Initialize the netconf structure
    statsite_networking *netconf = je_calloc(1, sizeof(struct statsite_networking));
    netconf->ipc_send_sock = -1; /* so we can tell uninitialized sender socket */
    netconf->config = config;

    if (!uv_default_loop ()) {
        log_error(lg, "Failed to initialize libuv!");
        je_free(netconf);
        return 1;
    }

    // Setup the stdin listener
    int res = setup_stdin_listener(netconf);
    if (res != 0) {
        je_free(netconf);
        return 1;
    }

    res = setup_auditd_clients(netconf);
    if (res != 0) {
	je_free(netconf);
	return 1;
    }

    if (netconf->config->tcp_port > 0) {
	    // Setup the TCP listener
	    res = setup_tcp_listener(netconf);
	    if (res != 0) {
		    je_free(netconf);
		    return 1;
	    }
    }

    if (netconf->config->udp_port > 0) {
	    // Setup the UDP listener
	    res = setup_udp_listener(netconf);
	    if (res != 0) {
		    if (uv_is_active((const uv_handle_t *)&netconf->tcp_client)) {
			    uv_poll_stop(&netconf->tcp_client);
			    close(netconf->tcp_client.io_watcher.fd);
		    }
		    je_free(netconf);
		    return 1;
	    }
    }

    // Setup the IPC listener
    res = setup_ipc_listener(netconf);
    if (res != 0) {
        if (uv_is_active((const uv_handle_t *)&netconf->tcp_client)) {
            uv_poll_stop(&netconf->tcp_client);
            close(netconf->tcp_client.io_watcher.fd);
        }
        if (uv_is_active((const uv_handle_t *)&netconf->udp_client)) {
            uv_poll_stop(&netconf->udp_client);
            close(netconf->udp_client.io_watcher.fd);
        }
        je_free(netconf);
        return 1;
    }

    struct stat sts;
    if (netconf->config->is_aggregator && stat(CCOWD_IPC_PATH, &sts) == 0) {

	    res = setup_ipc_clientsender(netconf);
	    if (res != 0) {
		    if (uv_is_active((const uv_handle_t *)&netconf->tcp_client)) {
			    uv_poll_stop(&netconf->tcp_client);
			    close(netconf->tcp_client.io_watcher.fd);
		    }
		    if (uv_is_active((const uv_handle_t *)&netconf->udp_client)) {
			    uv_poll_stop(&netconf->udp_client);
			    close(netconf->udp_client.io_watcher.fd);
		    }
		    je_free(netconf);
		    return 1;
	    }

		log_info(lg, "Requesting GET_SERVERINFO to ccowd. It can require some time.");
		/** @bug Timeout is too long or does not exist and signal handlers still are not acivated */
	    res = auditd_request_ccowd_serverinfo(netconf);
	    if (res != 0) {
		    log_error(lg, "Failed to request GET_SERVERINFO to ccowd.");
	    }

    }

    // Setup the timer
    uv_timer_init(uv_default_loop(), &netconf->flush_timer);
    uv_timer_start(&netconf->flush_timer, handle_flush_event, config->flush_interval,
	config->flush_interval * 1000);

    // Prepare the conn handlers
    init_conn_handler(config);

    // Success!
    *netconf_out = netconf;
    return 0;
}


/**
 * Invoked when our flush timer is reached.
 * We need to instruct the connection handler about this.
 */
static void handle_flush_event(uv_timer_t *watcher, int status) {
    // Inform the connection handler of the timeout
    flush_interval_trigger();
    clstat_dump();
}


/**
 * Invoked when a TCP listening socket fd is ready
 * to accept a new client. Accepts the client, initializes
 * the connection buffers, and stars to listening for data
 */
static void handle_new_client(uv_poll_t *watcher, int status, int ready_events) {
    // Accept the client connection
    int listen_fd = watcher->io_watcher.fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd,
                        (struct sockaddr*)&client_addr,
                        &client_addr_len);

    // Check for an error
    if (client_fd == -1) {
        log_error(lg, "Failed to accept() connection! %s.", strerror(errno));
        return;
    }

    // Setup the socket
    if (set_client_sockopts(client_fd)) {
        return;
    }

    // Debug info
    log_debug(lg, "Accepted client connection: %s %d [%d]",
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);

    // Get the associated conn object
    conn_info *conn = get_conn();

    // Initialize the libuv stuff
    uv_poll_init(uv_default_loop(), &conn->client, client_fd);
    uv_poll_start(&conn->client, UV_READABLE, invoke_event_handler);
}


/**
 * Invoked when a client connection has data ready to be read.
 * We need to take care to add the data to our buffers, and then
 * invoke the connection handlers who have the business logic
 * of what to do.
 */
static int read_client_data(conn_info *conn) {
    /**
     * Figure out how much space we have to write.
     * If we have < 50% free, we resize the buffer using
     * a multiplier.
     */
    uint32_t avail_buf = circbuf_avail_buf(&conn->input);
    if (avail_buf < conn->input.buf_size / 2) {
        circbuf_grow_buf(&conn->input);
    }

    // Build the IO vectors to perform the read
    struct iovec vectors[2];
    int num_vectors;
    circbuf_setup_readv_iovec(&conn->input, (struct iovec*)&vectors, &num_vectors);

    // Issue the read
    ssize_t read_bytes = readv(conn->client.io_watcher.fd, (struct iovec*)&vectors, num_vectors);

    // Make sure we actually read something
    if (read_bytes == 0) {
        log_debug(lg, "Closed client connection. [%d]\n", conn->client.io_watcher.fd);
        return 1;
    } else if (read_bytes == -1) {
        // Ignore the error, read again later
        if (errno == EAGAIN || errno == EINTR)
            return 0;

        log_error(lg, "Failed to read() from connection [%d]! %s.",
                conn->client.io_watcher.fd, strerror(errno));
        return 1;
    }

    // Update the write cursor
    circbuf_advance_write(&conn->input, read_bytes);
    return 0;
}


/**
 * Invoked when a UDP connection has a message ready to be read.
 * We need to take care to add the data to our buffers, and then
 * invoke the connection handlers who have the business logic
 * of what to do.
 */
static void handle_udp_message(uv_poll_t *watch, int status, int ready_events) {
    while (1) {
        // Get the associated connection struct
        conn_info *conn = watch->data;

        // Clear the input buffer
        circbuf_clear(&conn->input);

        // Build the IO vectors to perform the read
        struct iovec vectors[2];
        int num_vectors;
        circbuf_setup_readv_iovec(&conn->input, (struct iovec*)&vectors, &num_vectors);

        /*
         * Issue the read, always use the first vector.
         * since we just cleared the buffer, and it should
         * be a contiguous buffer.
         */
        assert(num_vectors == 1);
        ssize_t read_bytes = recv(watch->io_watcher.fd, vectors[0].iov_base,
                                    vectors[0].iov_len, 0);

        // Make sure we actually read something
        if (read_bytes == 0) {
            log_debug(lg, "Got empty UDP packet. [%d]\n", watch->io_watcher.fd);
            return;

        } else if (read_bytes == -1) {
            if (errno != EAGAIN && errno != EINTR) {
                log_error(lg, "Failed to recv() from connection [%d]! %s.",
                        watch->io_watcher.fd, strerror(errno));
            }
            return;
        }

        // Update the write cursor
        circbuf_advance_write(&conn->input, read_bytes);

        // UDP clients don't need to append newlines to the messages like
        // TCP clients do, but our parser requires them.  Append one if
        // it's not present.
        if (conn->input.buffer[conn->input.write_cursor - 1] != '\n')
            circbuf_write(&conn->input, "\n", 1);

        // Invoke the connection handler
        statsite_conn_handler handle = {netconf->config, watch->data};
        handle_client_connect(&handle);
    }
}


/**
 * Reads the thread specific userdata to figure out what
 * we need to handle. Things that purely effect the network
 * stack should be handled here, but otherwise we should defer
 * to the connection handlers.
 */
static void invoke_event_handler(uv_poll_t *watcher, int status, int ready_events) {
    // Read in the data, and close on issues
    conn_info *conn = watcher->data;
    if (read_client_data(conn)) {
        if (watcher->io_watcher.fd != STDIN_FILENO)
            close_client_connection(conn);
        return;
    }

    // Invoke the connection handler, and close connection on error
    statsite_conn_handler handle = {netconf->config, watcher->data};
    if (handle_client_connect(&handle) && watcher->io_watcher.fd != STDIN_FILENO)
        close_client_connection(conn);
}


/**
 * Entry point for main thread to enter the networking
 * stack. This method blocks indefinitely until the
 * network stack is shutdown.
 * @arg netconf The configuration for the networking stack.
 * @arg should_run_p A reference to a variable that is set when
 * a signal is caught and shutdown should be started
 */
void enter_networking_loop(statsite_networking *netconf, volatile int *should_run_p) {
    // Run forever until we are told to halt
    while (likely(*should_run_p != 0)) {
        uv_run(uv_default_loop(), UV_RUN_ONCE);
    }
    return;
}

/**
 * Shuts down all the connections
 * and listeners and prepares to exit.
 * @arg netconf The config for the networking stack.
 */
int shutdown_networking(statsite_networking *netconf) {
    // Stop listening for new connections
    if (uv_is_active((const uv_handle_t *)&netconf->tcp_client)) {
        uv_poll_stop(&netconf->tcp_client);
        close(netconf->tcp_client.io_watcher.fd);
    }
    if (uv_is_active((const uv_handle_t *)&netconf->udp_client)) {
        uv_poll_stop(&netconf->udp_client);
        close(netconf->udp_client.io_watcher.fd);
    }
    if (uv_is_active((const uv_handle_t *)&netconf->ipc_client_rcv)) {
        uv_poll_stop(&netconf->ipc_client_rcv);
	conn_info *conn = netconf->ipc_client_rcv.data;
	nn_close(conn->nn_fd);
    }
    if (netconf->stdin_client != NULL) {
        close_client_connection(netconf->stdin_client);
        netconf->stdin_client = NULL;
    }

    // Stop the other timers
    uv_timer_stop(&netconf->flush_timer);

    // TODO: Close all the client connections
    // ??? For now, we just leak the memory
    // since we are shutdown down anyways...

    // Free the netconf
    je_free(netconf);
    return 0;
}

/*
 * These are externally visible methods for
 * interacting with the connection buffers.
 */

/**
 * Called to close and cleanup a client connection.
 * Must be called when the connection is not already
 * scheduled. e.g. After uv_poll_stop() has been called.
 * Leaves the connection in the conns list so that it
 * can be re-used.
 * @arg conn The connection to close
 */
void close_client_connection(conn_info *conn) {
    // Stop the libuv clients
    uv_poll_stop(&conn->client);

    // Clear everything out
    circbuf_free(&conn->input);

    // Close the fd
    log_debug(lg, "Closed connection. [%d]", conn->client.io_watcher.fd);
    close(conn->client.io_watcher.fd);
    je_free(conn);
}


/**
 * This method is used to conveniently extract commands from the
 * command buffer. It scans up to a terminator, and then sets the
 * buf to the start of the buffer, and buf_len to the length
 * of the buffer. The output param should_free indicates that
 * the caller should free the buffer pointed to by buf when it is finished.
 * This method consumes the bytes from the underlying buffer, freeing
 * space for later reads.
 * @arg conn The client connection
 * @arg terminator The terminator charactor to look for. Replaced by null terminator.
 * @arg buf Output parameter, sets the start of the buffer.
 * @arg buf_len Output parameter, the length of the buffer.
 * @arg should_free Output parameter, should the buffer be freed by the caller.
 * @return 0 on success, -1 if the terminator is not found.
 */
int extract_to_terminator(statsite_conn_info *conn, char terminator, char **buf, int *buf_len, int *should_free) {
    // First we need to find the terminator...
    char *term_addr = NULL;
    if (unlikely(conn->input.write_cursor < conn->input.read_cursor)) {
        /*
         * We need to scan from the read cursor to the end of
         * the buffer, and then from the start of the buffer to
         * the write cursor.
        */
        term_addr = memchr(conn->input.buffer+conn->input.read_cursor,
                           terminator,
                           conn->input.buf_size - conn->input.read_cursor);

        // If we've found the terminator, we can just move up
        // the read cursor
        if (term_addr) {
            *buf = conn->input.buffer + conn->input.read_cursor;
            *buf_len = term_addr - *buf + 1;    // Difference between the terminator and location
            *term_addr = '\0';              // Add a null terminator
            *should_free = 0;               // No need to free, in the buffer

            // Push the read cursor forward
            conn->input.read_cursor = (term_addr - conn->input.buffer + 1) % conn->input.buf_size;
            return 0;
        }

        // Wrap around
        term_addr = memchr(conn->input.buffer,
                           terminator,
                           conn->input.write_cursor);

        // If we've found the terminator, we need to allocate
        // a contiguous buffer large enough to store everything
        // and provide a linear buffer
        if (term_addr) {
            int start_size = term_addr - conn->input.buffer + 1;
            int end_size = conn->input.buf_size - conn->input.read_cursor;
            *buf_len = start_size + end_size;
            *buf = je_malloc(*buf_len);

            // Copy from the read cursor to the end
            memcpy(*buf, conn->input.buffer+conn->input.read_cursor, end_size);

            // Copy from the start to the terminator
            *term_addr = '\0';              // Add a null terminator
            memcpy(*buf+end_size, conn->input.buffer, start_size);

            *should_free = 1;               // Must free, not in the buffer
            conn->input.read_cursor = start_size; // Push the read cursor forward
        }

    } else {
        /*
         * We need to scan from the read cursor to write buffer.
         */
        term_addr = memchr(conn->input.buffer+conn->input.read_cursor,
                           terminator,
                           conn->input.write_cursor - conn->input.read_cursor);

        // If we've found the terminator, we can just move up
        // the read cursor
        if (term_addr) {
            *buf = conn->input.buffer + conn->input.read_cursor;
            *buf_len = term_addr - *buf + 1; // Difference between the terminator and location
            *term_addr = '\0';               // Add a null terminator
            *should_free = 0;                // No need to free, in the buffer
            conn->input.read_cursor = term_addr - conn->input.buffer + 1; // Push the read cursor forward
        }
    }

    // Minor optimization, if our read-cursor has caught up
    // with the write cursor, reset them to the beginning
    // to avoid wrapping in the future
    if (conn->input.read_cursor == conn->input.write_cursor) {
        conn->input.read_cursor = 0;
        conn->input.write_cursor = 0;
    }

    // Return success if we have a term address
    return ((term_addr) ? 0 : -1);
}


/**
 * This method is used to query how much data is available
 * to be read from the command buffer.
 * @arg conn The client connection
 * @return The bytes available
 */
uint64_t available_bytes(statsite_conn_info *conn) {
    // Query the circular buffer
    return circbuf_used_buf(&conn->input);
}

/**
 * Lets the caller look at the next byte
 * @arg conn The client connectoin
 * @arg byte The output byte
 * @return 0 on success, -1 if there is no data.
 */
int peek_client_byte(statsite_conn_info *conn, unsigned char* byte) {
    if (unlikely(!circbuf_used_buf(&conn->input))) return -1;
    *byte = *(unsigned char*)(conn->input.buffer+conn->input.read_cursor);
    return 0;
}

/**
 * This method is used to peek into the input buffer without
 * causing input to be consumed. It attempts to use the data
 * in-place, similar to read_client_bytes.
 * @arg conn The client connection
 * @arg bytes The number of bytes to peek
 * @arg buf Output parameter, sets the start of the buffer.
 * @arg should_free Output parameter, should the buffer be freed by the caller.
 * @return 0 on success, -1 if there is insufficient data.
 */
int peek_client_bytes(statsite_conn_info *conn, int bytes, char** buf, int* should_free) {
    if (unlikely((uint32_t)bytes > circbuf_used_buf(&conn->input))) return -1;

    // Handle the wrap around case
    if (unlikely(conn->input.write_cursor < conn->input.read_cursor)) {
        // Check if we can use a contiguous chunk
        int end_size = conn->input.buf_size - conn->input.read_cursor;
        if (end_size >= bytes) {
            *buf = conn->input.buffer + conn->input.read_cursor;
            *should_free = 0;

        // Otherwise, allocate a dynamic slab, and copy
        } else {
            *buf = je_malloc(bytes);
            memcpy(*buf, conn->input.buffer + conn->input.read_cursor, end_size);
            memcpy(*buf + end_size, conn->input.buffer, bytes - end_size);
            *should_free = 1;
        }

    // Handle the contiguous case
    } else {
        *buf = conn->input.buffer + conn->input.read_cursor;
        *should_free = 0;
    }

    return 0;
}

/**
 * This method is used to seek the input buffer without
 * consuming input. It can be used in conjunction with
 * peek_client_bytes to conditionally seek.
 * @arg conn The client connection
 * @arg bytes The number of bytes to seek
 * @return 0 on success, -1 if there is insufficient data.
 */
int seek_client_bytes(statsite_conn_info *conn, int bytes) {
    if (unlikely((uint32_t)bytes > circbuf_used_buf(&conn->input))) return -1;
    circbuf_advance_read(&conn->input, bytes);
    return 0;
}


/**
 * This method is used to read and consume the input buffer
 * @arg conn The client connection
 * @arg bytes The number of bytes to read
 * @arg buf Output parameter, sets the start of the buffer.
 * @arg should_free Output parameter, should the buffer be freed by the caller.
 * @return 0 on success, -1 if there is insufficient data.
 */
int read_client_bytes(statsite_conn_info *conn, int bytes, char** buf, int* should_free) {
    if (unlikely((uint32_t)bytes > circbuf_used_buf(&conn->input))) return -1;

    // Handle the wrap around case
    if (unlikely(conn->input.write_cursor < conn->input.read_cursor)) {
        // Check if we can use a contiguous chunk
        int end_size = conn->input.buf_size - conn->input.read_cursor;
        if (end_size >= bytes) {
            *buf = conn->input.buffer + conn->input.read_cursor;
            *should_free = 0;

        // Otherwise, allocate a dynamic slab, and copy
        } else {
            *buf = je_malloc(bytes);
            memcpy(*buf, conn->input.buffer + conn->input.read_cursor, end_size);
            memcpy(*buf + end_size, conn->input.buffer, bytes - end_size);
            *should_free = 1;
        }

    // Handle the contiguous case
    } else {
        *buf = conn->input.buffer + conn->input.read_cursor;
        *should_free = 0;
    }

    // Advance the read cursor
    circbuf_advance_read(&conn->input, bytes);
    return 0;
}


/**
 * Sets the client socket options.
 * @return 0 on success, 1 on error.
 */
static int set_client_sockopts(int client_fd) {
    // Setup the socket to be non-blocking
    int sock_flags = fcntl(client_fd, F_GETFL, 0);
    if (sock_flags < 0) {
        log_error(lg, "Failed to get socket flags on connection! %s.", strerror(errno));
        close(client_fd);
        return 1;
    }
    if (fcntl(client_fd, F_SETFL, sock_flags | O_NONBLOCK)) {
        log_error(lg, "Failed to set O_NONBLOCK on connection! %s.", strerror(errno));
        close(client_fd);
        return 1;
    }

    /**
     * Set TCP_NODELAY. This will allow us to send small response packets more
     * quickly, since our responses are rarely large enough to consume a packet.
     */
    int flag = 1;
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int))) {
        log_warn(lg, "Failed to set TCP_NODELAY on connection! %s.", strerror(errno));
    }

    // Set keep alive
    if(setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(int))) {
        log_warn(lg, "Failed to set SO_KEEPALIVE on connection! %s.", strerror(errno));
    }

    return 0;
}


/**
 * Returns the conn_info* object associated with the FD
 * or allocates a new one as necessary.
 */
static conn_info* get_conn() {
    // Allocate space
    conn_info *conn = je_malloc(sizeof(conn_info));

    // Prepare the buffers
    circbuf_init(&conn->input);

    // Store a reference to the conn object
    conn->client.data = conn;
    return conn;
}

/*
 * Methods for manipulating our circular buffers
 */

// Conditionally allocates if there is no buffer
static void circbuf_init(circular_buffer *buf) {
    buf->read_cursor = 0;
    buf->write_cursor = 0;
    buf->buf_size = INIT_CONN_BUF_SIZE * sizeof(char);
    buf->buffer = je_malloc(buf->buf_size);
}

// Clears the circular buffer, reseting it.
static void circbuf_clear(circular_buffer *buf) {
    buf->read_cursor = 0;
    buf->write_cursor = 0;
}

// Frees a buffer
static void circbuf_free(circular_buffer *buf) {
    if (buf->buffer) je_free(buf->buffer);
    buf->buffer = NULL;
}

// Calculates the available buffer size
static uint64_t circbuf_avail_buf(circular_buffer *buf) {
    uint64_t avail_buf;
    if (buf->write_cursor < buf->read_cursor) {
        avail_buf = buf->read_cursor - buf->write_cursor - 1;
    } else {
        avail_buf = buf->buf_size - buf->write_cursor + buf->read_cursor - 1;
    }
    return avail_buf;
}

// Calculates the used buffer size
static uint64_t circbuf_used_buf(circular_buffer *buf) {
    uint64_t used_buf;
    if (buf->write_cursor < buf->read_cursor) {
        used_buf = buf->buf_size - buf->read_cursor + buf->write_cursor;
    } else {
        used_buf = buf->write_cursor - buf->read_cursor;
    }
    return used_buf;
}

// Grows the circular buffer to make room for more data
static void circbuf_grow_buf(circular_buffer *buf) {
    int new_size = buf->buf_size * CONN_BUF_MULTIPLIER * sizeof(char);
    char *new_buf = je_malloc(new_size);
    int bytes_written = 0;

    // Check if the write has wrapped around
    if (buf->write_cursor < buf->read_cursor) {
        // Copy from the read cursor to the end of the buffer
        bytes_written = buf->buf_size - buf->read_cursor;
        memcpy(new_buf,
               buf->buffer+buf->read_cursor,
               bytes_written);

        // Copy from the start to the write cursor
        memcpy(new_buf+bytes_written,
               buf->buffer,
               buf->write_cursor);
        bytes_written += buf->write_cursor;

    // We haven't wrapped yet...
    } else {
        // Copy from the read cursor up to the write cursor
        bytes_written = buf->write_cursor - buf->read_cursor;
        memcpy(new_buf,
               buf->buffer + buf->read_cursor,
               bytes_written);
    }

    // Update the buffer locations and everything
    je_free(buf->buffer);
    buf->buffer = new_buf;
    buf->buf_size = new_size;
    buf->read_cursor = 0;
    buf->write_cursor = bytes_written;
}


// Initializes a pair of iovectors to be used for readv
static void circbuf_setup_readv_iovec(circular_buffer *buf, struct iovec *vectors, int *num_vectors) {
    // Check if we've wrapped around
    *num_vectors = 1;
    if (buf->write_cursor < buf->read_cursor) {
        vectors[0].iov_base = buf->buffer + buf->write_cursor;
        vectors[0].iov_len = buf->read_cursor - buf->write_cursor - 1;
    } else {
        vectors[0].iov_base = buf->buffer + buf->write_cursor;
        vectors[0].iov_len = buf->buf_size - buf->write_cursor - 1;
        if (buf->read_cursor > 0)  {
            vectors[0].iov_len += 1;
            vectors[1].iov_base = buf->buffer;
            vectors[1].iov_len = buf->read_cursor - 1;
            *num_vectors = 2;
        }
    }
}

// Advances the cursors
static void circbuf_advance_write(circular_buffer *buf, uint64_t bytes) {
    buf->write_cursor = (buf->write_cursor + bytes) % buf->buf_size;
}

static void circbuf_advance_read(circular_buffer *buf, uint64_t bytes) {
    buf->read_cursor = (buf->read_cursor + bytes) % buf->buf_size;

    // Optimization, reset the cursors if they catchup with each other
    if (buf->read_cursor == buf->write_cursor) {
        buf->read_cursor = 0;
        buf->write_cursor = 0;
    }
}

/**
 * Writes the data from a given input buffer
 * into the circular buffer.
 * @return 0 on success.
 */
static int circbuf_write(circular_buffer *buf, char *in, uint64_t bytes) {
    // Check for available space
    uint64_t avail = circbuf_avail_buf(buf);
    while (avail < bytes) {
        circbuf_grow_buf(buf);
        avail = circbuf_avail_buf(buf);
    }

    if (buf->write_cursor < buf->read_cursor) {
        memcpy(buf->buffer+buf->write_cursor, in, bytes);
        buf->write_cursor += bytes;

    } else {
        uint64_t end_size = buf->buf_size - buf->write_cursor;
        if (end_size >= bytes) {
            memcpy(buf->buffer+buf->write_cursor, in, bytes);
            buf->write_cursor += bytes;

        } else {
            // Copy the first end_size bytes
            memcpy(buf->buffer+buf->write_cursor, in, end_size);

            // Copy the remaining data
            memcpy(buf->buffer, in+end_size, (bytes - end_size));
            buf->write_cursor = (bytes - end_size);
        }
    }

    return 0;
}

