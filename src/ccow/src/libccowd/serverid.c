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
#include <ctype.h>
#include <sys/sysinfo.h>
#include <uv.h>

#include "ccowutil.h"
#include "ccowd-impl.h"
#include "serverid.h"
#include "crypto.h"
#include "logger.h"

#define SERVERID_MAC_CACHE_FILE "%s/var/run/macid.cache"

static struct server_stat this_server;

static int
serverid_uuid(char *in, int len)
{
#ifdef linux
	int fd;

	if (len < 37)
		return -1;

	if ((fd = open("/sys/class/dmi/id/product_uuid", O_RDONLY)) < 0) {
		log_warn(lg, "Cannot open file to read mainboard UUID: %s",
		    strerror(errno));
		/* attempt to workaround "Not Present" UUID for OEM servers */
		if ((fd = open("/sys/class/dmi/id/product_serial", O_RDONLY)) < 0)
			return -1;
	}

	int bytes;
	bytes = read(fd, in, len);
	if (bytes < 0) {
		log_error(lg, "Cannot read mainboard UUID: %s",
		    strerror(errno));
		close(fd);
		return -1;
	}
	if (bytes <= len)
		in[bytes - 1] = '\0';
	close(fd);
	return 0;
#else
	log_error(lg, "Unsupported platform. Cannot retreive product UUID: -1");
	return -1;
#endif
}

/*
 * Retrieve MAC address of first physical interface and store it
 * locally. In case of mismatch, log a warning with an explanation that
 * MAC address of UUID device was changed but return original value,
 * NOT the new one, so that hash tables will continue to operate.
 */
static int
serverid_mac(char *in, int len)
{
	char cached[32] = { 0 };

	if (len < 32)
		return -1;

	/* MACID cache file exists - read cached value */
	struct stat sts;
	char macf_path[PATH_MAX];
	snprintf(macf_path, sizeof(macf_path), SERVERID_MAC_CACHE_FILE, nedge_path());
	if (stat(macf_path, &sts) == 0) {
		int fd;

		if ((fd = open(macf_path, O_RDONLY)) < 0) {
			log_error(lg, "Cannot open MACID in cache: %s",
			    strerror(errno));
			return -1;
		}
		if (read(fd, cached, 12) < 0) {
			log_error(lg, "Cannot read MACID to cache: %s",
			    strerror(errno));
			close(fd);
			return -1;
		}
		close(fd);
	}

	uv_interface_address_t *info;
	int count;
	uv_err_t uverr = uv_interface_addresses(&info, &count);
	if (uverr.code != UV_OK || count == 0) {
		log_error(lg, "Cannot get MAC interfaces");
		return -1;
	}

	int i = count;
	int interface_count = 0;

	while (i--) {
		uv_interface_address_t interface = info[i];

		/* skip non-physical interfaces */
		if (interface.is_internal) {
			free(interface.name);
			continue;
		}

		interface_count++;

		sprintf(in, "%02X%02X%02X%02X%02X%02X.%s",
			(uint8_t)interface.phys_addr[0],
			(uint8_t)interface.phys_addr[1],
			(uint8_t)interface.phys_addr[2],
			(uint8_t)interface.phys_addr[3],
			(uint8_t)interface.phys_addr[4],
			(uint8_t)interface.phys_addr[5],
			interface.name);

		free(interface.name);

		/* MACID cache file does not exists? */
		if (*cached == 0) {
			int fd;

			/* create one */
			if ((fd = open(macf_path, O_WRONLY|O_CREAT, 0644)) < 0) {
				log_error(lg, "Cannot store MACID in cache: %s",
				    strerror(errno));
				free(info);
				return -1;
			}

			if (write(fd, in, strlen(in)) < 0) {
				log_error(lg, "Cannot write MACID to cache: %s",
				    strerror(errno));
				free(info);
				return -1;
			}
			close(fd);

			strncpy(cached, in, 32);
		}
	}

	if (interface_count > 0) {
		strncpy(in, cached, 32);
		*(in + 12) = '\0';
		free(info);
		return 0;
	}

	log_error(lg, "Cannot find physical networking port. At least one "
	    "needs to exist: -1");
	free(info);
	return -1;
}

int
serverid_init(uint128_t *serverid)
{
	char mac[33];
	char uuid[37];
	uint8_t input[sizeof (mac) + sizeof (uuid) + 9] = { 0 };
	int fd;

	/* MACID */
	if (serverid_mac(mac, 33) != 0)
		return -1;

	/* Motherboard UUID */
	if (serverid_uuid(uuid, 37) != 0)
		return -1;

	/* For N+ "data" containers, add suffix */
	char *daemon_index = getenv("DAEMON_INDEX");
	char suffix[8] = { 0 };
	if (daemon_index && *daemon_index != '0')
		sprintf(suffix, ":%s", daemon_index);

	/* Combine both values */
	sprintf((char *)input, "%s:%s%s", uuid, mac, suffix);

	/* Crypto Hash it to size 16 */
	if (crypto_hash(CRYPTO_BLAKE2B, 16, input, strlen((char *)input),
		    (uint8_t *)serverid) != 0)
		return -1;

	char s_serverid[SERVER_ID_MAXLEN+1] = { 0 };
	serverid_dump(s_serverid, SERVER_ID_MAXLEN);
	log_notice(lg, "SERVERID: %s suffix=%s",s_serverid, suffix);

	struct stat st;
	char srv_path[PATH_MAX];
	snprintf(srv_path, sizeof(srv_path), SERVERID_CACHE_FILE, nedge_path());

	if (stat(srv_path, &st) == 0) {
		char tmp[SERVER_ID_MAXLEN+1] = { 0 };

		/* read from serverid cache and compare */
		if ((fd = open(srv_path,
				    O_RDONLY, 0644)) < 0) {
			log_error(lg, "Cannot open SERVERID cache: %s",
			    strerror(errno));
			return -1;
		}

		if (read(fd, tmp, sizeof(tmp)) < 0) {
			log_error(lg, "Cannot read SERVERID from cache: %s",
			    strerror(errno));
			close(fd);
			return -1;
		}
		close(fd);

		if (strncmp(tmp, s_serverid, UINT128_BYTES * 2) == 0)
			return 0;

		uint128_fromhex(tmp, UINT128_BYTES * 2, serverid);
		log_warn(lg, "Inconsistant SERVERID from cache. Using: %s", tmp);
		return 0;
	}

	/* updating serverid cache too */
	if ((fd = open(srv_path,
			    O_WRONLY|O_CREAT, 0644)) < 0) {
		log_error(lg, "Cannot store SERVERID in cache: %s",
		    strerror(errno));
		return -1;
	}

	if (write(fd, s_serverid, UINT128_BYTES * 2) < 0) {
		log_error(lg, "Cannot write SERVERID to cache: %s",
		    strerror(errno));
		return -1;
	}
	close(fd);

	return 0;
}

void
serverid_dump(char *out, int len)
{
	uint128_dump(&this_server.id, out, len);
}


static char *
stripstr(char *str)
{
	int i, j;
	for (i = 0, j = 0; (str[j] = str[i]); j += (!isspace(str[i++])));
	return str;
}



#define	CPUINFO_BUFSIZE	(128*1024)

int
get_isaggregator(struct server_stat *srvr)
{
	char mbuf[CPUINFO_BUFSIZE];
	size_t readsz;
	char *matched;
	char auditd_file[PATH_MAX];
	snprintf(auditd_file, sizeof(auditd_file), "%s/etc/ccow/auditd.ini",
			nedge_path());

	FILE *fp = fopen(auditd_file, "rb");
	if (fp == NULL) {
		log_error(lg, "Unable to read: %s  to determine aggregator status",
				auditd_file);
		return -1;
	}

	readsz = fread(mbuf, 1, sizeof (mbuf), fp);

	if (ferror(fp)) {
		log_error(lg, "Error reading %s to determine aggregator status",
				auditd_file);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	if ((readsz == 0) || (readsz == sizeof (mbuf))) {
		log_error(lg, "Incorrect buffer size. Unable to determine"
				"aggregator status of this node");
		return -1;
	}

	mbuf[readsz] = '\0';
	matched = strstr(mbuf, "is_aggregator=");
	if (matched == NULL) {
		log_error(lg, "is_aggregator not found in %s", auditd_file);
		return -1;
	}
	sscanf(matched, "is_aggregator=%i", &srvr->isaggregator);

	return 0;
}

static int
get_srvr_info(struct server_stat *srvr)
{
	uv_cpu_info_t* cpus;
	uv_err_t err;
	int count;
	struct sysinfo info;
	unsigned long memused;

	if (sysinfo(&info) < 0) {
		log_error(lg, "Unable to to determine sysinfo");
		return -1;
	}

	err = uv_cpu_info(&cpus, &count);
	if (UV_OK != err.code) {
		log_error(lg, "Unable to to determine cpuinfo");
		return -1;
	}

	srvr->cpuspeed = cpus[0].speed;
	srvr->loadavg1 = info.loads[0];
	srvr->loadavg5 = info.loads[1];
	srvr->loadavg15 = info.loads[2];
        srvr->memtotal = (info.totalram * (unsigned long)info.mem_unit) / 1024UL;

        memused = info.totalram - info.freeram - info.bufferram;
	//Add other values in next statement to avoid int overflow on right hand side...
	srvr->swapused = info.totalswap - info.freeswap;
	memused += srvr->swapused;
	memused *= (unsigned long)info.mem_unit;
	srvr->memused = memused	/ 1024UL;
	srvr->numcpu = count;

	uv_free_cpu_info(cpus, count);
	return 0;
}

static int
get_containerid(struct server_stat *srvr)
{
	rtbuf_t *rb = NULL;
	int rc;

	rc = ccowd_read_file("/data/configs/ctr.json", &rb);
	if (rc != 0) {
		/*
		 * dynamic container - swarm, etc
		 *
		 * We assume that HOST_HOSTNAME is set and that HOSTNAME is
		 * points to actual containerid.
		 *
		 */
		char *host_hostname = getenv("HOST_HOSTNAME");
		if (!host_hostname) {
			srvr->containerid[0] = 0;
			return 0;
		}
		strcpy(&srvr->name[0], host_hostname);
		char *containerid = getenv("HOSTNAME");
		if (!containerid) {
			srvr->containerid[0] = 0;
			return 0;
		}
		strcpy(&srvr->containerid[0], containerid);
		char *daemon_index = getenv("DAEMON_INDEX");
		char suffix[8] = { 0 };
		if (daemon_index) {
			sprintf(suffix, "-%s", daemon_index);
			strcat(&srvr->containerid[0], suffix);
		}
		return 0;
	}

	/* static container has /data mounted */

	json_value *ctr_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	rtbuf_destroy(rb);
	if (!ctr_json) {
		log_error(lg, "Cannot parse ctr.json file %s -ENOENT",
			      "/data/configs/ctr.json");
		return -ENOENT;
	}

	size_t i;
	int found = 0;
	for (i = 0; i < ctr_json->u.object.length; i++) {
		if (found == 2)
			break;
		if (strcmp(ctr_json->u.object.values[i].name, "id") == 0) {
			strcpy(&srvr->containerid[0],
			    ctr_json->u.object.values[i].value->u.string.ptr);
			found++;
		} else if (strcmp(ctr_json->u.object.values[i].name,
			    "host_hostname") == 0) {
			strcpy(&srvr->name[0],
			    ctr_json->u.object.values[i].value->u.string.ptr);
			found++;
		}
	}

	json_value_free(ctr_json);
	return 0;
}

int
ccowd_rt_disks(int *numdisks)
{
	int nd=0;
	rtbuf_t *rb = NULL;
	int rc;

	char rd_path[PATH_MAX];
	snprintf(rd_path, sizeof(rd_path), "%s/etc/ccow/rt-rd.json", nedge_path());
	rc = ccowd_read_file(rd_path, &rb);
	if (rc != 0) {
		log_error(lg, "Cannot find file %s -ENOENT ",
				rd_path);
		return -ENOENT;
	}
	json_value *disk_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!disk_json) {
		log_error(lg, "Cannot parse file %s -EBADF ",
			rd_path);
		return -EBADF;
	}

	for (size_t j = 0; j < disk_json->u.object.length; j++) {
		char *namekey = disk_json->u.object.values[j].name;
		if (strcmp(namekey, "devices") == 0) {
			json_value *v = disk_json->u.object.values[j].value;
			for (size_t k = 0; k < v->u.object.length; k++) {
				char *diskname = v->u.object.values[j].name;
				nd++;
			}
		}
	}
	*numdisks = nd;
	json_value_free(disk_json);
	rtbuf_destroy(rb);

	return 0;
}


int
ccowd_lfs_disks(int *numdisks)
{
	int nd=0;
	rtbuf_t *rb = NULL;
	int rc;

	char lfs_path[PATH_MAX];
	snprintf(lfs_path, sizeof(lfs_path), "%s/etc/ccow/rt-lfs.json", nedge_path());
	rc = ccowd_read_file(lfs_path, &rb);
	if (rc != 0) {
		log_error(lg, "Cannot find file %s -ENOENT ",
				lfs_path);
		return -ENOENT;
	}
	json_value *fs_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);

	for (size_t j = 0; j < fs_json->u.object.length; j++) {
		char *namekey = fs_json->u.object.values[j].name;
		if (strcmp(namekey, "devices") == 0) {
			json_value *v = fs_json->u.object.values[j].value;
			for (size_t k = 0; k < v->u.object.length; k++) {
				char *fsname = v->u.object.values[j].name;
				nd++;
			}
		}
	}

	*numdisks = nd;
	json_value_free(fs_json);
	rtbuf_destroy(rb);

	return 0;
}

int
ccowd_kvs_disks(int *numdisks)
{
	int nd=0;
	rtbuf_t *rb = NULL;
	int rc;

	char kvs_path[PATH_MAX];
	snprintf(kvs_path, sizeof(kvs_path), "%s/etc/ccow/rt-kvs.json", nedge_path());

	rc = ccowd_read_file(kvs_path, &rb);
	if (rc != 0) {
		log_error(lg, "Cannot find file %s -ENOENT ",
				kvs_path);
		return -ENOENT;
	}
	json_value *fs_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);

	for (size_t j = 0; j < fs_json->u.object.length; j++) {
		char *namekey = fs_json->u.object.values[j].name;
		if (strcmp(namekey, "devices") == 0) {
			json_value *v = fs_json->u.object.values[j].value;
			for (size_t k = 0; k < v->u.object.length; k++) {
				char *fsname = v->u.object.values[j].name;
				nd++;
			}
		}
	}

	*numdisks = nd;
	json_value_free(fs_json);
	rtbuf_destroy(rb);

	return 0;
}

static int
get_server_numdisks(uint8_t *numdisks)
{
	rtbuf_t *rb = NULL;
	int rc;

	// read ccowd.json to find out if this is a rtlfs or rtrd
	char ccowd_path[PATH_MAX];
	snprintf(ccowd_path, sizeof(ccowd_path), "%s/etc/ccow/ccowd.json",
			nedge_path());

	rc = ccowd_read_file(ccowd_path, &rb);
	if (rc != 0) {
		log_error(lg, "Cannot find file %s -ENOENT ",
				ccowd_path);
		return -ENOENT;
	}
	json_value *disk_json = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	if (!disk_json) {
		log_error(lg, "Cannot parse file %s: JSON parse error",
				ccowd_path);
		json_value_free(disk_json);
		rtbuf_destroy(rb);
		return -ENOENT;
	}
	json_value *transport = NULL;
	for (size_t j = 0; j < disk_json->u.object.length; j++) {
		char *namekey = disk_json->u.object.values[j].name;
		if (strncmp(namekey, "transport", 9) == 0) {
			json_value *v = disk_json->u.object.values[j].value;
			if (v->type != json_array) {
				log_error(lg, "Syntax error: transport is "
						"not an array: -EINVAL");
				json_value_free(disk_json);
				rtbuf_destroy(rb);
				return -EINVAL;
			}
			transport = v;
		}
	}
	if (!transport || !transport->u.array.length) {
		log_error(lg, "Transport not found in %s -ENOENT",
				ccowd_path);
		json_value_free(disk_json);
		rtbuf_destroy(rb);
		return -EINVAL;
	}

	int nd=0;
	for (size_t j = 0; j < transport->u.array.length; ++j) {
		json_value *v = transport->u.array.values[j];
		if (v->type != json_string) {
			log_error(lg, "Config error: transport name is "
					"not a string: -EINVAL");
			json_value_free(disk_json);
			rtbuf_destroy(rb);
			return -EINVAL;
		}
		if (strcmp(v->u.string.ptr, "rtrd") == 0) {
			int rd_disks=0;
			rc = ccowd_rt_disks(&rd_disks);
			if (rc == 0) {
				nd += rd_disks;
			}
		}
		if (strcmp(v->u.string.ptr, "rtlfs") == 0) {
			int lfs_disks = 0;
			rc = ccowd_lfs_disks(&lfs_disks);
			if (rc == 0) {
				nd += lfs_disks;
			}
		}
		if (strcmp(v->u.string.ptr, "rtkvs") == 0) {
			int kvs_disks = 0;
			rc = ccowd_kvs_disks(&kvs_disks);
			if (rc == 0) {
				nd += kvs_disks;
			}
		}
	}

	*numdisks = nd;
	json_value_free(disk_json);
	rtbuf_destroy(rb);
	return 0;
}

static int
get_installtype(char *installtype, size_t buffer_size)
{
	struct stat st;
	char inst_type_path[PATH_MAX];
	snprintf(inst_type_path, sizeof(inst_type_path), INSTALL_TYPE_FILE,
			nedge_path());
	if (stat(inst_type_path, &st) != 0) {
		log_debug(lg, "Cannot access install type file %s: %s",
				inst_type_path, strerror(errno));
		strncpy(installtype, BAREMETAL_INSTALL_TYPE, buffer_size);
		return 0;
	}

	int fd = open(inst_type_path, O_RDONLY);
	if (fd == -1) {
		log_error(lg, "Cannot open install type file %s: %s",
				inst_type_path, strerror(errno));
		strncpy(installtype, BAREMETAL_INSTALL_TYPE, buffer_size);
		return 0;
	}


	int len = read(fd, installtype, buffer_size);
	if (len == -1) {
		close(fd);
		log_error(lg, "Cannot read install type file %s: %s",
				inst_type_path, strerror(errno));
		strncpy(installtype, BAREMETAL_INSTALL_TYPE, buffer_size);
		return 0;
	}

	close(fd);

	installtype[buffer_size - 1] = '\0';
	/* type is the first line of the file, so cut the line at the first
	 * line feed */
	char *lf_pos;
	if ((lf_pos=strchr(installtype, '\n')) != NULL)
		*lf_pos = '\0';

	return 0;
}

static struct server_stat *
server_stat_init(struct server_stat *srvr_stat)
{
	int rc;

	if (srvr_stat == NULL) {
		return NULL;
	}

	rc = get_isaggregator(srvr_stat);
	if (rc != 0) {
		log_error(lg, "Failed to identify if this is an aggregator");
		return NULL;
	}

	srvr_stat->zone = ccow_daemon->zone;

	rc = gethostname(srvr_stat->name, MAX_SERVER_NAME);
	if (rc != 0) {
		log_error(lg, "Failed to retrieve the hostname");
		return NULL;
	}

	rc = get_installtype(srvr_stat->installtype, MAX_INSTALLTYPE);
	if (rc != 0) {
		log_error(lg, "Failed to retrieve the install type");
		return NULL;
	}

	/* may override hostname */
	rc = get_containerid(srvr_stat);
	if (rc != 0) {
		log_error(lg, "Failed to identify container id");
		return NULL;
	}

	rc = get_srvr_info(srvr_stat);
	if (rc != 0) {
		log_error(lg, "Failed to determine the CPU speed");
		return NULL;
	}

	rc = get_server_numdisks(&srvr_stat->numdisks);
	if (rc != 0) {
		log_error(lg, "Failed to initialize numdisks");
		srvr_stat->numdisks = 0;
	}

	rc = serverid_init(&srvr_stat->id);
	if (rc != 0) {
		log_error(lg, "Failed to initialize serverid");
		return NULL;
	}

	return srvr_stat;
}

int
server_init()
{
	struct server_stat *srvr_stat = &this_server;

	srvr_stat = server_stat_init(srvr_stat);

	if (srvr_stat == NULL) {
		return -1;
	}

	return 0;
}

struct server_stat *
server_get_invalidate()
{
	(void) get_srvr_info(&this_server);
	return &this_server;
}

struct server_stat *
server_get()
{
	return &this_server;
}


void
server_dump(char *out, int len)
{
	struct server_stat *server = server_get();
	char s_serverid[SERVER_ID_MAXLEN];
	uint128_dump(&server->id, s_serverid, SERVER_ID_MAXLEN);
	assert((uint32_t)len >= MAX_SERVER_STR_LEN);
	snprintf(out, len, "name/ID: %s/%s cpu: %d/%0.0fMHz/%.2f "
	    "mem total/free: %ldMB/%ldMB",
	    server->name, s_serverid, server->numcpu, server->cpuspeed,
	    server->loadavg15/65536.0, server->memtotal/1024UL,
	    server->memused/1024UL);
}
