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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/timerfd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <uv.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "ccowutil.h"
#include "crypto.h"
#include "logger.h"
#include <dlfcn.h>

#include "../libcrypto/libblake2/blake2dyn.h"

#define SERVERID_MAC_CACHE_FILE "%s/var/run/macid.cache"
#define SERVER_ID_MAXLEN (UINT128_BYTES * 2 + 1)
#define SERVERID_CACHE_FILE "%s/var/run/serverid.cache"


#ifdef USE_JE_MALLOC
const char *je_malloc_conf = "purge:decay,lg_dirty_mult:6,lg_tcache_max:17,lg_chunk:22";
#endif

#if defined(CCOW_EI_DIV)
int ccow_ei_enabled = 0;
#endif

uint32_t global_seed = 2166136261UL;
uint128_t uint128_null = {0, 0};
uint256_t uint256_null = {{0, 0}, {0, 0}};
uint512_t uint512_null = {{{0, 0}, {0, 0}}, {{0, 0}, {0, 0}}};
int ccow_embedded = -1;

#ifdef CCOW_USE_TIMERFD
int
uv_hpt_timer_init(uv_loop_t *loop, UV_HPT_TIMER_T *req)
{
	int err;

	int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timerfd == -1)
		return -errno;

	uv_poll_init(loop, req, timerfd);
	return timerfd;
}

int
uv_hpt_timer_start(int timerfd, UV_HPT_TIMER_T *req, uint64_t delay_us,
    uv_poll_cb poll_cb)
{
	int err;

	struct itimerspec timspec;
	memset(&timspec, 0, sizeof (timspec));
	timspec.it_value.tv_sec = delay_us / 1000000;
	timspec.it_value.tv_nsec = (delay_us % 1000000) * 1000;
	err = timerfd_settime(timerfd, 0, &timspec, 0);
	if (err)
		return -errno;

	uv_poll_start(req, UV_READABLE, poll_cb);
	return 0;
}

void
uv_hpt_timer_stop(int timerfd, UV_HPT_TIMER_T *req)
{
	struct itimerspec timspec;
	memset(&timspec, 0, sizeof (timspec));

	assert(timerfd);
	timerfd_settime(timerfd, 0, &timspec, NULL);

	assert(uv_is_active((uv_handle_t *)req));
	uv_poll_stop(req);
}

void
uv_hpt_timer_close(int timerfd, UV_HPT_TIMER_T *req)
{
	assert(req);
	if (uv_is_active((uv_handle_t *)req))
		uv_poll_stop(req);

	assert(timerfd);
	close(timerfd);
}
#else
int
uv_hpt_timer_init(uv_loop_t *loop, UV_HPT_TIMER_T *req)
{
	uv_timer_init(loop, (uv_timer_t *)req);
	return 1;
}

int
uv_hpt_timer_start(int timerfd, UV_HPT_TIMER_T *req, uint64_t delay_us,
    uv_timer_cb timer_cb)
{
	assert(timerfd);
	return uv_timer_start((uv_timer_t *)req, timer_cb, delay_us / 1000, 0);
}

void
uv_hpt_timer_stop(int timerfd, UV_HPT_TIMER_T *req)
{
	uv_timer_stop((uv_timer_t *)req);
}

void
uv_hpt_timer_close(int timerfd, UV_HPT_TIMER_T *req)
{
	assert(timerfd);
}
#endif

int
find_ipv6local(char *ifname, char *ip6addr)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	int err;

	if (getifaddrs(&ifaddr) == -1)
		return -errno;

	/* Walk through linked list, maintaining head pointer so we
	 * can free list later */
	char hbuf[NI_MAXHOST];
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		family = ifa->ifa_addr->sa_family;
		if (family != AF_INET6)
			continue;

		err = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
		    hbuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (err != 0) {
			log_error(lg, "getnameinfo() failed: %s",
			    gai_strerror(err));
			freeifaddrs(ifaddr);
			return err;
		}
		if ((strlen(ifname) >= 3 && memcmp(ifname, "rep", 3) == 0) ||
		    (strlen(ifname) >= 11 && memcmp(ifname, "nedge_repgw", 11) == 0) ||
		    (strlen(ifname) >= 9 && memcmp(ifname, "nedge_rep", 9) == 0)) {
			if (memcmp(hbuf, "fd00:", 5) != 0) {
				log_warn(lg, "Incorrect configuration for %s"
				    " could not find address starting fd00",
				    ifname);
				if (strlen(ifname) >= 3 && memcmp(ifname, "rep", 3) == 0) {
					/* do not fatal on virtual networks! */
					log_warn(lg, "Fallback using %s with fe80:",
					    ifname);
				    break;
				}
				continue;
			}
			break;
		}
		if (memcmp(hbuf, "fe80:", 5) != 0)
			continue;
		break;
	}

	freeifaddrs(ifaddr);
	strncpy(ip6addr, hbuf, INET6_ADDRSTRLEN);
	return 0;
}

int
getifname(char *ipaddr, char *ifname)
{
	struct ifaddrs *addrs, *iap;
	struct sockaddr_in *sa;
	char buf[INET6_ADDRSTRLEN + IFNAMSIZ];
	int err;

	err = getifaddrs(&addrs);
	if (err)
		return err;
	for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *)(iap->ifa_addr);
			inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
			if (!strcmp(ipaddr, buf)) {
				strcpy(ifname, iap->ifa_name);
				break;
			}
		}
	}
	freeifaddrs(addrs);
	return 0;
}

int
ethtool_info(const char *ifname, uint32_t *speed_mbits, uint8_t *duplex,
    uint8_t *link_status, int *mtu)
{
	int sock;
	struct ifreq ifr;
	struct ethtool_cmd edata_cmd;
	int err;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&edata_cmd;

	edata_cmd.cmd = ETHTOOL_GSET;

	err = ioctl(sock, SIOCETHTOOL, &ifr);
	if (err < 0) {
		/* assume paravirt environments */
		*speed_mbits = 10000;
		*duplex = 1;
	} else {
		*speed_mbits = (uint32_t)ethtool_cmd_speed(&edata_cmd);
		*duplex = (uint8_t)edata_cmd.duplex;
	}

	struct ethtool_value edata_value;

	edata_value.data = 0;
	edata_value.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (caddr_t)&edata_value;
	err = ioctl(sock, SIOCETHTOOL, &ifr);
	if (err < 0) {
		if (errno == EOPNOTSUPP) {
			/* This is a workaound for a Linux dummy interface */
			edata_value.data = 1;
		} else {
			close(sock);
			log_error(lg, "Cannot get %s link status (%d): %s\n", ifname,
				errno, strerror(errno));
			return -errno;
		}
	}
	*link_status = (uint8_t)edata_value.data;

	err = ioctl(sock, SIOCGIFMTU, &ifr);
	if (err < 0) {
		close(sock);
		log_error(lg, "Cannot get %s mtu (%d): %s\n", ifname,
		    errno, strerror(errno));
		return -errno;
	}
	*mtu = ifr.ifr_mtu;

	close(sock);
	return 0;
}



void
FNV_hash(const void *key, int length, uint32_t seed, void *out)
{
	unsigned char* p = (unsigned char *)key;
	unsigned long int h = seed;
	int i;

	for(i = 0; i < length; i++)
		h = (h * 16777619) ^ p[i] ;

	*(uint32_t *)out = h;
}


void
tiny_hash(const void *key, int len, void *out)
{
	FNV_hash(key, len, global_seed, out);
}

static inline uint64_t
rotl64(uint64_t x, int8_t r){
	return (x << r) | (x >> (64 - r));
}

#define ROTL64(x,y)	rotl64(x,y)
#define BIG_CONSTANT(x) (x##LLU)

static inline uint64_t
getblock(const uint64_t *p, int i) {
	return p[i];
}

static inline uint64_t
fmix( uint64_t k )
{
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;

	return k;
}

void
MurmurHash3_x64_128(const void *key, const int len, const uint32_t seed,
    void *out)
{
	const uint8_t * data = (const uint8_t*)key;
	const int nblocks = len / 16;

	uint64_t h1 = seed;
	uint64_t h2 = seed;

	uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	//----------
	// body

	const uint64_t * blocks = (const uint64_t *)(data);

	for(int i = 0; i < nblocks; i++)
	{
		uint64_t k1 = getblock(blocks,i*2+0);
		uint64_t k2 = getblock(blocks,i*2+1);

		k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;

		h1 = ROTL64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;

		k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

		h2 = ROTL64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5;
	}

	//----------
	// tail

	const uint8_t * tail = (const uint8_t*)(data + nblocks*16);

	uint64_t k1 = 0;
	uint64_t k2 = 0;

	switch(len & 15)
	{
	case 15: k2 ^= ((uint64_t)tail[14]) << 48;
	case 14: k2 ^= ((uint64_t)tail[13]) << 40;
	case 13: k2 ^= ((uint64_t)tail[12]) << 32;
	case 12: k2 ^= ((uint64_t)tail[11]) << 24;
	case 11: k2 ^= ((uint64_t)tail[10]) << 16;
	case 10: k2 ^= ((uint64_t)tail[ 9]) << 8;
	case  9: k2 ^= ((uint64_t)tail[ 8]) << 0;
		 k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

	case  8: k1 ^= ((uint64_t)tail[ 7]) << 56;
	case  7: k1 ^= ((uint64_t)tail[ 6]) << 48;
	case  6: k1 ^= ((uint64_t)tail[ 5]) << 40;
	case  5: k1 ^= ((uint64_t)tail[ 4]) << 32;
	case  4: k1 ^= ((uint64_t)tail[ 3]) << 24;
	case  3: k1 ^= ((uint64_t)tail[ 2]) << 16;
	case  2: k1 ^= ((uint64_t)tail[ 1]) << 8;
	case  1: k1 ^= ((uint64_t)tail[ 0]) << 0;
		 k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= len; h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix(h1);
	h2 = fmix(h2);

	h1 += h2;
	h2 += h1;

	((uint64_t*)out)[0] = h1;
	((uint64_t*)out)[1] = h2;
}

void
uint64_to_hex(uint64_t n, char *s)
{
	const char hex_lookup[] = "0123456789ABCDEF";
	register int len = 0;
	uint64_t tmp = n;

	if (!tmp)
		len = 1;
	else {
		for (; tmp; tmp >>= 4)
			++len;
	}

	/* padding */
	int off = 16 - len;
	s[16] = '\0';
	for (int i = 0; i < off; i++)
		s[i] = '0';

	for (--len; len >= 0; n >>= 4, --len)
		s[off + len] = hex_lookup[n & 0xf];
}

static char json_file_buf[JSON_BUF_PAGE_SZ];

/* Stage the buffer if it's less than JSON_BUF_PAGE_SZ else flush it */
void
json_buf_put(FILE *fd, char *buf)
{
	size_t filebuf_len;
	size_t buflen;

	if (buf == NULL) {
		log_error(lg, "NULL json buffer pointer in flexhash\n");
		return;
	}

	filebuf_len = strlen(json_file_buf);
	buflen = strlen(buf);

	if (buflen > JSON_BUF_PAGE_SZ - 1 ||
	    filebuf_len + buflen > JSON_BUF_PAGE_SZ - 1) {
		fprintf(fd, "%s%s", json_file_buf, buf);
		json_file_buf[0] = '\0'; /* reset buffer after flush */
	} else
		strcat(json_file_buf, buf);
}

void
 json_buf_flush(FILE *fd)
{
	fprintf(fd, "%s", json_file_buf);
	fflush(fd);
	json_file_buf[0] = '\0';
}

void
json_file_buf_prepare()
{
	json_file_buf[0] = '\0';
}

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
	;

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
	uint128_dump(serverid, s_serverid, SERVER_ID_MAXLEN);
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
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

#define SRCDIR_PREFIX "/src/ccow/src/libcrypto/libblake2/.libs"
#define OPT_PREFIX "/lib"
#define CRYPTO_NAME_DEFAULT "libblake2_simd.so"
#define CRYPTO_NAME_SSE41 "libblake2_sse41.so"
#define CRYPTO_NAME_AVX "libblake2_avx.so"
#define CRYPTO_NAME_AVX2 "libblake2_avx2.so"

void *crypto_lib_handle;

void unload_crypto_lib() {
	int err = dlclose(crypto_lib_handle);
	log_info(lg, "Unloading crypto library, err: %d", err);
	return;
}

void load_crypto_lib()
{
	char cryptofile[PATH_MAX];
	struct stat srcdir;

	snprintf(cryptofile, sizeof(cryptofile), "%s/src/ccow", nedge_path());
	int is_srcdir = stat(cryptofile, &srcdir) == 0 && S_ISDIR(srcdir.st_mode);

	if (__builtin_cpu_supports("avx2")) {
		snprintf(cryptofile, sizeof(cryptofile), "%s/%s/%s", nedge_path(),
			is_srcdir ? SRCDIR_PREFIX : OPT_PREFIX, CRYPTO_NAME_AVX2);
	} else if (__builtin_cpu_supports("avx")) {
		snprintf(cryptofile, sizeof(cryptofile), "%s/%s/%s", nedge_path(),
			is_srcdir ? SRCDIR_PREFIX : OPT_PREFIX, CRYPTO_NAME_AVX);
	} else if (__builtin_cpu_supports("sse4.1")) {
		snprintf(cryptofile, sizeof(cryptofile), "%s/%s/%s", nedge_path(),
			is_srcdir ? SRCDIR_PREFIX : OPT_PREFIX, CRYPTO_NAME_SSE41);
	} else if (__builtin_cpu_supports("sse2")) {
		snprintf(cryptofile, sizeof(cryptofile), "%s/%s/%s", nedge_path(),
			is_srcdir ? SRCDIR_PREFIX : OPT_PREFIX, CRYPTO_NAME_DEFAULT);
	} else {
		log_notice(lg, "Unable to detect crypto libs, and load them, fatal.");
		exit(-1);
	}
	log_info(lg, "Loading %s", cryptofile);
	crypto_lib_handle = dlopen(cryptofile, RTLD_NOW);
	if (!crypto_lib_handle) {
		log_notice(lg, "Unable to load crypto lib: %s\n", dlerror());
		exit(EXIT_FAILURE);
	}
	*(void **) (&blake2b_init_dyn) = dlsym(crypto_lib_handle, "blake2b_init");
	*(void **) (&blake2b_update_dyn) = dlsym(crypto_lib_handle, "blake2b_update");
	*(void **) (&blake2b_final_dyn) = dlsym(crypto_lib_handle, "blake2b_final");
	*(void **) (&blake2b_dyn) = dlsym(crypto_lib_handle, "blake2b");
	*(void **) (&blake2bp_init_dyn) = dlsym(crypto_lib_handle, "blake2bp_init");
	*(void **) (&blake2bp_update_dyn) = dlsym(crypto_lib_handle, "blake2bp_update");
	*(void **) (&blake2bp_final_dyn) = dlsym(crypto_lib_handle, "blake2bp_final");
	*(void **) (&blake2bp_dyn) = dlsym(crypto_lib_handle, "blake2bp");

	return;
}

/* We do not support SafeNet/USB HASP activation, define symbols */
void hasp_free() {}
void hasp_get_info() {}

uint64_t nondecreasing_get_realtime_ns()
{
	static uint64_t ts_prev;

	/** We must be sure about value of ts_prev */
	__asm__ volatile("" : : : "memory");

	uint64_t ts = get_realtime_ns();

	if(unlikely(!ts_prev)) {
		ts_prev = ts;
		ts ++; //< We definitely spent here more than 1 ns :-)
	}

	/* did time go backwards?  If so, make time sit still this time,
	 * and change our adjustment factor so we still see forward deltas. */
	if (unlikely(ts <= ts_prev))
	{
		ts = __atomic_add_fetch(&ts_prev, 1, __ATOMIC_SEQ_CST);
	} else /* time went forward or stayed put, so remember it. */
	{
		ts_prev = ts;
	}

	return ts;
}

int
pidfile_verify(char *pidfile, char *progname)
{
	int pid;
	char cmdfile[PATH_MAX];
	char buf[PATH_MAX];
	struct stat st;

	if (stat(pidfile, &st) != 0)
		return 0;

	FILE *fpid = fopen(pidfile, "r");
	if (!fpid) {
		fprintf(stderr, "File %s open error!\n", pidfile);
		return 1;
	}
	int err = fscanf(fpid, "%d", &pid);
	if (err <= 0 || errno != 0) {
		fprintf(stderr, "Pid read error %s: %d!\n", cmdfile, errno);
		return 1;
	}
	fclose(fpid);

	sprintf(cmdfile, "/proc/%d/cmdline", pid);
	if (stat(cmdfile, &st) == 0) {
		FILE *f = fopen(cmdfile, "r");
		if (!f) {
			fprintf(stderr, "File %s open error!\n", cmdfile);
			return 1;
		}
		err = fscanf(f, "%s", buf);
		if (err <= 0 || errno != 0) {
			fprintf(stderr, "Pid read error %s: %d!\n", cmdfile, errno);
			return 1;
		}
		fclose(f);
		if (strstr(buf, progname)) {
			fprintf(stderr, "Daemon already running!\n");
			return 1;
		}
	}
	unlink(pidfile);
	return 0;
}

int
ccow_calc_nhid(const char* cid, const char* tid, const char* bid,
	const char* oid, uint512_t* nhid) {
	int err = 0;
	crypto_state_t S;
	err = crypto_init_with_type(&S, HASH_TYPE_DEFAULT);
	if (err) {
		fprintf(stderr, "crypto_init: object hash id %d\n", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)cid, strlen(cid) + 1);
	if (err) {
		fprintf(stderr, "crypto_update: object hash id %d\n", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)tid, strlen(tid) + 1);
	if (err) {
		fprintf(stderr, "crypto_update: object hash id %d\n", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)bid, strlen(bid) + 1);
	if (err) {
		fprintf(stderr, "crypto_update: object hash id %d\n", err);
		return err;
	}

	err = crypto_update(&S, (uint8_t *)oid, strlen(oid) + 1);
	if (err) {
		fprintf(stderr, "crypto_update: object hash id %d\n", err);
		return err;
	}

	crypto_final(&S, (uint8_t *)nhid);
	if (err)
		fprintf(stderr, "crypto_final: object hash id %d\n", err);
	return err;
}
