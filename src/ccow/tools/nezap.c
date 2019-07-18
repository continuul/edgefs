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
/*
 * nezap.c
 *
 *  Created on: Jun 3, 2018
 *      Author: root
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <dlfcn.h>

#include "ccowutil.h"
#include "reptrans.h"
#include "ccowd-impl.h"

struct rt_name_to_config {
	const char* name;
	const char* config_name;
} rt_configs[] = {
	{.name = "rtlfs", .config_name = "rt-lfs.json" },
	{.name = "rtrd", .config_name = "rt-rd.json" },
	{.name = "rtkvs", .config_name = "rt-kvs.json" },
};

static void
show_help() {
	printf("\nUsage: nezap [--do-as-i-say | --do-as-i-say-noio] [--disk=<name> [--plevel=<index>] [--journal]] [--group=<jname>]\n");
	printf("    --do-as-i-say       force execution\n");
	printf("    --do-as-i-say-noio  imitate zap procedure: no disk IO, disable bcache if needed\n");
	printf("    --disk              device name to be zapped\n");
	printf("    --plevel            device plevel to be zapped 1..plevelMax\n");
	printf("    --group             erase entire journal group\n");
	printf("    --journal           erase the journal-only\n");
	printf("    --restore-metaloc   don't zap, jut restore metaloc record (if applicable)\n");
	printf("    --destroy-gpt       destroy partition table of the main HDD (capacity mode only)\n\n");
}

int main(int argc, char* argv[]) {
	char path[PATH_MAX];
	char* transport = NULL;
	const char* transport_cfg = NULL;
	int err = 0;
	erase_opt_t eopts = { .name = NULL, .plevel = 0, .flags = 0};
	int force = 0;
	int option_index = 0;
	int c;
	int aux = 0;
	static struct option long_options[] = {
		{"help", 0, 0, 'h' },
		{"do-as-i-say", 0, 0, 'f' },
		{"do-as-i-say-noio", 0, 0, 'n' },
		{"disk", required_argument, 0, 'd' },
		{"journal", 0, 0, 'j' },
		{"plevel", required_argument, 0, 'p' },
		{"group", required_argument, 0, 'g' },
		{"restore-metaloc", 0, 0, 'r' },
		{"destroy-gpt", 0, 0, 'b' },
		{0, 0, 0, 0 }
	};
	while (1) {
		c = getopt_long(argc, argv, "hfnjg:d:prb:",long_options, &option_index);
		if (c < 0)
			break;
		switch (c) {
			case 'h':
				show_help();
				exit(0);
				break;

			case 'f':
				force = 1;
				break;

			case 'b':
				eopts.flags |= RD_REASE_FLAG_GPT_DESTROY;
				break;

			case 'n':
				force = 1;
				eopts.flags |= RD_ERASE_FLAG_NOIO;
				break;

			case 'd':
				if (optarg)
					eopts.name = je_strdup(optarg);
				break;


			case 'g':
				eopts.journal_group = je_strdup(optarg);
				break;

			case 'j':
				eopts.flags |= RD_ERASE_FLAG_WAL_ONLY;
				break;

			case 'r':
				eopts.flags |= RD_ERASE_FLAG_RESTORE_ML;
				break;

			case 'p':
				aux = sscanf(optarg,"%d", &eopts.plevel);
				if (!aux) {
					fprintf(stderr, "plevel must be integer");
					exit(-1);
				}
				break;

			default:
				exit(-1);
				break;
		}
	}

	if (eopts.name && eopts.journal_group) {
		fprintf(stderr, "A journal group cannot be specified along with a device name\n");
		exit(-1);
	}

	if ((eopts.flags & RD_ERASE_FLAG_WAL_ONLY) && eopts.journal_group) {
		fprintf(stderr, "A journal zapping is supported in a disk mode only\n");
		exit(-1);
	}
	if (eopts.plevel && eopts.journal_group) {
		fprintf(stderr, "Invalid plevel usage\n");
		exit(-1);
	}
	if (!eopts.name && (eopts.flags & RD_ERASE_FLAG_WAL_ONLY)) {
		fprintf(stderr, "Invalid journal usage\n");
		exit(-1);
	}

	if ((eopts.flags & RD_REASE_FLAG_GPT_DESTROY) &&
		(eopts.plevel || eopts.journal_group || !eopts.name)) {
		fprintf(stderr, "A GPT destroy option is valid for entire device "
			"erase mode and only if journal SSD isn't used\n");
		exit(-1);
	}
	if (!force) {
		char* line = NULL;
		printf("\n\tREADY TO ZAP DISKS? : ... [y|n]? ");
		size_t n = 0;
		int err = getline(&line, &n, stdin);
		if (err && err > 0 && line && (!strcmp(line, "Y\n") ||
			!strcmp(line, "y\n") || !strcmp(line, "YES\n")
			|| !strcmp(line, "yes\n"))) {
			force = 1;
		}
		if (line)
			free(line);
	}
	printf("\n");
	if (!force) {
		printf("\nZAP TERMINATED by User Request\n\n");
		exit(0);
	}

	lg = Logger_create("nezap");

	/*
	 * CCOW daemon configuration file is ccowd.json
	 */
	char conffile[PATH_MAX];
	snprintf(conffile, sizeof(conffile), CCOWD_CONF_DIR "/" CCOWD_CONF_FILE,
		nedge_path());


	/*
	 * Read configuration file
	 */
	rtbuf_t *rb = NULL;
	err = ccowd_read_file(conffile, &rb);
	if (err != 0) {
		fprintf(stderr, "ccowd.json read error %d\n", err);
		return -1;
	}

	/*
	 * Parse configuration file
	 */
	json_value* o = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	rtbuf_destroy(rb);
	if (!o) {
		fprintf(stderr, "ccowd.json parse error\n");
		return -2;
	}
	/* Look for reptrans name */

	for (size_t i = 0; i < o->u.object.length; i++) {
		if (strncmp(o->u.object.values[i].name, "transport", 9) == 0) {
			json_value* t = o->u.object.values[i].value;
			if (t->type != json_array) {
				fprintf(stderr, "ccowd.json: 'transport' ins't an array\n");
				err = -3;
				goto _exit;
			}
			if (t->u.array.length == 0) {
				fprintf(stderr, "ccowd.json: 'transport' array is void\n");
				err = -3;
				goto _exit;
			}
			if (t->u.array.values[0]->type != json_string) {
				fprintf(stderr, "ccowd.json: 'transport[0]' isn't a string\n");
				err = -4;
				goto _exit;
			}
			transport = je_strdup(t->u.array.values[0]->u.string.ptr);
			break;
		}
	}
	json_value_free(o);
	o = NULL;

	if (!transport) {
		fprintf(stderr, "Couldn't find a reptrans transport name\n");
		err = -5;
		goto _exit;
	}
	/* Looking for a reptrans configuration file */
	for (size_t i = 0; i < sizeof(rt_configs)/sizeof(rt_configs[0]); i++) {
		if (strcmp(rt_configs[i].name, transport) == 0) {
			transport_cfg = rt_configs[i].config_name;
			break;
		}
	}
	if (!transport_cfg) {
		fprintf(stderr, "Cannot find a reptrans config file name for transport %s", transport);
		err = -6;
		goto _exit;
	}
	/* Open and parse transport configuration file */
	sprintf(path, CCOWD_CONF_DIR "/%s", nedge_path(), transport_cfg);
	err = ccowd_read_file(path, &rb);
	if (err != 0) {
		fprintf(stderr, "%s read error %d\n", path, err);
		err = -7;
		goto _exit;
	}

	o = json_parse(rtbuf(rb, 0).base, rtbuf(rb, 0).len);
	rtbuf_destroy(rb);
	if (!o) {
		fprintf(stderr, "%s parse error\n", path);
		err = -8;
		goto _exit;
	}

	/* Opening transport */
	char lib_name[PATH_MAX];
	void *lib_handle = NULL;
	struct reptrans *rt = NULL;
	snprintf(lib_name, PATH_MAX, "lib%s.so", transport);
	lib_handle = dlopen(lib_name, RTLD_LAZY | RTLD_LOCAL);
	if (!lib_handle) {
		char *errstr = dlerror();
		fprintf(stderr, "Error loading the library %s: %s", lib_name, errstr);
		err = -11;
		goto _exit;
	}
	rt = dlsym(lib_handle, transport);
	if (!rt || !rt->erase) {
		fprintf(stderr, "the rt '%s' is incomplete\n",transport);
		err = -11;
		goto _exit;
	}
	assert(o);
	load_crypto_lib();
	char cmdline[2048] = {0};
	strcpy(cmdline, argv[0]);
	for (int i = 1; i < argc; i++) {
		sprintf(cmdline + strlen(cmdline)," %s", argv[i]);
	}
	QUEUE_INIT(&rt->devices);
	log_notice(lg, "Running %s", cmdline);
	err = rt->erase(rt, o, &eopts);
	dlclose(lib_handle);
	if (err) {
		switch(err) {

		case -EINVAL:
			fprintf(stderr, "Cannot erase a plevel in a hybrid configuration\n");
			break;

		case -ENFILE:
			fprintf(stderr, "The plevel value %d is out of bounds\n", eopts.plevel);
			break;

		case -ESPIPE:
			fprintf(stderr, "The journal groupt erase is supported only in hybrid configuration\n");
			break;

		case -EFAULT:
			fprintf(stderr, "This feature isn't supported by the transport driver\n");
			break;

		case -ENOANO:
			fprintf(stderr, "Disk or a partition isn't a block device\n");
			break;

		case -EBADRQC:
			fprintf(stderr, "Disk or a partition doesn't exist\n");
			break;

		default:
			fprintf(stderr, "Erase error %d\n", err);
			break;
		}
		err = -12;
	}

_exit:
	if (o)
		json_value_free(o);
	if (transport)
		je_free(transport);
	if (eopts.name)
		je_free((char*)eopts.name);
	return err;
}



