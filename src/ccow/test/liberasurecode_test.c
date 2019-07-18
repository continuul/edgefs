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
#include <stdlib.h>
#include <string.h>
#include <liberasurecode/erasurecode.h>
#include <liberasurecode/erasurecode_helpers.h>

int main(int argc, const char** argv) {
	int rc = 0;
	struct ec_args args = {.k = 5,
	    .m = 3,
	    .hd = 3,
	    .ct = CHKSUM_NONE};

	if (argc == 3) {
		int k = strtol(argv[1], NULL, 10);
		int m = strtol(argv[2], NULL, 10);
		if (k < 3 || m <= 0 || k > 20 || m > 20 || m >= k) {
			fprintf(stderr, "Usage: liberasurecode_test [<m> <k>]\n\t "
					"m - number of original fragments\n\t "
					"n - number of parity fragments\n");
			exit(-1);
		}
		args.k = k;
		args.m = m;
	}

	size_t orig_size = args.k * 4*1024*1024;
	char* orig_data = malloc(orig_size);
	int* fill_buff = (int*) orig_data;
	for (size_t n = 0; n < orig_size/sizeof(int); n++) {
		fill_buff[n] = rand();
	}

	ec_backend_id_t backend_ids[] = {
			EC_BACKEND_ISA_L_RS_VAND,
			EC_BACKEND_JERASURE_RS_CAUCHY,
			EC_BACKEND_JERASURE_RS_VAND,
			EC_BACKEND_INTERNAL_RS_VAND};

	const char* backend_ids_name[] = {
			"EC_BACKEND_ISA_L_RS_VAND",
			"EC_BACKEND_JERASURE_RS_CAUCHY",
			"EC_BACKEND_JERASURE_RS_VAND",
			"EC_BACKEND_INTERNAL_RS_VAND"
	};

	for (size_t bindex = 0;
		bindex < sizeof(backend_ids)/sizeof(backend_ids[0]);
		bindex++) {
		printf("Testing erasure code backed %s..", backend_ids_name[bindex]);
		int desc = liberasurecode_instance_create(backend_ids[bindex], &args);
		if (!desc) {
			printf("couldn't create encoder instance\n");
			rc = -1;
			continue;
		}
		/**
		 * Encode the original data.
		 * The data will be split into k+m fragments.
		 * 0..k-1 fragments expected to hold chunks from original data
		 * k..m-1 are parity chunks
		 * Each fragment includes a header
		 */
		char** encoded_data = NULL, **encoded_parity = NULL;
		uint64_t fragment_len = 0;
		int err = liberasurecode_encode(desc, orig_data, orig_size,
		        &encoded_data, &encoded_parity, &fragment_len);
		if (err) {
			printf("error during chunk encode: %d\n", err);
			rc = -2;
			continue;
		}
		/* Test #1. Content length of the encoded data has to
		 * match original size
		 **/
		if (orig_size != args.k*(fragment_len - sizeof(fragment_header_t))) {
			liberasurecode_encode_cleanup(desc, encoded_data, encoded_parity);
			printf("total encoded content size doesn't match original chunk "
					"size: %lu vs %lu\n", orig_size,
					args.k*(fragment_len - sizeof(fragment_header_t)));
			rc = -3;
			continue;
		}
		/* Test #2. Restore original data from 0..k-1 fragments */
		char* restored_data = malloc(orig_size);
		char* current = restored_data;
		for (int i = 0; i < args.k; i++) {
			memcpy(current, encoded_data[i] + sizeof(fragment_header_t),
				fragment_len - sizeof(fragment_header_t));
			current += fragment_len - sizeof(fragment_header_t);
		}
		if (memcmp(orig_data, restored_data, orig_size) != 0) {
			free(restored_data);
			liberasurecode_encode_cleanup(desc, encoded_data, encoded_parity);
			printf("the encoded content isn't equal original one\n");
			rc = -4;
			continue;
		}
		free(restored_data);
		/* Test 3. Try to restore fragments
		 * Reconstruction is done using k-m original fragments
		 * and m parity fragments
		 **/
		char* restore_from[args.k];
		memcpy(&restore_from[0], encoded_data, (args.k-args.m)*sizeof(char*));
		memcpy(&restore_from[args.k-args.m], encoded_parity,
			args.m*sizeof(char*));
		char* out_fragment = calloc(1, fragment_len);
		for(int n = args.k-args.m; n < args.k; n++) {
			err = liberasurecode_reconstruct_fragment(desc, restore_from,
				args.k, fragment_len, n, out_fragment);

			if (err) {
				free(out_fragment);
				liberasurecode_encode_cleanup(desc, encoded_data,
					encoded_parity);
				printf("liberasurecode_reconstruct_fragment() "
					"returned error: %d\n", err);
				rc = -5;
				break;
			}

			if (memcmp(encoded_data[n], out_fragment, fragment_len) != 0) {
				printf("A reconstructed fragment %d doesn't "
					"match encoded one\n", n);
				rc = -6;
				break;
			}
		}

		liberasurecode_encode_cleanup(desc, encoded_data, encoded_parity);
		free(out_fragment);
		liberasurecode_instance_destroy(desc);
		printf("done\n");
	}
	free(orig_data);
	exit(rc);
}
