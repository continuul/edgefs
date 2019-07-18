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
#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>
#include <syslog.h>
#include <stdbool.h>
#include "radix.h"


// Represents the configuration of a histogram
typedef struct histogram_config {
    char *prefix;
    double min_val;
    double max_val;
    double bin_width;
    int num_bins;
    struct histogram_config *next;
    char parts;
} histogram_config;

#define MAX_SERVERID_STR 64
#define MAX_SERVER_IF 16
/**
 * Stores our configuration
 */
typedef struct {
    int tcp_port;
    int udp_port;
    char *ipc_endpoint;
    char *pub_endpoint;
    char *bind_address;
    bool parse_stdin;
    double timer_eps;
    char *stream_cmd;
    int flush_interval;
    bool binary_stream;
    char *input_counter;
    histogram_config *hist_configs;
    radix_tree *histograms;
    double set_eps;
    unsigned char set_precision;
    bool is_aggregator;
    char serveridstr[MAX_SERVERID_STR];
    char *if_name[MAX_SERVER_IF];
    int if_count;
} statsite_config;

/**
 * Initializes the configuration from a filename.
 * Reads the file as an INI configuration, and sets up the
 * config object.
 * @arg filename The name of the file to read. NULL for defaults.
 * @arg config Output. The config object to initialize.
 * @return 0 on success, negative on error.
 */
int config_from_filename(char *filename, statsite_config *config);

/**
 * Validates the configuration
 * @arg config The config object to validate.
 * @return 0 on success, negative on error.
 */
int validate_config(statsite_config *config);

// Configuration validation methods
int sane_timer_eps(double eps);
int sane_flush_interval(int intv);
int sane_histograms(histogram_config *config);
int sane_set_precision(double eps, unsigned char *precision);

/**
 * Joins two strings as part of a path,
 * and adds a separating slash if needed.
 * @param path Part one of the path
 * @param part2 The second part of the path
 * @return A new string, that uses a malloc()'d buffer.
 */
char* join_path(char *path, char *part2);

/**
 * Builds the radix tree for prefix matching
 * @return 0 on success
 */
int build_prefix_tree(statsite_config *config);

#endif
