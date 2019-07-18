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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ccowutil.h"
#include "logger.h"
#include "config.h"
#include "ini.h"
#include "hll.h"

/**
 * Static pointer used for
 * while we are still parsing the configs
 * for a histogram.
 */
static char* histogram_section;
static histogram_config *in_progress;

/**
 * Default statsite_config values. Should create
 * filters that are about 300KB initially, and suited
 * to grow quickly.
 */
static const statsite_config DEFAULT_CONFIG = {
    8125,               // TCP defaults to 8125
    8125,               // UDP on 8125
    "ipc://%s/var/run/auditd.ipc", // Listen for IPC on default loc
    "tcp://*:10395",    // Listen on default PUB port
    "0.0.0.0",          // Listen on all IPv4 addresses
    false,              // Do not parse stdin by default
    0.01,               // Default 1% error
    "",                 // Do not pipe if not specified
    10,                 // Flush every 10 seconds
    0,                  // Do not use binary output by default
    NULL,               // Do not track number of messages received
    NULL,               // No histograms by default
    NULL,
    0.02,               // 2% goal uses precision 12
    12,                 // Set precision 12, 1.6% variance
    false,		// is_aggregator is set to false
    "",
    {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL},
    0
};

/**
 * Attempts to convert a string to a boolean,
 * and write the value out.
 * @arg val The string value
 * @arg result The destination for the result
 * @return 1 on success, 0 on error.
 */
static bool value_to_bool(const char *val, bool *result) {
    #define VAL_MATCH(param) (strcasecmp(param, val) == 0)

    if (VAL_MATCH("true") || VAL_MATCH("yes") || VAL_MATCH("1")) {
        *result = true;
        return 1;
    } else if (VAL_MATCH("false") || VAL_MATCH("no") || VAL_MATCH("0")) {
        *result = false;
        return 1;
    }
    return 0;
}

/**
 * Attempts to convert a string to an integer,
 * and write the value out.
 * @arg val The string value
 * @arg result The destination for the result
 * @return 1 on success, 0 on error.
 */
static int value_to_int(const char *val, int *result) {
    long res = strtol(val, NULL, 10);
    if (res == 0 && errno == EINVAL) {
        return 0;
    }
    *result = res;
    return 1;
}

/**
 * Attempts to convert a string to a double,
 * and write the value out.
 * @arg val The string value
 * @arg result The destination for the result
 * @return 1 on success, -EINVAL on error.
 */
static int value_to_double(const char *val, double *result) {
    return sscanf(val, "%lf", result);
}

/**
 * Callback function to use with INIH for parsing histogram configs
 * @arg user Opaque value. Actually a statsite_config pointer
 * @arg name The config name
 * @value = The config value
 * @return 1 on success
 */
static int histogram_callback(void* user, const char* section, const char* name, const char* value) {
    // Make sure we don't change sections with an unfinished config
    if (in_progress && strcasecmp(histogram_section, section)) {
        log_warn(lg, "Unfinished configuration for section: %s", histogram_section);
        return 0;
    }

    // Ensure we have something in progress
    if (!in_progress) {
        in_progress = je_calloc(1, sizeof(histogram_config));
        histogram_section = je_strdup(section);
    }

    // Cast the user handle
    statsite_config *config = (statsite_config*)user;

    // Switch on the config
    #define NAME_MATCH(param) (strcasecmp(param, name) == 0)

    int res = 1;
    if (NAME_MATCH("prefix")) {
        in_progress->parts |= 1;
        in_progress->prefix = je_strdup(value);

    } else if (NAME_MATCH("min")) {
        in_progress->parts |= 1 << 1;
        res = value_to_double(value, &in_progress->min_val);

    } else if (NAME_MATCH("max")) {
        in_progress->parts |= 1 << 2;
        res = value_to_double(value, &in_progress->max_val);

    } else if (NAME_MATCH("width")) {
        in_progress->parts |= 1 << 3;
        res = value_to_double(value, &in_progress->bin_width);

    } else {
        log_error(lg, "Unrecognized histogram config parameter: %s", value);
    }

    // Check if this config is done, and push into the list of configs
    if (in_progress->parts == 15) {
        in_progress->next = config->hist_configs;
        config->hist_configs = in_progress;
        in_progress = NULL;
        je_free(histogram_section);
        histogram_section = NULL;
    }
    return res;
}

/**
 * Callback function to use with INI-H.
 * @arg user Opaque user value. We use the statsite_config pointer
 * @arg section The INI seciton
 * @arg name The config name
 * @arg value The config value
 * @return 1 on success.
 */
static int config_callback(void* user, const char* section, const char* name, const char* value) {
    // Specially handle histogram sections
    if (strncasecmp("histogram", section, 9) == 0) {
        return histogram_callback(user, section, name, value);
    }

    // Ignore any non-statsite sections
    if (strcasecmp("statsite", section) != 0) {
        return 0;
    }

    // Cast the user handle
    statsite_config *config = (statsite_config*)user;

    // Switch on the config
    #define NAME_MATCH(param) (strcasecmp(param, name) == 0)

    // Handle the int cases
    if (NAME_MATCH("port")) {
        return value_to_int(value, &config->tcp_port);
    } else if (NAME_MATCH("tcp_port")) {
        return value_to_int(value, &config->tcp_port);
    } else if (NAME_MATCH("udp_port")) {
        return value_to_int(value, &config->udp_port);
    } else if (NAME_MATCH("flush_interval")) {
         return value_to_int(value, &config->flush_interval);
    } else if (NAME_MATCH("parse_stdin")) {
        return value_to_bool(value, &config->parse_stdin);
    } else if (NAME_MATCH("binary_stream")) {
        return value_to_bool(value, &config->binary_stream);

    // Handle the double cases
    } else if (NAME_MATCH("timer_eps")) {
        return value_to_double(value, &config->timer_eps);
    } else if (NAME_MATCH("set_eps")) {
        return value_to_double(value, &config->set_eps);

    // Copy the string values
    } else if (NAME_MATCH("stream_cmd")) {
        config->stream_cmd = je_strdup(value);
    } else if (NAME_MATCH("input_counter")) {
        config->input_counter = je_strdup(value);
    } else if (NAME_MATCH("bind_address")) {
        config->bind_address = je_strdup(value);
    } else if (NAME_MATCH("ipc_endpoint")) {
        config->ipc_endpoint = je_strdup(value);
    } else if (NAME_MATCH("pub_endpoint")) {
        config->pub_endpoint = je_strdup(value);
    } else if (NAME_MATCH("is_aggregator")) {
        return value_to_bool(value, &config->is_aggregator);
    // Unknown parameter?
    } else {
        // Log it, but ignore
        log_error(lg, "Unrecognized config parameter: %s", value);
    }

    // Success
    return 1;
}

/**
 * Initializes the configuration from a filename.
 * Reads the file as an INI configuration, and sets up the
 * config object.
 * @arg filename The name of the file to read. NULL for defaults.
 * @arg config Output. The config object to initialize.
 * @return 0 on success, negative on error.
 */
int config_from_filename(char *filename, statsite_config *config) {
    // Initialize to the default values
    memcpy(config, &DEFAULT_CONFIG, sizeof(statsite_config));
    char ipc_path[PATH_MAX];
    snprintf(ipc_path, sizeof(ipc_path), DEFAULT_CONFIG.ipc_endpoint, nedge_path());
    config->ipc_endpoint = ipc_path;

    // If there is no filename, return now
    if (filename == NULL)
        return 0;

    // Try to open the file
    int res = ini_parse(filename, config_callback, config);
    if (res == -1) {
        return -ENOENT;
    } else if (res) {
        log_error(lg, "Failed to parse config on line: %d", res);
        return -res;
    }

    // Check for an unfinished histogram
    if (in_progress) {
        log_warn(lg, "Unfinished configuration for section: %s", histogram_section);
        je_free(histogram_section);
        je_free(in_progress);
        in_progress = NULL;
        histogram_section = NULL;
    }

    return 0;
}

/**
 * Joins two strings as part of a path,
 * and adds a separating slash if needed.
 * @param path Part one of the path
 * @param part2 The second part of the path
 * @return A new string, that uses a malloc()'d buffer.
 */
char* join_path(char *path, char *part2) {
    // Check for the end slash
    int len = strlen(path);
    int has_end_slash = path[len-1] == '/';

    // Use the proper format string
    char *buf;
    int res;
    if (has_end_slash)
        res = asprintf(&buf, "%s%s", path, part2);
    else
        res = asprintf(&buf, "%s/%s", path, part2);
    assert(res != -1);

    // Return the new buffer
    return buf;
}

int sane_timer_eps(double eps) {
    if (eps>= 0.5) {
        log_error(lg,
               "Timer epsilon cannot be equal-to or greater than 0.5!");
        return 1;
    } else if (eps > 0.10) {
        log_warn(lg, "Timer epsilon very high!");
    } else if (eps<= 0) {
        log_error(lg,
               "Timer epsilon cannot less than or equal to 0!");
        return 1;
    }
    return 0;
}

int sane_flush_interval(int intv) {
    if (intv <= 0) {
        log_error(lg, "Flush interval cannot be negative!");
        return 1;
    } else if (intv >= 600)  {
        log_warn(lg,
               "Flushing set to be very infrequent! Increased risk of data loss.");
    }
    return 0;
}

int sane_histograms(histogram_config *config) {
    while (config) {
        // Ensure sane upper / lower
        if (config->min_val >= config->max_val) {
            log_error(lg, "Histogram min value must be less than max value! Prefix: %s", config->prefix);
            return 1;
        }

        // Check width
        if (config->bin_width <= 0) {
            log_error(lg, "Histogram bin width must be greater than 0! Prefix: %s", config->prefix);
            return 1;
        }

        // Compute the number of bins
        // We divide the range by bin width, and add 2 for the less than min, and more than max bins
        config->num_bins = ((config->max_val - config->min_val) / config->bin_width) + 2;

        // Check that the count is sane
        if (config->num_bins > 1024) {
            log_error(lg, "Histogram bin count cannot exceed 1024! Prefix: %s", config->prefix);
            return 1;
        } else if (config->num_bins > 128) {
            log_warn(lg, "Histogram bin count very high! Bins: %d Prefix: %s",
                    config->num_bins, config->prefix);
        }

        // Inspect the next config
        config = config->next;
    }
    return 0;
}

int sane_set_precision(double eps, unsigned char *precision) {
    // Determine the minimum precision needed
    int minimum_prec = hll_precision_for_error(eps);
    if (minimum_prec < 0) {
        log_error(lg, "Set epsilon must be between 0 and 1!");
        return 1;
    }

    // Check if the precision is within range
    if (minimum_prec < HLL_MIN_PRECISION) {
        log_error(lg, "Set epsilon too high!");
        return 1;
    }
    if (minimum_prec > HLL_MAX_PRECISION) {
        log_error(lg, "Set epsilon too low! Memory use would be prohibitive.");
        return 1;
    }

    // Warn if the precision is very high
    if (minimum_prec > 15) {
        log_warn(lg, "Set epsilon low, high precision could \
cause increased memory use.");
    }

    *precision = minimum_prec;
    return 0;
}

/**
 * Validates the configuration
 * @arg config The config object to validate.
 * @return 0 on success.
 */
int validate_config(statsite_config *config) {
    int res = 0;

    res |= sane_timer_eps(config->timer_eps);
    res |= sane_flush_interval(config->flush_interval);
    res |= sane_histograms(config->hist_configs);
    res |= sane_set_precision(config->set_eps, &config->set_precision);

    return res;
}

/**
 * Builds the radix tree for prefix matching
 * @return 0 on success
 */
int build_prefix_tree(statsite_config *config) {
    // Do nothing if there is no config
    if (!config->hist_configs)
        return 0;

    // Initialize the radix tree
    radix_tree *t = je_malloc(sizeof(radix_tree));
    config->histograms = t;
    int res = radix_init(t);
    if (res) goto ERR;

    // Add all the prefixes
    histogram_config *current = config->hist_configs;
    void **val;
    while (!res && current) {
        val = (void**)&current;
        res = radix_insert(t, current->prefix, val);
        current = current->next;
    }

    if (!res)
        return res;
ERR:
    je_free(t);
    return 1;
}

