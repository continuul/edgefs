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
#ifndef METRICS_H
#define METRICS_H
#include <stdint.h>
#include "config.h"
#include "radix.h"
#include "counter.h"
#include "timer.h"
#include "hashmap.h"
#include "set.h"

typedef enum {
    UNKNOWN,
    KEY_VAL,
    GAUGE,
    COUNTER,
    TIMER,
    SET,
    GAUGE_DELTA,
    CCOWD_PRIVATE
} metric_type;

typedef struct key_val {
    char *name;
    double val;
    struct key_val *next;
} key_val;

typedef struct {
    timer tm;

    // Support for histograms
    histogram_config *conf;
    unsigned int *counts;
} timer_hist;

typedef struct {
    double value;
} gauge_t;

typedef struct {
    hashmap *counters;  // Hashmap of name -> counter structs
    hashmap *timers;    // Map of name -> timer_hist structs
    hashmap *sets;      // Map of name -> set_t structs
    hashmap *gauges;    // Map of name -> guage struct
    key_val *kv_vals;   // Linked list of key_val structs
    double timer_eps;   // The error for timers
    double *quantiles;  // Array of quantiles
    uint32_t num_quants; // Size of quantiles array
    radix_tree *histograms; // Radix tree with histogram configs
    unsigned char set_precision; // The precision for sets
} metrics;

typedef int(*metric_callback)(void *data, metric_type type, char *name, void *val);

/**
 * Initializes the metrics struct.
 * @arg eps The maximum error for the quantiles
 * @arg quantiles A sorted array of double quantile values, must be on (0, 1)
 * @arg num_quants The number of entries in the quantiles array
 * @arg histograms A radix tree with histogram settings. This is not owned
 * by the metrics object. It is assumed to exist for the life of the metrics.
 * @arg set_precision The precision to use for sets
 * @return 0 on success.
 */
int init_metrics(double timer_eps, double *quantiles, uint32_t num_quants, radix_tree *histograms, unsigned char set_precision, metrics *m);

/**
 * Initializes the metrics struct, with preset configurations.
 * This defaults to a epsilon of 0.01 (1% error), and quantiles at
 * 0.5, 0.95, and 0.99.
 * @return 0 on success.
 */
int init_metrics_defaults(metrics *m);

/**
 * Destroys the metrics
 * @return 0 on success.
 */
int destroy_metrics(metrics *m);

/**
 * Adds a new sampled value
 * arg type The type of the metrics
 * @arg name The name of the metric
 * @arg val The sample to add
 * @return 0 on success.
 */
int metrics_add_sample(metrics *m, metric_type type, char *name, double val);

/**
 * Adds a value to a named set.
 * @arg name The name of the set
 * @arg value The value to add
 * @return 0 on success
 */
int metrics_set_update(metrics *m, char *name, char *value);

/**
 * Iterates through all the metrics
 * @arg m The metrics to iterate through
 * @arg data Opaque handle passed to the callback
 * @arg cb A callback function to invoke. Called with a type, name
 * and value. If the type is KEY_VAL, it is a pointer to a double,
 * for a counter, it is a pointer to a counter, and for a timer it is
 * a pointer to a timer. Return non-zero to stop iteration.
 * @return 0 on success.
 */
int metrics_iter(metrics *m, void *data, metric_callback cb);

#endif
