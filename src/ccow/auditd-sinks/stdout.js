#!/usr/bin/env node
/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 *
 * LineStream came from node-byline (C) 2011-2013 John Hewson (BSD)
 *
 * Audit service sink: CCOW and other background jobs mixer
 */
var util = require("util");

process.stdin.on('data', function (data) {
    util.print(data.toString());
});
process.stdin.on('end', function () {
    process.exit(0);
});
