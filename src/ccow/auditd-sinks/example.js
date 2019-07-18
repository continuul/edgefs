#!/usr/bin/env node
/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 *
 * Audit service sink: example sink
 */
var fs = require('fs');

try {
    var NEDGE_HOME = process.env["NEDGE_HOME"];
    if (!fs.existsSync(NEDGE_HOME)) {
        console.error("NEDGE_HOME not found");
        process.exit(1);
    }

    var NMF_HOME = fs.existsSync(NEDGE_HOME + "/src/nmf") ?
        NEDGE_HOME + "/src/nmf" : NEDGE_HOME + "/nmf";
} catch (e) {
    console.error(e.toString());
    process.exit(1);
}

var ccow = require(NMF_HOME + "/lib/nef/ccow");
var async = require(NMF_HOME + "/node_modules/async");
var byline = require(NMF_HOME + "/node_modules/byline");

global.__ = function (msg) { return msg; };
global.NEFError = function (code) { return code; };

var lines = [];
var stream = byline.createStream(process.stdin);
stream.on('data', function (line) {
    lines.push(line);
});
process.stdin.on('end', function () {
    lines.forEach(function (line) {
        //console.log("metric:", line.toString());
    });
    process.exit(0);
});
