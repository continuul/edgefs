#!/usr/bin/env node
/*
 * Use is subject of licensing terms
 * Nexenta Systems, Inc.
 *
 * LineStream came from node-byline (C) 2011-2013 John Hewson (BSD)
 *
 * Audit service sink: CCOW and other background jobs mixer
 */
var fs = require('fs');
var path = require('path');
var stream = require('stream');
var util = require('util');
var cluster = require('cluster');
var spawn = require('child_process').spawn;

var isAggr = 0;
try {
    var NEDGE_HOME = process.env["NEDGE_HOME"];
    if (!fs.existsSync(NEDGE_HOME)) {
        console.error("MIXER-ERROR:", "NEDGE_HOME not found");
        process.exit(1);
    }

    var NMF_HOME = fs.existsSync(NEDGE_HOME + "/src/nmf") ?
        NEDGE_HOME + "/src/nmf" : NEDGE_HOME + "/nmf";

    var CCOW_AUDITD_INI = NEDGE_HOME + '/etc/ccow/auditd.ini';
    var options = {
        path: true,
        variables: true,
        sections: true,
        namespaces: false
    };
    var aas_conf;
    var properties = require(NMF_HOME + "/node_modules/properties");
    properties.parse(CCOW_AUDITD_INI, options, function (err, p) {
        aas_conf = p.statsite;
        isAggr = aas_conf.is_aggregator;
    });

} catch (e) {
    console.error("MIXER-ERROR:", e.toString());
    process.exit(1);
}

var async = require(NMF_HOME + "/node_modules/async");
var byline = require(NMF_HOME + "/node_modules/byline");

if (cluster.isMaster) {
    var children = [];
    var CCOW_SINK_SCRIPTS = process.argv.slice(2);
    CCOW_SINK_SCRIPTS.forEach(function (sinkScript) {
        var sinkPath = path.resolve(__dirname, sinkScript);
        cluster.fork({ "CCOW_SINK_SCRIPT" : sinkPath, "AUDITD_IS_AGGREGATOR" : isAggr });
    });

    process.stdin.pause();

    cluster.on('fork', function (worker) {
        children.push(worker);
    });

    var onlineCnt = 0;
    cluster.on('online', function (worker) {
        setTimeout(function () {
            onlineCnt++;
            if (onlineCnt >= CCOW_SINK_SCRIPTS.length)
                process.stdin.resume();
        }, 100);
    });

    cluster.on('exit', function (worker, code, signal) {
        onlineCnt++;
        if (onlineCnt >= CCOW_SINK_SCRIPTS.length)
            process.stdin.resume();
    });

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', function (data) {
        
        children.forEach(function (worker) {
            worker.send({ cmd: 'stdin', data: data });
        });
    });

    process.stdin.on('finish', function () {
        children.forEach(function (worker) {
            worker.send({ cmd: 'finish' });
        });
    });

    return;
} 

var sinkPath = process.env["CCOW_SINK_SCRIPT"];
if (!fs.existsSync(sinkPath)) {
    process.exit(1);
}

var sink = spawn(sinkPath);
sink.stdin.setEncoding = 'utf-8';
sink.stdout.pipe(process.stdout);

process.on('message', function (msg) {
    if (msg.cmd === 'stdin') {
        sink.stdin.write(msg.data);
    }
    if (msg.cmd === 'finish') {
        sink.stdin.end();
    }
});
sink.on('exit', function (code) {
    process.exit(code);
});
