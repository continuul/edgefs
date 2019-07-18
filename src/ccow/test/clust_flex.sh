##
## Copyright (c) 2015-2018 Nexenta Systems, inc.
##
## This file is part of EdgeFS Project
## (see https://github.com/Nexenta/edgefs).
##
## Licensed to the Apache Software Foundation (ASF) under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  The ASF licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
##
##   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##
#Copyright - Nexenta Systems, Inc.
#!/bin/bash

#Other nodes in the cluster (exclusing this one)
#example - 192.168.1.33
NODE1=
#example - rajesh
user=

if [ "x${NODE1}" = "x" ]; then
	echo "Configure other test server IP addr"
	exit
fi

if [ "x${user}" = "x" ]; then
	echo "Please set the user name"
	exit
fi

#Clean the stores
rm -rfv /data/store*/*
rm -rfv /data/store*/.device-metadata

#Start deamon test in the background
/opt/nedge/src/ccow/test/daemon_test &

#Look at the number of servers and disks
config1_servers=`/opt/nedge/sbin/fhdebug.py --summary | grep servers | awk '{print $5}'`
config1_devs=`/opt/nedge/sbin/fhdebug.py --summary | grep devices | awk '{print $5}'`

#Start daemon test on another server and then look at the configuration
ssh -tq ${user}@${NODE1} 'sudo rm -rfv /data/store*/*; sudo rm -rfv /data/store*/.device-metadata; export NEDGE_HOME=/opt/nedge;  sudo chmod -R o+w /opt/nedge/var; sudo -E nohup bash -c "/opt/nedge/src/ccow/test/daemon_test -i 10 &"'

echo "waiting for flexhash changes ..."
sleep 2
#Store the config
config2_servers=`/opt/nedge/sbin/fhdebug.py --summary | grep servers | awk '{print $5}'`
config2_devs=`/opt/nedge/sbin/fhdebug.py --summary | grep devices | awk '{print $5}'`

#Wait for daemon_test on other node to stop
#echo "Flexhash servers changed from $config1_servers to $config2_servers"
#echo "Flexhash devices changed from $config1_devs to $config2_devs"
echo "waiting for deamon_test on ${NODE1} to finish ..."
sleep 10

#The daemon on other node should have left by now. Get the config again
config3_servers=`/opt/nedge/sbin/fhdebug.py --summary | grep servers | awk '{print $5}'`
config3_devs=`/opt/nedge/sbin/fhdebug.py --summary | grep devices | awk '{print $5}'`

if [ $config1_servers -ne $config1_servers ]; then
	echo "Error: Flexhash server count does not match"
else
	if [ $config1_devs -ne $config1_devs ]; then
		echo "Error: Flexhash device count does not match"
	else
		echo "Flexhash is fine after node join/leave"
	fi
fi

pkill daemon_test
