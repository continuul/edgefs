#!/bin/bash

NEDGE_HOME=${NEDGE_HOME:-/opt/nedge}; export NEDGE_HOME

cd $NEDGE_HOME
source env.sh

EFSPROXY_PID=$NEDGE_HOME/var/run/grpc-efsproxy.pid
CCOWD_PID=$NEDGE_HOME/var/run/ccowd.pid

if test -f $EFSPROXY_PID; then
	kill -TERM `cat $EFSPROXY_PID` 2>/dev/null
	rm -f $EFSPROXY_PID
fi

if test -f $CCOWD_PID; then
	kill -TERM `cat $CCOWD_PID` 2>/dev/null
	echo -n "Waiting for ccow-daemon process to flush and exit "
	while test -e $CCOWD_PID; do
		sleep 5
		echo -n "."
	done
	echo " [ OK ]"
	rm -f $CCOWD_PID
fi

$NEDGE_HOME/etc/init.d/auditctl stop
$NEDGE_HOME/etc/init.d/corosync stop
