#!/bin/bash
is_stub() {
        grep name $NEDGE_HOME/etc/ccow/rt-lfs.json &>/dev/null && return 1
        grep name $NEDGE_HOME/etc/ccow/rt-rd.json &>/dev/null && return 1
        return 0
}

NEDGE_HOME=${NEDGE_HOME:-/opt/nedge}; export NEDGE_HOME

cd $NEDGE_HOME
source env.sh
#skip check for stub daemon container
if [ "$DAEMON_INDEX" -gt 0 ];then 
	if is_stub;then
	        echo "Skipping liveness probe for stub container"
		exit 0
	fi
fi

efscli system state
