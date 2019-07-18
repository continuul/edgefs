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
	        echo "Skipping readiness probe for stub container"
	        exit 0
	fi
fi

if test ! -e $NEDGE_HOME/var/run/serverid.cache; then
        echo "CCOW daemon not yet started"
        exit 1
fi
if test ! -e $NEDGE_HOME/var/run/stats.db; then
        echo "Audit daemon not yet started"
        exit 1
fi

if ! cat $NEDGE_HOME/var/run/stats.db | grep clengine | grep `cat $NEDGE_HOME/var/run/serverid.cache` &>/dev/null; then
        echo "CCOW daemon not yet ready"
        exit 1
fi
exit 0

