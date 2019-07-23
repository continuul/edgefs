#!/bin/bash
NEDGE_HOME=${NEDGE_HOME:-/opt/nedge}; export NEDGE_HOME

cd $NEDGE_HOME
source env.sh

efscli system state
