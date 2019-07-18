# Override it in .local if need to set target to a new location
NEDGE_HOME=${NEDGE_HOME:-/opt/edgefs}; export NEDGE_HOME

# Override it in .local to 1 in terms of to enable syslog globally
CCOW_LOG_SYSLOG=0; export CCOW_LOG_SYSLOG

# Enable core files. Core files will be stored in /opt/nedge/var/cores/core_%e.%p.
ulimit -c unlimited

# CCOW Daemon may open lots of files
ulimit -n 65536

# CCOW Daemon needs more memory on stack
ulimit -s 32768

LDFLAGS=-L$NEDGE_HOME/lib; export LDFLAGS
CFLAGS="-I$NEDGE_HOME/include -I$NEDGE_HOME/include/ccow"; export CFLAGS
CXXFLAGS=-I$NEDGE_HOME/include; export CXXFLAGS

ASAN_OPTIONS=symbolize=1:abort_on_error=1:disable_core=1:alloc_dealloc_mismatch=0:detect_leaks=0; export ASAN_OPTIONS
ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-3.5/bin/llvm-symbolizer; export ASAN_SYMBOLIZER_PATH
LD_LIBRARY_PATH=$NEDGE_HOME/lib; export LD_LIBRARY_PATH
PATH=$NEDGE_HOME/bin:$NEDGE_HOME/sbin:$PATH

if [ -f $NEDGE_HOME/.local ]; then
    . $NEDGE_HOME/.local
fi
