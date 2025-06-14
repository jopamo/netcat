#!/bin/sh
#
# dist.sh - Example listen-exec file server with connection logging and syslog UDP
#
# Purpose:
#   - Demonstrates how to use netcat/ncat as a simple "inetd"-style server
#   - Logs each connection to a file and syslog (UDP)
#   - After each connection, restarts itself (one-shot/inetd-style)
#
# Requirements:
#   - Modern 'nc' or 'ncat' installed
#   - 'dist.file' contains the data to send
#   - 'dist.log' will be created as a connection log
#
# Usage:
#   ./dist-server.sh [PORT]
#

PORT="${1:-31337}"
NC="./nc"           # Or path to ncat, or just "nc" if in $PATH
SYSLOG_HOST="localhost"
SYSLOG_PORT="514"
LOGFILE="dist.log"
DATAFILE="dist.file"
RESTART_DELAY=1
PRE_MSG_DELAY=8

# --- Detect ncat or nc ---
if "$NC" -h 2>&1 | grep -qi nmap; then
    IS_NCAT=1
else
    IS_NCAT=0
fi

log_syslog() {
    # Usage: log_syslog "message"
    logger="<36>elite: $1"
    if [ "$IS_NCAT" -eq 1 ]; then
        echo "$logger" | $NC -u $SYSLOG_HOST $SYSLOG_PORT > /dev/null 2>&1
    else
        echo "$logger" | $NC -u -w 1 $SYSLOG_HOST $SYSLOG_PORT > /dev/null 2>&1
    fi
}

launch_listener() {
    # One-shot listener; after connection, script restarts
    if [ "$IS_NCAT" -eq 1 ]; then
        $NC -l $PORT --sh-exec "$0 --serve" >> $LOGFILE 2>&1 < /dev/null &
    else
        $NC -v -l -p $PORT -e "$0 --serve" >> $LOGFILE 2>&1 < /dev/null &
    fi
}

if [ "$1" = "--serve" ]; then
    # This block runs for every connection
    SRC="$(date) $(who | awk '{print $5}' | head -1)"
    echo "$SRC" >> $LOGFILE
    log_syslog "$SRC"
    echo ";;; Hi, $SRC..."
    echo ";;; This is a PRERELEASE version of 'netcat', tar/gzip/uuencoded."
    echo ";;; Unless you are capturing this somehow, it won't do you much good."
    echo ";;; Ready??  Here it comes!  Have phun ..."
    sleep $PRE_MSG_DELAY
    cat "$DATAFILE"
    sleep 1
    log_syslog "done"
    # Relaunch the listener for next connection, then exit
    "$0" $PORT &
    exit 0
fi

# ---- Initial startup (not --serve) ----

# Start main listener
echo "[$$] [*] Starting dist-server on port $PORT"
sleep $RESTART_DELAY
launch_listener
echo "[$$] [*] Listener launched on port $PORT"
exit 0
