#!/bin/sh
set -eu

node=$1
monitor=$2
policy=$3

# Replace the timeout process with the isolated scanner so only one Node
# process is live during ordinary polling.
if ! outcome=$(/usr/bin/perl -e 'alarm shift; exec @ARGV or die "Unable to start scanner: $!"' \
    150 /usr/bin/sandbox-exec -f "$policy" "$node" "$monitor" scan); then
    exec "$node" "$monitor" scan-failed
fi

case "$outcome" in
    idle) exit 0 ;;
    deliver) exec "$node" "$monitor" deliver ;;
    *) exec "$node" "$monitor" scan-failed ;;
esac
