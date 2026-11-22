#!/bin/sh
# Internal watchdog. Its arguments are paths, transaction ID, and duration.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
sleep "$3"
# Wait for an in-progress kit command to release its lock. Commands that can
# prompt or restart services are blocked while a management trial is pending.
exec /usr/bin/lockf -k /var/run/pf-start.lock \
    /usr/local/bin/php -f "$1" -- management-rollback --token "$2" --apply
