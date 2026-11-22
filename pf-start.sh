#!/bin/sh
# pfSense Competition Kit 0.2.0. Use console menu option 8.
# Each mutating operation requires --apply. The default command is audit.
set -eu
set +x
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
PF_START_TTY=$(/usr/bin/tty 2>/dev/null || true)
export PF_START_TTY
terminal_state=
if [ -t 0 ]; then
    terminal_state=$(stty -g </dev/tty)
fi
restore_terminal() {
    if [ -n "$terminal_state" ]; then
        stty "$terminal_state" </dev/tty 2>/dev/null || true
    fi
}
trap restore_terminal EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
kit_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
case "${1-}" in
    -h|--help|help)
        cat "$kit_dir/HELP.txt"
        exit 0
        ;;
esac
[ "$(uname -s)" = FreeBSD ] || { echo 'Requires pfSense on FreeBSD.' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo 'Run as admin/root (UID 0).' >&2; exit 1; }
[ -x /usr/local/bin/php ] || { echo 'The PHP CLI is missing.' >&2; exit 1; }
[ -f /etc/inc/config.inc ] || { echo 'The pfSense libraries are missing.' >&2; exit 1; }
# One kit operation runs at a time, including the rollback watchdog.
/usr/bin/lockf -k -t 0 /var/run/pf-start.lock \
    /usr/local/bin/php -f "$kit_dir/lib/pf-start.php" -- "$@"
