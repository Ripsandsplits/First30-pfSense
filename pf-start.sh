#!/bin/sh
# pfSense Competition Kit 0.3.0. Use console menu option 8.
# Each mutating operation requires --apply. An interactive shell opens the menu.
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
[ -f /usr/local/etc/php.ini ] || { echo 'The native PHP configuration is missing.' >&2; exit 1; }
if [ "$#" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
    set -- menu
fi
case "${1-}" in
    menu)
        [ "$#" -eq 1 ] || { echo 'The menu takes no options.' >&2; exit 1; }
        [ -t 0 ] && [ -t 1 ] || { echo 'The menu requires an interactive terminal. Use audit or logs --list when redirecting output.' >&2; exit 1; }
        # No lock while the operator reads a prompt: watchdogs can still run.
        . "$kit_dir/lib/menu.sh"
        menu_main
        exit 0
        ;;
    logs)
        # Log viewing works even when native configuration loading fails.
        /usr/local/bin/php -c /usr/local/etc/php.ini -f "$kit_dir/lib/pf-start.php" -- "$@"
        exit "$?"
        ;;
esac
[ -f /etc/inc/config.inc ] || { echo 'The pfSense libraries are missing.' >&2; exit 1; }
# One kit operation runs at a time, including the rollback watchdog.
/usr/bin/lockf -k -t 0 /var/run/pf-start.lock \
    /usr/local/bin/php -c /usr/local/etc/php.ini -f "$kit_dir/lib/pf-start.php" -- "$@"
