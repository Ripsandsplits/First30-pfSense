#!/bin/sh
# Sourced by pf-start.sh. Each command uses the launcher's normal checks.
# Split lists on spaces, without expanding input as wildcards or shell code.
set -f

menu_read() {
    printf '%s' "$1"
    menu_reply=
    IFS= read -r menu_reply
}

menu_yes() {
    menu_read "$1 [y/N]: " || return 1
    case "$menu_reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

menu_run() {
    printf '\nRunning:'
    printf ' %s' "$@"
    printf '\n\n'
    if /bin/sh "$kit_dir/pf-start.sh" "$@"; then
        return 0
    else
        menu_status=$?
        printf '\nCommand exited with status %s. Review its output before continuing.\n' "$menu_status"
        return "$menu_status"
    fi
}

menu_change() {
    if menu_run "$@"; then
        if menu_yes 'Apply the previewed operation'; then
            menu_run "$@" --apply || :
        else
            printf 'No change applied.\n'
        fi
    fi
}

menu_rotate() {
    menu_read 'Usernames separated by spaces (blank = all eligible accounts, 0 = back): ' || return 0
    [ "$menu_reply" != 0 ] || return 0
    set -- rotate
    for menu_user in $menu_reply; do set -- "$@" --user "$menu_user"; done
    if menu_yes 'Limit rotation to passwords matching known defaults'; then
        set -- "$@" --defaults-only
    fi
    menu_change "$@"
}

menu_terminals() {
    menu_run sessions || return 0
    menu_read 'TTY to terminate, others for other terminals, or 0 to go back: ' || return 0
    case "$menu_reply" in
        0|'') return 0 ;;
        others) menu_change sessions-kill --others ;;
        *) menu_change sessions-kill --tty "$menu_reply" ;;
    esac
}

menu_gui_sessions() {
    menu_run sessions || return 0
    menu_read 'GUI session key to revoke, all for every GUI session, or 0 to go back: ' || return 0
    case "$menu_reply" in
        0|'') return 0 ;;
        all) menu_change gui-revoke --all ;;
        *) menu_change gui-revoke --session "$menu_reply" ;;
    esac
}

menu_service() {
    menu_run services || return 0
    menu_read 'Service key to restart, gui for the web interface, or 0 to go back: ' || return 0
    case "$menu_reply" in 0|'') return 0 ;; esac
    menu_change service-restart --service "$menu_reply"
}

menu_checks() {
    menu_read 'TCP endpoints separated by spaces (host:port or [IPv6]:port, 0 = back): ' || return 0
    case "$menu_reply" in 0|'') return 0 ;; esac
    set -- check
    for menu_endpoint in $menu_reply; do set -- "$@" --tcp "$menu_endpoint"; done
    menu_run "$@" || :
}

menu_stage() {
    menu_read 'Interfaces separated by spaces (for example lan, 0 = back): ' || return 0
    case "$menu_reply" in 0|'') return 0 ;; esac
    set -- management-stage
    for menu_interface in $menu_reply; do set -- "$@" --interface "$menu_interface"; done
    menu_read 'Allowed source IPs/CIDRs separated by spaces: ' || return 0
    [ -n "$menu_reply" ] || return 0
    for menu_source in $menu_reply; do set -- "$@" --allow "$menu_source"; done
    menu_read 'Management TCP ports separated by commas (use your actual GUI and SSH ports): ' || return 0
    [ -n "$menu_reply" ] || return 0
    set -- "$@" --ports "$menu_reply"
    menu_read 'Trial timeout in seconds [180]: ' || return 0
    set -- "$@" --timeout "${menu_reply:-180}"
    if menu_run "$@" && menu_yes 'Recovery console available; start this temporary trial'; then
        menu_run "$@" --console-ready --apply || :
    fi
}

menu_transaction() {
    menu_operation=$1
    menu_run management-status || return 0
    menu_read 'Transaction token (0 = back): ' || return 0
    case "$menu_reply" in 0|'') return 0 ;; esac
    set -- "$menu_operation" --token "$menu_reply"
    if [ "$menu_operation" = management-rollback ]; then
        menu_change "$@"
    elif menu_run "$@" && menu_yes 'Fresh allowed management login tested; apply this operation'; then
        menu_run "$@" --access-tested --apply || :
    fi
}

menu_management() {
    while :; do
        cat <<'MENU'

Management access
  1) Show trial status
  2) Stage a temporary access trial
  3) Enforce a tested trial
  4) Confirm and save a tested trial
  5) Roll back a trial
  0) Back
MENU
        menu_read 'Select: ' || return 0
        case "$menu_reply" in
            1) menu_run management-status || : ;;
            2) menu_stage ;;
            3) menu_transaction management-enforce ;;
            4) menu_transaction management-confirm ;;
            5) menu_transaction management-rollback ;;
            0) return 0 ;;
            *) printf 'Choose a number from the list.\n' ;;
        esac
    done
}

menu_reboot() {
    menu_run reboot || return 0
    menu_read 'With recovery-console access available, type REBOOT to reboot now (anything else cancels): ' || return 0
    if [ "$menu_reply" = REBOOT ]; then
        menu_run reboot --console-ready --apply || :
    else
        printf 'Reboot cancelled.\n'
    fi
}

menu_main() {
    while :; do
        printf '\n'
        sed -n '1p' "$kit_dir/HELP.txt"
        cat <<'MENU'
  1) Opening audit
  2) Save a recovery backup
  3) Rotate local passwords
  4) List terminal and GUI sessions
  5) Terminate selected terminal sessions
  6) Revoke selected GUI sessions
  7) List services and their keys
  8) Restart a selected service
  9) Check TCP endpoints
 10) Management access tools
 11) View saved logs and reports
 12) Help and command reference
 13) Reboot
  0) Exit
MENU
        menu_read 'Select: ' || return 0
        case "$menu_reply" in
            1) menu_run audit || : ;;
            2) menu_change backup ;;
            3) menu_rotate ;;
            4) menu_run sessions || : ;;
            5) menu_terminals ;;
            6) menu_gui_sessions ;;
            7) menu_run services || : ;;
            8) menu_service ;;
            9) menu_checks ;;
            10) menu_management ;;
            11) menu_run logs || : ;;
            12) menu_run help || : ;;
            13) menu_reboot ;;
            0) return 0 ;;
            *) printf 'Choose a number from the list.\n' ;;
        esac
        menu_read 'Press Enter to return to the menu...' || return 0
    done
}
