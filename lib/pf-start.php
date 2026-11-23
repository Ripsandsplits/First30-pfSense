<?php
namespace PFStart;
use RuntimeException;
use Throwable;
/* pfSense Competition Kit CLI. PHP 7.4+ and modern pfSense APIs. */
/* Compatibility hotfix 1: current config_read_file() plus legacy parse_config(). */
ini_set('display_errors', 'stderr');
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
umask(0077);
require_once(__DIR__ . '/accounts.php');
require_once(__DIR__ . '/core.php');
require_once(__DIR__ . '/sessions.php');
require_once(__DIR__ . '/management.php');

function refresh_config() {
    global $config;
    if (function_exists('config_read_file')) {
        // Arguments are use_backup and use_cache, not a force-reload flag.
        // Refresh from disk without restoring backups or trusting a stale cache.
        // This API updates the global configuration and returns a BOOLEAN.
        if (config_read_file(false, false) !== true) {
            fail('Could not reload config.xml. No backup recovery was requested.');
        }
    } elseif (function_exists('parse_config')) {
        $loaded = parse_config(true);
        if ($loaded === false) {
            fail('The legacy configuration loader failed.');
        }
        // Older releases return the array; some update global state directly.
        // Never replace the configuration array with a success boolean.
        if (is_array($loaded)) {
            $config = $loaded;
        }
    } else {
        fail('This pfSense release provides neither config_read_file nor parse_config.');
    }
    if (!is_array(config_get_path('', null)) ||
        !is_array(config_get_path('system', null))) {
        fail('The native loader did not provide a valid configuration array.');
    }
}

function rotation_preflight() {
    if (config_get_path('hasync/adminsync') === 'on' || config_get_path('hasync/synchronizetoip')) {
        fail('Coordinate HA peers before rotating administrator credentials.');
    }
    $auth = auth_get_authserver(config_get_path('system/webgui/authmode'));
    if (!empty($auth['type']) && $auth['type'] !== 'Local Auth') {
        fail('Remote GUI authentication is configured. Review local and directory credentials first.');
    }
    if (!is_executable('/usr/local/bin/usermgrpasswd')) {
        fail('This pfSense version lacks usermgrpasswd; its password handler needs adaptation.');
    }
    if (!stream_isatty(STDIN) || !stream_isatty(STDOUT)) {
        fail('Password rotation requires an interactive terminal.');
    }
}

function rotate_accounts($options) {
    $requested = array_values(array_unique($options['--user'] ?? []));
    $inventory = account_inventory($requested);
    $targets = rotation_targets($inventory, $requested, isset($options['--defaults-only']));
    output_json(['rotation_targets' => array_column($targets, 'name'),
        'disabled_expired_and_locked_accounts' => 'excluded',
        'password_scope' => isset($options['--defaults-only']) ? 'known defaults or empty' : 'all selected accounts']);
    if (empty($options['--apply']) || !$targets) {
        return;
    }
    require_no_management_trial();
    rotation_preflight();
    configuration_backup('before local password rotation');
    echo "Use a distinct new password at each prompt. Verify a fresh login afterward.\n";
    $completed = [];
    try {
        foreach ($targets as $account) {
            refresh_config();
            // Re-evaluate the current account before each native update.
            $latest = account_inventory([$account['name']])[$account['name']];
            if ($latest['disabled'] || $latest['expired'] || $latest['locked']) {
                fail('Account became disabled/expired/locked: ' . $account['name']);
            }
            $before = account_fingerprint($account);
            record_action('password-change-started', ['user' => $account['name']]);
            echo 'Changing ', $account['name'], "\n";
            $arguments = $account['kind'] === 'managed'
                ? ['/usr/local/bin/usermgrpasswd', '-u', $account['name']]
                : ['/usr/bin/passwd', $account['name']];
            require_command_success($arguments, true);
            refresh_config();
            verify_rotation($account, $before);
            $completed[] = $account['name'];
            record_action('password-change-verified', ['user' => $account['name']]);
            echo 'Verified ', $account['name'], "\n";
        }
    } catch (Throwable $error) {
        record_action('password-rotation-interrupted', ['verified' => $completed,
            'note' => 'An attempted native change may also have succeeded. Inspect that account.']);
        echo 'Verified changes retained: ', implode(', ', $completed), "\n";
        throw $error;
    }
    echo "Password rotation finished. Test a NEW login before revoking sessions.\n";
}

function services_inventory() {
    require_once('/etc/inc/service-utils.inc');
    foreach (['get_services', 'get_service_status', 'service_control_restart'] as $function) {
        if (!function_exists($function)) {
            fail('Missing service API ' . $function);
        }
    }
    $result = [];
    foreach ((array)get_services() as $service) {
        if (empty($service['name'])) {
            continue;
        }
        $identity = [];
        foreach (['name', 'id', 'vpnid', 'zone', 'type'] as $field) {
            if (isset($service[$field])) {
                $identity[$field] = $service[$field];
            }
        }
        $key = substr(hash('sha256', json_encode($identity)), 0, 16);
        if (isset($result[$key])) {
            fail('Ambiguous service identity. Use the pfSense GUI for this service.');
        }
        $result[$key] = ['key' => $key, 'name' => $service['name'],
            'description' => $service['description'] ?? '',
            'running' => (bool)get_service_status($service), 'native' => $service];
    }
    return $result;
}

function services_public($services) {
    foreach ($services as &$service) {
        unset($service['native']);
    }
    unset($service);
    return array_values($services);
}

function process_exists($name) {
    [$status] = run_command(['/usr/bin/pgrep', '-x', $name]);
    if ($status > 1) {
        fail('Process inspection failed for ' . $name);
    }
    return $status === 0;
}

function restart_gui() {
    foreach (['/etc/rc.restart_webgui', '/etc/rc.php-fpm_restart'] as $script) {
        if (!is_executable($script)) {
            fail('The native GUI restart script is missing: ' . $script);
        }
    }
    require_command_success(['/etc/rc.restart_webgui']);
    require_command_success(['/etc/rc.php-fpm_restart']);
    if (!process_exists('nginx') || !process_exists('php-fpm')) {
        fail('The expected GUI processes did not return. Inspect the console.');
    }
}

function restart_service($options) {
    $key = single_option($options, '--service');
    if ($key === null) {
        fail('Choose --service using a key from the services command, or use --service gui.');
    }
    if ($key === 'gui') {
        echo "Selected the GUI web server and PHP-FPM. Existing page loads may disconnect.\n";
        if (!empty($options['--apply'])) {
            require_no_management_trial();
            configuration_backup('before GUI restart');
            record_action('gui-restart-started');
            restart_gui();
            record_action('gui-restart-processes-verified');
            echo "GUI processes are running. Verify a fresh browser request.\n";
        }
        return;
    }
    $services = services_inventory();
    if (!isset($services[$key])) {
        fail('No configured service matches that key. List services again.');
    }
    $selected = $services[$key];
    output_json(services_public([$selected]));
    if (empty($options['--apply'])) {
        return;
    }
    require_no_management_trial();
    configuration_backup('before service restart');
    record_action('service-restart-started', ['key' => $key, 'name' => $selected['name']]);
    $message = service_control_restart($selected['name'], $selected['native']);
    echo strip_tags((string)$message), "\n";
    $running = false;
    for ($attempt = 0; $attempt < 15; $attempt++) {
        $current = services_inventory();
        if (isset($current[$key]) && $current[$key]['running']) {
            $running = true;
            break;
        }
        sleep(1);
    }
    if (!$running) {
        record_action('service-restart-unverified', ['key' => $key]);
        fail('Service did not return to running state within 15 seconds. Inspect its logs.');
    }
    record_action('service-restart-process-verified', ['key' => $key]);
    echo "The service reports running. Verify its application response and scoring.\n";
}

function kill_terminal_sessions($options) {
    $snapshot = terminal_snapshot();
    $requested = $options['--tty'] ?? [];
    foreach ($requested as $terminal) {
        if (!preg_match('#^[A-Za-z0-9_/.-]+$#D', $terminal) || $terminal[0] === '-') {
            fail('Invalid terminal name.');
        }
    }
    $targets = terminal_targets($snapshot, $requested, isset($options['--others']));
    output_json(['terminal_targets' => $targets, 'protected_operator_tty' => $snapshot['current_tty']]);
    if (empty($options['--apply']) || !$targets) {
        return;
    }
    require_no_management_trial();
    $directory = configuration_backup('before terminal session revocation');
    save_json($directory . '/sessions-before.json', $snapshot);
    foreach ($targets as $terminal) {
        // Check again immediately before signaling to avoid killing a terminal
        // which disappeared since the preview. SIGTERM preserves process cleanup.
        terminal_targets(terminal_snapshot(), [$terminal], false);
        [$status] = run_command(['/usr/bin/pkill', '-TERM', '-t', $terminal]);
        if ($status > 1) {
            fail('Failed to signal terminal ' . $terminal);
        }
        record_action('terminal-signaled', ['tty' => $terminal]);
    }
    sleep(1);
    save_json($directory . '/sessions-after.json', terminal_snapshot());
    echo "SIGTERM sent. Review sessions again for any process that remains.\n";
}

function revoke_gui($options) {
    $directory = gui_session_directory();
    $sessions = gui_sessions($directory);
    $requested = $options['--session'] ?? [];
    $all = isset($options['--all']);
    if ((!$requested && !$all) || ($requested && $all)) {
        fail('Choose --session SESSION_KEY or --all.');
    }
    foreach ($requested as $key) {
        if (!isset($sessions[$key])) {
            fail('GUI session is absent. List sessions again.');
        }
    }
    output_json(['gui_session_targets' => $all ? array_keys($sessions) : $requested]);
    if (empty($options['--apply'])) {
        return;
    }
    require_no_management_trial();
    if (!is_executable('/etc/rc.php-fpm_restart')) {
        fail('The native PHP-FPM restart handler is unavailable.');
    }
    $evidence = configuration_backup('before GUI session revocation');
    save_json($evidence . '/gui-session-metadata.json', $sessions);
    $wasRunning = process_exists('php-fpm');
    try {
        if ($wasRunning) {
            require_command_success(['/usr/bin/pkill', '-TERM', '-x', 'php-fpm']);
            for ($attempt = 0; $attempt < 15 && process_exists('php-fpm'); $attempt++) {
                sleep(1);
            }
            if (process_exists('php-fpm')) {
                fail('PHP-FPM did not stop. Session files were left intact.');
            }
        }
        $removed = revoke_gui_sessions($directory, $requested, $all);
        record_action('gui-sessions-revoked', ['session_keys' => $removed]);
    } finally {
        if ($wasRunning) {
            require_command_success(['/etc/rc.php-fpm_restart']);
            if (!process_exists('php-fpm')) {
                fail('PHP-FPM did not return. Use the console to recover the GUI.');
            }
        }
    }
    output_json(['revoked_gui_session_keys' => $removed]);
}

function tcp_checks($targets) {
    if (!$targets) {
        fail('Specify one or more --tcp HOST:PORT targets. IPv6 uses [ADDRESS]:PORT.');
    }
    $results = [];
    foreach ($targets as $target) {
        if (!preg_match('/^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9_.-]+):([0-9]+)$/D', $target, $match) ||
            (int)$match[2] < 1 || (int)$match[2] > 65535) {
            fail('Invalid TCP target ' . $target);
        }
        $start = microtime(true);
        $connection = @stream_socket_client('tcp://' . $target, $error, $message, 3);
        $results[] = ['target' => $target, 'reachable' => is_resource($connection),
            'elapsed_ms' => (int)((microtime(true) - $start) * 1000)];
        if (is_resource($connection)) {
            fclose($connection);
        }
    }
    return $results;
}

function audit_firewall() {
    $directory = configuration_backup('opening baseline audit');
    $report = ['time_utc' => gmdate('c'), 'version' => PF_START_VERSION,
        'accounts' => account_inventory(), 'management' => config_get_path('system/webgui', []),
        'interfaces' => config_get_path('interfaces', []),
        'pending_management_trial' => pending_transaction()];
    // Only selected management fields belong in the report. Full configuration
    // with credential hashes belongs in the separately protected recovery backup.
    $report['management'] = array_intersect_key($report['management'], array_flip([
        'protocol', 'port', 'noantilockout', 'authmode', 'disablehttpredirect', 'interfaces'
    ]));
    foreach ($report['interfaces'] as &$interface) {
        $interface = array_intersect_key($interface, array_flip([
            'descr', 'if', 'enable', 'ipaddr', 'subnet', 'ipaddrv6', 'subnetv6', 'gateway', 'gatewayv6'
        ]));
    }
    unset($interface);
    $report['ssh'] = array_intersect_key(config_get_path('system/ssh', []), array_flip([
        'enable', 'port', 'sshdkeyonly', 'sshdagentforwarding'
    ]));
    try {
        $report['services'] = services_public(services_inventory());
    } catch (Throwable $error) {
        $report['service_warning'] = $error->getMessage();
    }
    $report['sessions'] = terminal_snapshot();
    try {
        $report['gui_sessions'] = array_values(gui_sessions(gui_session_directory()));
    } catch (Throwable $error) {
        $report['gui_session_warning'] = $error->getMessage();
    }
    foreach (['interfaces' => ['/sbin/ifconfig', '-a'],
              'routes' => ['/usr/bin/netstat', '-rn'],
              'listening_sockets' => ['/usr/bin/sockstat', '-l'],
              'active_rules' => ['/sbin/pfctl', '-vvsr'],
              'active_nat' => ['/sbin/pfctl', '-sn']] as $name => $command) {
        [$status, $output, $error] = run_command($command);
        $report[$name . '_runtime'] = ['status' => $status, 'output' => $output, 'error' => $error];
    }
    $report['configuration_review'] = [
        'firewall_rule_count' => count(config_get_path('filter/rule', [])),
        'nat_rule_count' => count(config_get_path('nat/rule', [])),
        'cron_job_count' => count(config_get_path('cron/item', [])),
        'package_names' => array_column(config_get_path('installedpackages/package', []), 'name'),
        'early_shell_command_present' => (bool)config_get_path('system/earlyshellcmd'),
        'after_boot_shell_command_present' => (bool)config_get_path('system/afterbootupshellcmd'),
        'review' => 'Inspect cron, Shellcmd, sudo, package configuration, rule history, and authorized keys in the GUI.'
    ];
    save_json($directory . '/audit.json', $report);
    echo 'Audit report: ', $directory, "/audit.json\n";
    output_json(['accounts' => $report['accounts'], 'management' => $report['management'],
        'ssh' => $report['ssh'], 'configuration_review' => $report['configuration_review']]);
    echo "Compare required services from the competition packet with live scoring and client tests.\n";
}

function main($arguments) {
    $command = array_shift($arguments) ?? 'audit';
    $definitions = [
        'audit' => [], 'backup' => ['--apply' => false],
        'rotate' => ['--apply' => false, '--user' => true, '--defaults-only' => false],
        'sessions' => [],
        'sessions-kill' => ['--apply' => false, '--tty' => true, '--others' => false],
        'gui-revoke' => ['--apply' => false, '--session' => true, '--all' => false],
        'services' => [], 'service-restart' => ['--apply' => false, '--service' => true],
        'check' => ['--tcp' => true],
        'management-stage' => ['--apply' => false, '--console-ready' => false,
            '--interface' => true, '--allow' => true, '--ports' => true, '--timeout' => true],
        'management-enforce' => ['--apply' => false, '--access-tested' => false, '--token' => true],
        'management-confirm' => ['--apply' => false, '--access-tested' => false, '--token' => true],
        'management-rollback' => ['--apply' => false, '--token' => true],
        'management-status' => [], 'reboot' => ['--apply' => false, '--console-ready' => false]
    ];
    if (!isset($definitions[$command])) {
        fail('Unknown command ' . $command . '. Use sh pf-start.sh help.');
    }
    $options = options_for($arguments, $definitions[$command]);
    if (php_uname('s') !== 'FreeBSD' || !function_exists('posix_geteuid') || posix_geteuid() !== 0) {
        fail('This entry point requires a root shell on pfSense/FreeBSD.');
    }
    foreach (['config_get_path', 'local_user_get_groups'] as $function) {
        if (!function_exists($function)) {
            fail('This pfSense release is missing ' . $function . '.');
        }
    }
    refresh_config();
    $pending = pending_transaction();
    if (transaction_open($pending) && time() >= $pending['deadline'] && $command !== 'management-rollback') {
        rollback_management($pending);
        if (in_array($command, ['management-enforce', 'management-confirm'], true)) {
            fail('The management trial expired and was rolled back. Stage a new trial.');
        }
    }
    switch ($command) {
        case 'audit': audit_firewall(); break;
        case 'backup':
            if (isset($options['--apply'])) {
                require_no_management_trial();
                configuration_backup('operator requested backup');
            } else {
                echo "Add --apply to save a root-only configuration backup.\n";
            }
            break;
        case 'rotate': rotate_accounts($options); break;
        case 'sessions':
            output_json(terminal_snapshot());
            try { output_json(['gui_session_files' => array_values(gui_sessions(gui_session_directory()))]); }
            catch (Throwable $error) { echo 'GUI session inspection: ', $error->getMessage(), "\n"; }
            break;
        case 'sessions-kill': kill_terminal_sessions($options); break;
        case 'gui-revoke': revoke_gui($options); break;
        case 'services':
            output_json(services_public(services_inventory()));
            echo "The special service key gui restarts the GUI web server and PHP-FPM.\n";
            break;
        case 'service-restart': restart_service($options); break;
        case 'check':
            $checks = tcp_checks($options['--tcp'] ?? []);
            output_json($checks);
            record_action('TCP reachability checks', $checks);
            foreach ($checks as $check) {
                if (!$check['reachable']) { return 2; }
            }
            break;
        case 'management-stage': stage_management($options); break;
        case 'management-enforce': enforce_management($options); break;
        case 'management-confirm': confirm_management($options); break;
        case 'management-status': output_json(pending_transaction() ?? ['phase' => 'none']); break;
        case 'management-rollback':
            $transaction = transaction_for_token(single_option($options, '--token'));
            if (isset($options['--apply'])) { rollback_management($transaction); }
            else { output_json($transaction); echo "Add --apply to roll back this trial.\n"; }
            break;
        case 'reboot':
            if (!isset($options['--apply']) || !isset($options['--console-ready'])) {
                echo "Reboot interrupts traffic and all shell connections. Use --console-ready --apply to request it.\n";
                break;
            }
            require_no_management_trial();
            configuration_backup('before explicit operator reboot');
            record_action('explicit-reboot-requested');
            require_command_success(['/sbin/shutdown', '-r', 'now']);
            break;
    }
    return 0;
}

try {
    if (php_uname('s') !== 'FreeBSD' || !function_exists('posix_geteuid') || posix_geteuid() !== 0) {
        fail('Run this kit from a root pfSense shell.');
    }
    // Initialize native CLI globals before any include can transitively load auth.
    // auth.inc otherwise pulls in GUI-specific code and warns about this flag.
    $do_not_include_config_gui_inc = true;
    if (empty($ARCH)) {
        $ARCH = php_uname('m');
    }
    foreach (['globals.inc', 'config.inc', 'functions.inc', 'auth.inc', 'service-utils.inc', 'filter.inc'] as $library) {
        require_once('/etc/inc/' . $library);
    }
    exit(main(array_slice($argv, 1)));
} catch (Throwable $error) {
    fwrite(STDERR, 'ERROR: ' . $error->getMessage() . "\n");
    fwrite(STDERR, "Review /conf/pf-start/actions.jsonl and the console. Earlier completed changes remain in effect.\n");
    exit(1);
}
