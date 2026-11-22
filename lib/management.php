<?php
namespace PFStart;
use RuntimeException;
use Throwable;
/* Trial rules stay in memory until explicitly confirmed. */

function pending_path() {
    return PF_START_STATE . '/management/pending.json';
}

function pending_transaction() {
    return is_file(pending_path()) ? load_json(pending_path()) : null;
}

function transaction_for_token($token) {
    if (!preg_match('/^[a-f0-9]{20}$/D', (string)$token)) {
        fail('Invalid management transaction token.');
    }
    $transaction = pending_transaction();
    if (!$transaction || !hash_equals($transaction['token'], $token)) {
        fail('This token does not match the current management transaction.');
    }
    return $transaction;
}

function transaction_open($transaction) {
    return $transaction && in_array($transaction['phase'],
        ['staged', 'enforced', 'committing', 'rolling-back', 'rollback-failed'], true);
}

function require_no_management_trial() {
    if (transaction_open(pending_transaction())) {
        fail('Finish or roll back the pending management trial before another mutating operation.');
    }
}

function check_management_platform() {
    require_once('/etc/inc/filter.inc');
    foreach (['filter_configure_sync', 'config_set_path', 'config_del_path', 'write_config'] as $function) {
        if (!function_exists($function)) {
            fail('Missing management API ' . $function . '.');
        }
    }
    if (config_get_path('hasync/synchronizetoip') || config_get_path('hasync/adminsync') === 'on') {
        fail('Coordinate HA peers before changing management rules.');
    }
}

function saved_config_unchanged($transaction) {
    if (!hash_equals($transaction['config_sha256'], hash_file('sha256', '/conf/config.xml'))) {
        fail('The saved configuration changed during the trial. Roll back and stage against the new configuration.');
    }
}

function require_trial_time($transaction) {
    if (time() >= $transaction['deadline']) {
        fail('The management trial has expired. Roll back or wait for its watchdog.');
    }
}

function operator_allowed($spec) {
    $connection = trim((string)getenv('SSH_CONNECTION'));
    if ($connection === '') {
        return;
    }
    $address = explode(' ', $connection)[0];
    foreach ($spec['sources'] as $source) {
        if (address_in_cidr($address, $source['address'])) {
            return;
        }
    }
    fail('The current SSH client address is outside the proposed management allowlist.');
}

function overlay_management_rules($transaction, $enforced) {
    $rules = management_rules($transaction['spec'], $transaction['token'], $enforced,
        $transaction['tracker_base']);
    config_set_path('filter/rule', array_merge($rules, config_get_path('filter/rule', [])));
    if ($enforced && $transaction['change_anti_lockout']) {
        config_set_path('system/webgui/noantilockout', true);
    }
    return $rules;
}

function verify_live_rules($rules) {
    $active = require_command_success(['/sbin/pfctl', '-vvsr']);
    foreach ($rules as $rule) {
        if (strpos($active, $rule['descr']) === false) {
            fail('The expected rule label is absent from the active PF ruleset: ' . $rule['descr']);
        }
    }
}

function reload_saved_rules() {
    // A new CLI process loads the authoritative configuration at startup.
    // false prevents a requested blanket state-table reset by this operation.
    filter_configure_sync(false);
}

function apply_trial_overlay($transaction, $enforced) {
    $originalRules = config_get_path('filter/rule', []);
    $webgui = config_get_path('system/webgui', []);
    $before = hash_file('sha256', '/conf/config.xml');
    try {
        $rules = overlay_management_rules($transaction, $enforced);
        filter_configure_sync(false);
    } finally {
        config_set_path('filter/rule', $originalRules);
        config_set_path('system/webgui', $webgui);
    }
    if (!hash_equals($before, hash_file('sha256', '/conf/config.xml'))) {
        fail('The saved configuration changed during the runtime reload. Rollback is required.');
    }
    verify_live_rules($rules);
}

function rollback_management($transaction) {
    check_management_platform();
    if (!transaction_open($transaction)) {
        echo 'Transaction already closed with phase ', $transaction['phase'], ".\n";
        return;
    }
    $transaction['phase'] = 'rolling-back';
    save_json(pending_path(), $transaction);
    $prefix = 'PFSTART-' . $transaction['token'] . '-';
    $rules = config_get_path('filter/rule', []);
    $kept = array_values(array_filter($rules, function ($rule) use ($prefix) {
        return strpos($rule['descr'] ?? '', $prefix) !== 0;
    }));
    // Normally there are no persistent trial rules. This also recovers a crash
    // between writing a confirmed configuration and marking it confirmed.
    if (count($rules) !== count($kept)) {
        config_set_path('filter/rule', $kept);
        if ($transaction['change_anti_lockout']) {
            if ($transaction['anti_lockout_existed']) {
                config_set_path('system/webgui/noantilockout', $transaction['anti_lockout_value']);
            } else {
                config_del_path('system/webgui/noantilockout');
            }
        }
        if (write_config('pf-start management rollback') === false) {
            fail('Could not save the management rollback.');
        }
    }
    try {
        reload_saved_rules();
        $active = require_command_success(['/sbin/pfctl', '-vvsr']);
        if (strpos($active, $prefix) !== false) {
            fail('Trial rule labels remain after the rollback reload.');
        }
    } catch (Throwable $error) {
        $transaction['phase'] = 'rollback-failed';
        save_json(pending_path(), $transaction);
        throw $error;
    }
    $transaction['phase'] = 'rolled-back';
    $transaction['closed_utc'] = gmdate('c');
    save_json(pending_path(), $transaction);
    record_action('management-rolled-back', ['token' => $transaction['token']]);
    echo "Saved firewall rules reloaded. Trial rolled back.\n";
}

function stage_management($options) {
    $spec = management_spec($options);
    operator_allowed($spec);
    output_json(['management_plan' => $spec,
        'destination' => 'firewall addresses only', 'protocol' => 'TCP',
        'trial' => 'runtime only; save after a separate fresh-login confirmation']);
    if (empty($options['--apply'])) {
        return;
    }
    if (empty($options['--console-ready'])) {
        fail('Use --console-ready after verifying recovery-console access.');
    }
    check_management_platform();
    require_no_management_trial();
    if (!is_executable('/usr/sbin/daemon')) {
        fail('The rollback watchdog launcher is unavailable.');
    }
    $backup = configuration_backup('before management trial');
    $token = bin2hex(random_bytes(10));
    $webgui = config_get_path('system/webgui', []);
    $base = random_int(1000000000, 1800000000);
    $allRules = management_rules($spec, $token, true, $base);
    $existingTrackers = array_column(config_get_path('filter/rule', []), 'tracker');
    if (array_intersect(array_column($allRules, 'tracker'), $existingTrackers)) {
        fail('Rule tracker collision; stage the trial again.');
    }
    $transaction = ['token' => $token, 'phase' => 'staged', 'spec' => $spec,
        'tracker_base' => $base, 'deadline' => time() + $spec['timeout'],
        'created_utc' => gmdate('c'), 'config_sha256' => hash_file('sha256', '/conf/config.xml'),
        'backup' => $backup, 'anti_lockout_existed' => array_key_exists('noantilockout', $webgui),
        'anti_lockout_value' => $webgui['noantilockout'] ?? null,
        'change_anti_lockout' => in_array('lan', $spec['interfaces'], true) ||
            count(config_get_path('interfaces', [])) === 1];
    save_json(pending_path(), $transaction);
    $pidFile = PF_START_STATE . '/management/watchdog-' . $token . '.pid';
    try {
        require_command_success(['/usr/sbin/daemon', '-f', '-p', $pidFile,
            '-o', PF_START_STATE . '/management/watchdog-' . $token . '.log',
            '/bin/sh', __DIR__ . '/rollback.sh', __DIR__ . '/pf-start.php', $token,
            (string)$spec['timeout']]);
        for ($attempt = 0; $attempt < 30 && !is_file($pidFile); $attempt++) {
            usleep(100000);
        }
        $pid = is_file($pidFile) ? trim(file_get_contents($pidFile)) : '';
        if (!ctype_digit($pid) || (int)$pid < 2 || !posix_kill((int)$pid, 0)) {
            fail('Could not verify the rollback watchdog.');
        }
        apply_trial_overlay($transaction, false);
    } catch (Throwable $error) {
        rollback_management($transaction);
        throw $error;
    }
    record_action('management-staged', ['token' => $token, 'spec' => $spec]);
    echo 'Transaction token: ', $token, "\n";
    echo 'Open a fresh allowed management connection, then run management-enforce with this token.', "\n";
    echo 'The entire trial expires at ', gmdate('c', $transaction['deadline']), ".\n";
}

function enforce_management($options) {
    $transaction = transaction_for_token(single_option($options, '--token'));
    if ($transaction['phase'] === 'enforced') {
        echo "The trial is already enforced. Test a new connection before confirming.\n";
        return;
    }
    if ($transaction['phase'] !== 'staged') {
        fail('This transaction is not staged.');
    }
    if (empty($options['--apply']) || empty($options['--access-tested'])) {
        output_json($transaction);
        echo "Enforcing requires --apply --access-tested after testing an allowed connection.\n";
        return;
    }
    check_management_platform();
    require_trial_time($transaction);
    saved_config_unchanged($transaction);
    operator_allowed($transaction['spec']);
    try {
        apply_trial_overlay($transaction, true);
    } catch (Throwable $error) {
        rollback_management($transaction);
        throw $error;
    }
    $transaction['phase'] = 'enforced';
    $transaction['enforce_ssh_connection'] = (string)getenv('SSH_CONNECTION');
    save_json(pending_path(), $transaction);
    record_action('management-enforced', ['token' => $transaction['token']]);
    echo "Trial restrictions are active. Test another NEW login, then run management-confirm.\n";
    echo 'Deadline remains ', gmdate('c', $transaction['deadline']), ".\n";
}

function confirm_management($options) {
    $transaction = transaction_for_token(single_option($options, '--token'));
    if ($transaction['phase'] === 'confirmed') {
        echo "This transaction is already confirmed.\n";
        return;
    }
    if ($transaction['phase'] !== 'enforced') {
        fail('Enforce and test the trial before confirmation.');
    }
    if (empty($options['--apply']) || empty($options['--access-tested'])) {
        echo "Confirmation requires --apply --access-tested after testing a fresh login.\n";
        return;
    }
    check_management_platform();
    require_trial_time($transaction);
    saved_config_unchanged($transaction);
    operator_allowed($transaction['spec']);
    $connection = (string)getenv('SSH_CONNECTION');
    if ($connection !== '' && $connection === $transaction['enforce_ssh_connection']) {
        fail('Confirm from a fresh SSH connection. Existing PF states can mask an access problem.');
    }
    verify_live_rules(management_rules($transaction['spec'], $transaction['token'], true,
        $transaction['tracker_base']));
    require_trial_time($transaction);
    $transaction['phase'] = 'committing';
    save_json(pending_path(), $transaction);
    overlay_management_rules($transaction, true);
    if (write_config('pf-start confirmed management allowlist') === false) {
        fail('Saving the confirmed rules failed; the watchdog will attempt rollback.');
    }
    // Runtime rules are already tested. Saving them avoids a second filter reload.
    $transaction['phase'] = 'confirmed';
    $transaction['closed_utc'] = gmdate('c');
    save_json(pending_path(), $transaction);
    record_action('management-confirmed', ['token' => $transaction['token']]);
    echo "Management rules saved. The watchdog will leave this confirmed transaction in place.\n";
}
