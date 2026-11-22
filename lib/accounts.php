<?php
namespace PFStart;
use RuntimeException;
use Throwable;

function fail($message) {
    throw new RuntimeException($message);
}

function password_hash_for_user($user) {
    foreach (['bcrypt-hash', 'sha512-hash', 'password', 'md5-hash'] as $key) {
        if (!empty($user[$key])) {
            return (string)$user[$key];
        }
    }
    return '';
}

function weak_password($hash, $name) {
    $hash = preg_replace('/^\*LOCKED\*/', '', $hash);
    if ($hash === '') {
        return true;
    }
    foreach (['pfsense', $name] as $candidate) {
        if (password_verify($candidate, $hash) ||
            hash_equals($hash, crypt($candidate, $hash)) ||
            (strlen($hash) === 32 && hash_equals($hash, md5($candidate)))) {
            return true;
        }
    }
    return false;
}

function system_users() {
    $lines = file('/etc/master.passwd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        fail('Cannot read the local account database.');
    }
    $users = [];
    foreach ($lines as $line) {
        if ($line[0] === '#') {
            continue;
        }
        $fields = explode(':', $line);
        if (count($fields) === 10) {
            $users[$fields[0]] = $fields;
        }
    }
    return $users;
}

function root_page_privileges() {
    // pfSense labels GUI privileges which grant effective root access in each
    // page's PRIV declaration. Read these declarations without executing pages.
    $privileges = ['page-diagnostics-command', 'page-diagnostics-backup-restore'];
    foreach (glob('/usr/local/www/*.php') as $page) {
        $contents = file_get_contents($page);
        if ($contents === false) {
            fail('Cannot inspect GUI privilege declarations.');
        }
        preg_match_all('/##\|\+PRIV(.*?)##\|\-PRIV/s', $contents, $blocks);
        foreach ($blocks[1] as $block) {
            if (strpos($block, 'standard-warning-root') !== false &&
                preg_match('/##\|\*IDENT=([^\s]+)/', $block, $match)) {
                $privileges[] = $match[1];
            }
        }
    }
    return array_unique($privileges);
}

function account_inventory($requested = []) {
    $osUsers = system_users();
    $groups = config_get_path('system/group', []);
    $rootPages = root_page_privileges();
    $wheel = [];
    foreach (file('/etc/group', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $fields = explode(':', $line);
        if (($fields[0] ?? '') === 'wheel') {
            $wheel = explode(',', $fields[3] ?? '');
        }
    }
    $result = [];
    $known = [];
    $uidZero = 0;
    foreach (config_get_path('system/user', []) as $user) {
        $name = username_ok((string)($user['name'] ?? ''));
        $known[$name] = true;
        $memberships = local_user_get_groups($user, true);
        $privileges = (array)($user['priv'] ?? []);
        foreach ($groups as $group) {
            if (in_array($group['name'] ?? '', $memberships, true)) {
                $privileges = array_merge($privileges, (array)($group['priv'] ?? []));
            }
        }
        $reasons = [];
        if (isset($user['uid']) && (string)$user['uid'] === '0') {
            $uidZero++;
            $reasons[] = 'UID-0 administrator and root password';
        }
        if (in_array('admins', $memberships, true) || in_array('page-all', $privileges, true)) {
            $reasons[] = 'administrator privileges';
        }
        if (in_array('user-shell-access', $privileges, true)) {
            $reasons[] = 'shell access, inspect sudo rights';
        }
        if (array_intersect($rootPages, $privileges)) {
            $reasons[] = 'root-capable GUI privilege';
        }
        if (($osUsers[$name][2] ?? '') === '0' && (string)($user['uid'] ?? '') !== '0') {
            $reasons[] = 'OS UID differs from configured UID, investigate';
        }
        if (in_array($name, $wheel, true) || ($osUsers[$name][3] ?? '') === '0') {
            $reasons[] = 'wheel membership';
        }
        $disabled = isset($user['disabled']);
        $expires = $user['expires'] ?? null;
        $expired = $expires !== null && strtotime($expires) !== false && strtotime($expires) < time();
        $keys = base64_decode($user['authorizedkeys'] ?? '', true);
        $keyLines = preg_split('/\R/', trim($keys === false ? '' : $keys));
        $keyDigests = [];
        foreach ($keyLines as $line) {
            if (trim($line) !== '') {
                $keyDigests[] = hash('sha256', trim($line));
            }
        }
        $result[$name] = ['name' => $name, 'kind' => 'managed', 'uid' => $user['uid'] ?? null,
            'groups' => $memberships, 'privileges' => array_values(array_unique($privileges)),
            'reasons' => $reasons, 'privileged' => (bool)$reasons,
            'disabled' => $disabled, 'expired' => $expired, 'locked' => false,
            'known_default' => weak_password(password_hash_for_user($user), $name),
            'authorized_key_line_sha256' => $keyDigests];
    }
    if ($uidZero !== 1) {
        fail('Expected one configured UID-0 administrator; investigate the account configuration.');
    }
    foreach ($osUsers as $name => $fields) {
        if ($name === 'root' || isset($known[$name])) {
            continue;
        }
        $privileged = $fields[2] === '0' || $fields[3] === '0' || in_array($name, $wheel, true);
        if (!$privileged && !in_array($name, $requested, true)) {
            continue;
        }
        username_ok($name);
        $locked = $fields[1] !== '' && ($fields[1][0] === '*' || $fields[1][0] === '!');
        $expired = ctype_digit($fields[6]) && (int)$fields[6] > 0 && (int)$fields[6] < time();
        $result[$name] = ['name' => $name, 'kind' => 'os', 'uid' => $fields[2],
            'reasons' => ['OS-only account, investigate origin and persistence'],
            'privileged' => $privileged, 'disabled' => false, 'expired' => $expired,
            'locked' => $locked, 'known_default' => weak_password($fields[1], $name)];
    }
    foreach ($requested as $name) {
        username_ok($name);
        if (!isset($result[$name])) {
            fail('No local account named ' . $name . '. Use its pfSense username; root is updated through admin.');
        }
    }
    ksort($result);
    return $result;
}

function rotation_targets($inventory, $requested, $defaultsOnly) {
    return array_values(array_filter($inventory, function ($account) use ($requested, $defaultsOnly) {
        $selected = $requested ? in_array($account['name'], $requested, true) : $account['privileged'];
        return $selected && !$account['disabled'] && !$account['expired'] && !$account['locked'] &&
            (!$defaultsOnly || $account['known_default']);
    }));
}

function account_fingerprint($account) {
    $name = $account['name'];
    $osUsers = system_users();
    if ($account['kind'] === 'os') {
        if (!isset($osUsers[$name])) {
            fail('OS account disappeared: ' . $name);
        }
        return ['hash' => hash('sha256', $osUsers[$name][1]),
            'state' => [$osUsers[$name][2], $osUsers[$name][3], $osUsers[$name][6]]];
    }
    foreach (config_get_path('system/user', []) as $user) {
        if (($user['name'] ?? '') === $name) {
            return ['hash' => hash('sha256', password_hash_for_user($user)),
                'state' => [(string)$user['uid'], isset($user['disabled']), $user['expires'] ?? null]];
        }
    }
    fail('Configured account disappeared: ' . $name);
}

function verify_rotation($account, $before) {
    $after = account_fingerprint($account);
    $name = $account['name'];
    if ($after['state'] !== $before['state']) {
        fail('Account identity or disabled/expiration state changed: ' . $name);
    }
    if (hash_equals($before['hash'], $after['hash'])) {
        fail('Password hash did not change: ' . $name);
    }
    $osUsers = system_users();
    $hash = $osUsers[$name][1] ?? '';
    if ($account['kind'] === 'managed') {
        foreach (config_get_path('system/user', []) as $user) {
            if (($user['name'] ?? '') !== $name) {
                continue;
            }
            $expected = preg_replace('/^\*LOCKED\*/', '', password_hash_for_user($user));
            if (!hash_equals($expected, preg_replace('/^\*LOCKED\*/', '', $hash))) {
                fail('The configuration and OS password hashes differ: ' . $name);
            }
            if ((string)$user['uid'] === '0' && !hash_equals($expected, $osUsers['root'][1] ?? '')) {
                fail('Root password synchronization failed.');
            }
        }
    }
    if (weak_password($hash, $name)) {
        fail('The resulting password is still empty or matches a known default: ' . $name);
    }
}

