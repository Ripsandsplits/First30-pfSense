<?php
namespace PFStart;
use RuntimeException;
use Throwable;
/* Shared input validation, local evidence storage, and rule construction. */
const PF_START_VERSION = '0.2.1';
const PF_START_STATE = '/conf/pf-start';

function options_for($arguments, $allowed) {
    $result = [];
    for ($i = 0; $i < count($arguments); $i++) {
        $key = $arguments[$i];
        if (!array_key_exists($key, $allowed)) {
            fail('Unknown option ' . $key . '. Use sh pf-start.sh help.');
        }
        if ($allowed[$key] === false) {
            if (isset($result[$key])) {
                fail('Repeated flag ' . $key);
            }
            $result[$key] = true;
        } else {
            $value = $arguments[++$i] ?? '';
            if ($value === '' || substr($value, 0, 2) === '--') {
                fail('A value is required for ' . $key);
            }
            $result[$key][] = $value;
        }
    }
    return $result;
}

function single_option($options, $key, $default = null) {
    $values = $options[$key] ?? [];
    if (count($values) > 1) {
        fail('Specify ' . $key . ' once.');
    }
    return $values[0] ?? $default;
}

function username_ok($name) {
    if (!preg_match('/^[A-Za-z0-9_.][A-Za-z0-9_.-]*$/D', $name)) {
        fail('Unsupported local username.');
    }
    return $name;
}

function secure_directory($path) {
    if (is_link($path)) {
        fail('Refusing a symbolic link for ' . $path);
    }
    if (!is_dir($path) && !mkdir($path, 0700, true)) {
        fail('Cannot create ' . $path);
    }
    if (fileowner($path) !== posix_geteuid() || !chmod($path, 0700)) {
        fail('Cannot secure directory ' . $path);
    }
}

function save_json($path, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        fail('Cannot encode evidence or transaction state.');
    }
    secure_directory(dirname($path));
    $temporary = tempnam(dirname($path), '.pf-start-');
    if ($temporary === false) {
        fail('Cannot allocate a state file.');
    }
    try {
        if (!chmod($temporary, 0600) || file_put_contents($temporary, $json . "\n") === false ||
            !rename($temporary, $path)) {
            fail('Cannot save ' . $path);
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}

function load_json($path) {
    if (is_link($path) || !is_file($path) || fileowner($path) !== posix_geteuid()) {
        fail('Missing or unsafe state file ' . $path);
    }
    $data = json_decode(file_get_contents($path), true);
    if (!is_array($data)) {
        fail('Invalid JSON in ' . $path);
    }
    return $data;
}

function run_command($arguments, $interactive = false) {
    if ($interactive) {
        $descriptors = [0 => ['file', '/dev/tty', 'r'], 1 => STDOUT, 2 => STDERR];
    } else {
        // File-backed output avoids pipe deadlocks for large PF/process reports.
        $output = tmpfile();
        $errors = tmpfile();
        if ($output === false || $errors === false) {
            fail('Cannot allocate command output files.');
        }
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => $output, 2 => $errors];
    }
    $process = proc_open($arguments, $descriptors, $pipes);
    if (!is_resource($process)) {
        fail('Cannot start ' . $arguments[0]);
    }
    $status = proc_close($process);
    if ($interactive) {
        return [$status, '', ''];
    }
    rewind($output);
    rewind($errors);
    $stdout = stream_get_contents($output);
    $stderr = stream_get_contents($errors);
    fclose($output);
    fclose($errors);
    return [$status, $stdout, $stderr];
}

function require_command_success($arguments, $interactive = false) {
    $result = run_command($arguments, $interactive);
    if ($result[0] !== 0) {
        fail('Command failed: ' . $arguments[0] . '. ' . trim($result[2]));
    }
    return $result[1];
}

function record_action($action, $details = []) {
    secure_directory(PF_START_STATE);
    $entry = ['time_utc' => gmdate('c'), 'action' => $action, 'details' => $details];
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    $path = PF_START_STATE . '/actions.jsonl';
    if (is_link($path)) {
        fail('Unsafe action log.');
    }
    if (file_put_contents($path, $line, FILE_APPEND | LOCK_EX) === false || !chmod($path, 0600)) {
        fail('Cannot write the action log.');
    }
    openlog('pf-start', LOG_PID, LOG_AUTHPRIV);
    syslog(LOG_NOTICE, $action);
    closelog();
}

function configuration_backup($reason) {
    secure_directory(PF_START_STATE);
    $directory = PF_START_STATE . '/runs/' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(4));
    secure_directory($directory);
    if (!copy('/conf/config.xml', $directory . '/config.xml') ||
        !chmod($directory . '/config.xml', 0600)) {
        fail('Configuration backup failed before the change.');
    }
    if (!copy('/etc/master.passwd', $directory . '/master.passwd.reference') ||
        !chmod($directory . '/master.passwd.reference', 0600)) {
        fail('OS account reference backup failed before the change.');
    }
    save_json($directory . '/metadata.json', [
        'time_utc' => gmdate('c'), 'reason' => $reason, 'kit_version' => PF_START_VERSION,
        'pfsense_version' => trim(file_get_contents('/etc/version')),
        'sha256' => hash_file('sha256', $directory . '/config.xml')
    ]);
    record_action('backup', ['reason' => $reason, 'directory' => $directory]);
    echo 'Protected recovery backup: ', $directory, "\n";
    return $directory;
}

function parse_cidr($text) {
    $parts = explode('/', $text);
    if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
        fail('Use a literal management IP address or CIDR: ' . $text);
    }
    $bytes = inet_pton($parts[0]);
    $maximum = strlen($bytes) * 8;
    $prefix = $parts[1] ?? (string)$maximum;
    if (!ctype_digit($prefix) || (int)$prefix < 1 || (int)$prefix > $maximum) {
        fail('Invalid or unrestricted management prefix: ' . $text);
    }
    $prefix = (int)$prefix;
    for ($i = 0; $i < strlen($bytes); $i++) {
        $bits = max(0, min(8, $prefix - 8 * $i));
        $bytes[$i] = chr(ord($bytes[$i]) & (0xff << (8 - $bits)));
    }
    return ['address' => inet_ntop($bytes) . '/' . $prefix,
        'ipprotocol' => $maximum === 32 ? 'inet' : 'inet6', 'prefix' => $prefix];
}

function address_in_cidr($address, $network) {
    $candidate = inet_pton($address);
    [$base, $bits] = explode('/', $network);
    $base = inet_pton($base);
    if ($candidate === false || $base === false || strlen($candidate) !== strlen($base)) {
        return false;
    }
    for ($i = 0; $i < strlen($base); $i++) {
        $mask = (0xff << (8 - max(0, min(8, (int)$bits - 8 * $i)))) & 0xff;
        if ((ord($candidate[$i]) & $mask) !== (ord($base[$i]) & $mask)) {
            return false;
        }
    }
    return true;
}

function management_spec($options) {
    $interfaces = array_values(array_unique($options['--interface'] ?? []));
    $sources = array_map(__NAMESPACE__ . '\\parse_cidr', $options['--allow'] ?? []);
    $portString = single_option($options, '--ports', '');
    if (!$interfaces || !$sources || $portString === '') {
        fail('Management staging requires --interface, --allow, and --ports.');
    }
    $configured = config_get_path('interfaces', []);
    foreach ($interfaces as $interface) {
        if (!isset($configured[$interface])) {
            fail('Unknown configured interface ' . $interface);
        }
    }
    $ports = [];
    foreach (explode(',', $portString) as $port) {
        if (!ctype_digit($port) || (int)$port < 1 || (int)$port > 65535) {
            fail('Management ports must be comma-separated TCP port numbers.');
        }
        $ports[] = (string)(int)$port;
    }
    $timeout = single_option($options, '--timeout', '180');
    if (!ctype_digit($timeout) || (int)$timeout < 60 || (int)$timeout > 600) {
        fail('Use a management trial timeout from 60 through 600 seconds.');
    }
    return ['interfaces' => $interfaces, 'sources' => $sources,
        'ports' => array_values(array_unique($ports)), 'timeout' => (int)$timeout];
}

function management_rules($spec, $token, $enforced, $trackerBase) {
    $rules = [];
    foreach ($spec['interfaces'] as $interface) {
        foreach ($spec['ports'] as $port) {
            foreach ($spec['sources'] as $source) {
                $rules[] = ['type' => 'pass', 'interface' => $interface,
                    'floating' => 'yes', 'quick' => 'yes', 'direction' => 'in',
                    'ipprotocol' => $source['ipprotocol'], 'protocol' => 'tcp',
                    'source' => ['address' => $source['address']],
                    'destination' => ['network' => '(self)', 'port' => $port]];
            }
            if ($enforced) {
                foreach (['inet', 'inet6'] as $family) {
                    $rules[] = ['type' => 'block', 'interface' => $interface,
                        'floating' => 'yes', 'quick' => 'yes', 'direction' => 'in',
                        'ipprotocol' => $family, 'protocol' => 'tcp', 'log' => '',
                        'source' => ['any' => ''],
                        'destination' => ['network' => '(self)', 'port' => $port]];
                }
            }
        }
    }
    foreach ($rules as $index => &$rule) {
        $rule['tracker'] = $trackerBase + $index;
        $rule['descr'] = 'PFSTART-' . $token . '-' . $index;
    }
    unset($rule);
    return $rules;
}

function output_json($value) {
    echo json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), "\n";
}
