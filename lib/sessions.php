<?php
namespace PFStart;
use RuntimeException;
use Throwable;
/* Terminal and GUI session inventory. No password or session-cookie output. */

function terminal_snapshot() {
    $who = require_command_success(['/usr/bin/who']);
    $processes = require_command_success(['/bin/ps', '-axo', 'pid=,ppid=,uid=,tty=,comm=']);
    $current = trim((string)getenv('PF_START_TTY'));
    $current = preg_replace('#^/dev/#', '', $current);
    $protected = [$current];
    if (substr($current, 0, 3) === 'tty') {
        $protected[] = substr($current, 3);
    }
    $terminals = [];
    foreach (explode("\n", trim($processes)) as $line) {
        $fields = preg_split('/\s+/', trim($line), 5);
        if (count($fields) !== 5) {
            continue;
        }
        [$pid, $parent, $uid, $terminal, $command] = $fields;
        if (in_array($terminal, ['?', '-', '??'], true)) {
            continue;
        }
        if (!preg_match('#(^|/)(-?(sh|tcsh|csh|bash|zsh|fish)|login|sshd(-session)?|rc\.initial)$#', $command)) {
            continue;
        }
        $terminals[$terminal] = ['tty' => $terminal,
            'current' => in_array($terminal, $protected, true)];
    }
    return ['time_utc' => gmdate('c'), 'current_tty' => $current,
        'terminals' => array_values($terminals), 'who' => $who, 'processes' => $processes];
}

function terminal_targets($snapshot, $requested, $others) {
    if (!$requested && !$others) {
        fail('Choose --tty TTY or --others.');
    }
    if ($snapshot['current_tty'] === '' || $snapshot['current_tty'] === 'not a tty') {
        fail('A terminal is required so the operator session can be protected.');
    }
    if ($requested && $others) {
        fail('Choose --tty or --others, rather than combining them.');
    }
    $found = [];
    foreach ($snapshot['terminals'] as $terminal) {
        if ($terminal['current']) {
            if (in_array($terminal['tty'], $requested, true)) {
                fail('The operator terminal is protected.');
            }
            continue;
        }
        if ($others || in_array($terminal['tty'], $requested, true)) {
            $found[] = $terminal['tty'];
        }
    }
    foreach ($requested as $terminal) {
        if (!in_array($terminal, $found, true)) {
            fail('Terminal is absent or protected: ' . $terminal);
        }
    }
    return $found;
}

function gui_session_directory() {
    if (!function_exists('phpsession_begin') || !function_exists('phpsession_end')) {
        fail('This GUI session manager is unsupported.');
    }
    ob_start();
    try {
        phpsession_begin();
        $handler = ini_get('session.save_handler');
        $path = session_save_path();
        phpsession_end(true);
    } finally {
        ob_end_clean();
    }
    if ($handler !== 'files' || strpos($path, ';') !== false) {
        fail('Custom GUI session storage requires version-specific handling.');
    }
    $path = realpath($path === '' ? sys_get_temp_dir() : $path);
    if ($path === false || $path === '/' || !is_writable($path)) {
        fail('Cannot safely determine the GUI session directory.');
    }
    return $path;
}

function gui_sessions($directory) {
    $result = [];
    $files = glob($directory . '/sess_*');
    if ($files === false) {
        fail('Cannot enumerate GUI sessions.');
    }
    foreach ($files as $file) {
        if (is_link($file) || !is_file($file)) {
            fail('Unexpected object in the GUI session directory.');
        }
        // The identifier displayed to the operator cannot be used as a cookie.
        $key = substr(hash('sha256', basename($file)), 0, 20);
        $result[$key] = ['key' => $key, 'last_modified_utc' => gmdate('c', filemtime($file)),
            'size_bytes' => filesize($file)];
    }
    return $result;
}

function revoke_gui_sessions($directory, $requested, $all) {
    $files = glob($directory . '/sess_*');
    if ($files === false) {
        fail('Cannot enumerate GUI sessions.');
    }
    $removed = [];
    foreach ($files as $file) {
        $key = substr(hash('sha256', basename($file)), 0, 20);
        if (!$all && !in_array($key, $requested, true)) {
            continue;
        }
        if (is_link($file) || !is_file($file) || !unlink($file)) {
            fail('Could not revoke GUI session ' . $key);
        }
        $removed[] = $key;
    }
    return $removed;
}
