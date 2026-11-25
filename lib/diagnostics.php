<?php
namespace PFStart;
/* Keep native-library warnings as private evidence without masking kit errors. */

function native_diagnostics_begin($context) {
    set_error_handler(function ($severity, $message, $file, $line) use ($context) {
        if (!(error_reporting() & $severity) ||
            (strpos($file, '/etc/inc/') !== 0 &&
             strpos($file, '/usr/local/pfSense/') !== 0 &&
             strpos($file, '/usr/local/pkg/') !== 0)) {
            return false;
        }
        if (!in_array($severity, [E_WARNING, E_USER_WARNING, E_NOTICE, E_USER_NOTICE,
            E_DEPRECATED, E_USER_DEPRECATED], true)) {
            return false;
        }
        $key = hash('sha256', json_encode([$context, $severity, $message, $file, $line]));
        $warnings = &$GLOBALS['PFSTART_NATIVE_WARNINGS'];
        if (!is_array($warnings)) {
            $warnings = [];
        }
        if (!isset($warnings[$key])) {
            $warnings[$key] = ['context' => $context, 'severity' => $severity,
                'message' => $message, 'file' => $file, 'line' => $line, 'occurrences' => 0];
        }
        $warnings[$key]['occurrences']++;
        return true;
    });
}

function native_diagnostics_end() {
    restore_error_handler();
}

function native_call($context, $callback) {
    native_diagnostics_begin($context);
    try {
        return $callback();
    } finally {
        native_diagnostics_end();
    }
}

function native_warning_summary() {
    $warnings = array_values($GLOBALS['PFSTART_NATIVE_WARNINGS'] ?? []);
    return ['occurrences' => array_sum(array_column($warnings, 'occurrences')),
        'unique_warnings' => count($warnings),
        'contexts' => array_values(array_unique(array_column($warnings, 'context')))];
}

function save_native_warnings($directory = null) {
    $summary = native_warning_summary();
    if ($summary['occurrences'] === 0) {
        return null;
    }
    $saved = $GLOBALS['PFSTART_NATIVE_WARNINGS_SAVED'] ?? null;
    if ($saved && $saved['occurrences'] === $summary['occurrences']) {
        return $saved['path'];
    }
    $directory = $directory ?? PF_START_STATE . '/diagnostics';
    $path = $directory . '/native-warnings-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.json';
    save_json($path, ['time_utc' => gmdate('c'), 'php_version' => PHP_VERSION,
        'summary' => $summary, 'warnings' => array_values($GLOBALS['PFSTART_NATIVE_WARNINGS']),
        'review' => 'Native inventory can be incomplete when its libraries warn. Verify affected services and configuration.']);
    $GLOBALS['PFSTART_NATIVE_WARNINGS_SAVED'] = ['occurrences' => $summary['occurrences'], 'path' => $path];
    return $path;
}

function report_native_warnings() {
    $path = save_native_warnings();
    if ($path !== null) {
        $summary = native_warning_summary();
        echo 'Native pfSense warnings captured: ', $summary['occurrences'],
            '. Review affected inventory; details: ', $path, "\n";
    }
}
