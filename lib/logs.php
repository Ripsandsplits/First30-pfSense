<?php
namespace PFStart;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;
use Throwable;

/* Read-only access to kit reports. Credential recovery backups are not listed. */
function log_files() {
    $root = PF_START_STATE;
    if (is_link($root)) { fail('The log directory must not be a symbolic link.'); }
    if (!is_dir($root)) { return []; }
    if (fileowner($root) !== posix_geteuid()) {
        fail('The log directory is not owned by the current administrator.');
    }
    $root = realpath($root);
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,
        FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if ($file->isLink() || !$file->isFile() || $file->getOwner() !== posix_geteuid() ||
            !preg_match('/\.(?:json|jsonl|log|txt)$/iD', $file->getFilename())) {
            continue;
        }
        $relative = substr($file->getPathname(), strlen($root) + 1);
        $files[] = ['key' => substr(hash('sha256', $relative), 0, 20),
            'path' => $relative, 'size_bytes' => $file->getSize(),
            'modified_utc' => gmdate('c', $file->getMTime()), 'modified' => $file->getMTime()];
    }
    usort($files, function ($a, $b) {
        return ($b['modified'] <=> $a['modified']) ?: strcmp($a['path'], $b['path']);
    });
    return $files;
}

function log_label($text) {
    return preg_replace('/[\x00-\x1F\x7F]/', '', $text);
}

function open_log($entry) {
    $root = realpath(PF_START_STATE);
    $path = PF_START_STATE . '/' . $entry['path'];
    $resolved = realpath($path);
    if ($root === false || is_link(PF_START_STATE) || is_link($path) || $resolved === false ||
        strpos($resolved, $root . '/') !== 0 || !is_file($path) || fileowner($path) !== posix_geteuid()) {
        fail('The selected log is no longer available inside the kit log directory.');
    }
    $parent = dirname($path);
    while ($parent !== PF_START_STATE) {
        if (is_link($parent)) { fail('Refusing a symbolic link in the log path.'); }
        $parent = dirname($parent);
    }
    $before = lstat($path);
    $handle = fopen($path, 'rb');
    if ($handle === false) { fail('Cannot open the selected log.'); }
    $opened = fstat($handle);
    if ($before === false || $opened === false || $opened['ino'] !== $before['ino'] ||
        $opened['dev'] !== $before['dev'] || ($opened['mode'] & 0170000) !== 0100000 ||
        $opened['uid'] !== posix_geteuid()) {
        fclose($handle);
        fail('The selected log changed while it was being opened.');
    }
    return $handle;
}

function log_terminal() {
    return stream_isatty(STDIN) && stream_isatty(STDOUT);
}

function view_log($entry) {
    $handle = open_log($entry);
    try {
        if (!log_terminal()) {
            if (fpassthru($handle) === false) { fail('Could not read the log.'); }
            return;
        }
        echo "\nViewing ", log_label($entry['path']), " (q returns from the viewer)\n";
        if (is_executable('/usr/bin/less')) {
            // Disable shell/editor escapes, history, and input preprocessors.
            $environment = ['TERM' => getenv('TERM') ?: 'xterm', 'PATH' => '/usr/bin:/bin',
                'LESSSECURE' => '1', 'LESSHISTFILE' => '-', 'LESS' => '',
                'LESSOPEN' => '', 'LESSCLOSE' => ''];
            $pager = proc_open(['/usr/bin/less', '-F', '-X'],
                [0 => $handle, 1 => STDOUT, 2 => STDERR], $pipes, null, $environment);
            if (!is_resource($pager)) { fail('Could not start the log viewer.'); }
            if (proc_close($pager) !== 0) { fail('The log viewer exited with an error.'); }
        } else {
            $lines = 0;
            while (($line = fgets($handle, 8192)) !== false) {
                echo preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $line);
                if (++$lines >= 20) {
                    echo "\nEnter for more, q to return: ";
                    $reply = fgets(STDIN);
                    if ($reply === false || strtolower(trim($reply)) === 'q') { break; }
                    $lines = 0;
                }
            }
        }
    } finally {
        fclose($handle);
    }
}

function browse_logs() {
    $page = 0;
    while (true) {
        $files = log_files();
        if (!$files) {
            echo "No saved logs or reports yet. Run an audit first.\n";
            return 0;
        }
        $pages = (int)ceil(count($files) / 15);
        $page = min($page, $pages - 1);
        echo "\nSaved logs and reports, newest first (page ", $page + 1, '/', $pages, ")\n";
        foreach (array_slice($files, $page * 15, 15, true) as $index => $file) {
            printf("%3d) %s  %d bytes  %s\n", $index + 1, $file['modified_utc'],
                $file['size_bytes'], log_label($file['path']));
        }
        echo "Number to view, n = next, p = previous, r = refresh, 0 = back: ";
        $reply = fgets(STDIN);
        if ($reply === false) { return 0; }
        $reply = trim($reply);
        if ($reply === '0') { return 0; }
        if ($reply === 'n') { $page = min($page + 1, $pages - 1); continue; }
        if ($reply === 'p') { $page = max($page - 1, 0); continue; }
        if ($reply === 'r') { continue; }
        if (ctype_digit($reply) && isset($files[(int)$reply - 1])) {
            try { view_log($files[(int)$reply - 1]); }
            catch (Throwable $error) { echo 'Log viewer: ', $error->getMessage(), "\n"; }
        } else {
            echo "Choose a number from the list.\n";
        }
    }
}

function logs_main($arguments) {
    $options = options_for($arguments, ['--list' => false, '--file' => true]);
    $key = single_option($options, '--file');
    if (isset($options['--list']) && $key !== null) { fail('Choose --list or --file KEY.'); }
    if ($key !== null) {
        foreach (log_files() as $entry) {
            if ($entry['key'] === $key) { view_log($entry); return 0; }
        }
        fail('No saved log matches that key. Run logs --list again.');
    }
    if (isset($options['--list']) || !log_terminal()) {
        output_json(['directory' => PF_START_STATE, 'files' => log_files()]);
        return 0;
    }
    return browse_logs();
}
