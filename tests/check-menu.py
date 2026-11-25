"""Exercise the real POSIX shell menu with a recording backend, never a firewall."""
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parent.parent
checks = 0


def check(condition, label):
    global checks
    assert condition, label
    checks += 1


with tempfile.TemporaryDirectory(prefix="pf-start-menu-") as temporary:
    root = Path(temporary)
    trace = root / "calls.jsonl"
    locks = root / "locks.log"
    environment = dict(os.environ, PF_TEST_TRACE=str(trace), PF_TEST_LOCK=str(locks))
    (root / "HELP.txt").write_text((repo / "HELP.txt").read_text())
    (root / "record.py").write_text('''import json,os,sys
args=sys.argv[1:]
if '--' in args: args=args[args.index('--')+1:]
with open(os.environ['PF_TEST_TRACE'],'a') as f: f.write(json.dumps(args)+'\\n')
print('SIMULATED',json.dumps(args))
sys.exit(7 if args and args[0]==os.environ.get('PF_TEST_FAIL') else 0)
''')
    backend = 'exec python3 ' + shlex.quote(str(root / "record.py")) + ' "$@"\n'
    (root / "pf-start.sh").write_text('#!/bin/sh\n' + backend)
    seen_commands = set()

    def calls():
        return [json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else []

    def drive(text, fail=""):
        trace.unlink(missing_ok=True)
        result = subprocess.run(
            ["/bin/sh", "-c", 'set -eu; kit_dir=$1; . "$2"; menu_main',
             "menu-test", str(root), str(repo / "lib/menu.sh")],
            input=text, text=True, capture_output=True, timeout=8,
            env=dict(environment, PF_TEST_FAIL=fail))
        assert result.returncode == 0, result.stdout + result.stderr
        seen_commands.update(args[0] for args in calls() if args)
        return calls(), result.stdout

    actual, output = drive("0\n")
    check(not actual and "View saved logs and reports" in output, "menu exit runs no tool")
    actual, output = drive("1\n\n0\n")
    check(actual == [["audit"]], "opening audit routes without mutation flags")
    actual, output = drive("2\n\n\n0\n")
    check(actual == [["backup"]], "blank apply answer cancels")
    actual, output = drive("2\ny\n\n0\n")
    check(actual == [["backup"], ["backup", "--apply"]], "backup previews before apply")
    actual, output = drive("2\ny\n0\n", fail="backup")
    check(actual == [["backup"]] and "status 7" in output, "failed preview never applies and menu survives")
    actual, output = drive("3\nadmin ops\ny\ny\n\n0\n")
    rotate = ["rotate", "--user", "admin", "--user", "ops", "--defaults-only"]
    check(actual == [rotate, rotate + ["--apply"]], "password selection preserves usernames and defaults scope")
    actual, output = drive("3\n* $(touch " + str(root / "proof") + ")\nn\nn\n\n0\n")
    check("*" in actual[0] and "$(touch" in actual[0] and not (root / "proof").exists(), "typed text is never evaluated or expanded as a wildcard")
    actual, output = drive("4\n\n0\n")
    check(actual == [["sessions"]], "session listing routes correctly")
    actual, output = drive("5\npts/2\ny\n\n0\n")
    check(actual == [["sessions"], ["sessions-kill", "--tty", "pts/2"], ["sessions-kill", "--tty", "pts/2", "--apply"]], "terminal selection is explicit and previewed")
    actual, output = drive("5\nothers\nn\n\n0\n")
    check(actual[-1] == ["sessions-kill", "--others"], "other-terminal selection is available")
    actual, output = drive("6\nkey123\ny\n\n0\n")
    check(actual[-1] == ["gui-revoke", "--session", "key123", "--apply"], "GUI session keys reach the revocation handler")
    actual, output = drive("6\nall\nn\n\n0\n")
    check(actual[-1] == ["gui-revoke", "--all"], "all-GUI-session revocation can be previewed")
    actual, output = drive("7\n\n0\n")
    check(actual == [["services"]], "service inventory is selectable")
    actual, output = drive("8\ngui\ny\n\n0\n")
    check(actual[-1] == ["service-restart", "--service", "gui", "--apply"], "selected service restart retains preview/apply")
    actual, output = drive("9\n192.0.2.1:443 [2001:db8::1]:22\n\n0\n")
    check(actual == [["check", "--tcp", "192.0.2.1:443", "--tcp", "[2001:db8::1]:22"]], "TCP targets retain IPv6 brackets")
    actual, output = drive("10\n1\n0\n\n0\n")
    check(actual == [["management-status"]], "management submenu returns to the main menu")
    actual, output = drive("10\n2\nlan opt1\n192.0.2.10/32 2001:db8::/64\n443,22\n\ny\n0\n\n0\n")
    stage = ["management-stage", "--interface", "lan", "--interface", "opt1", "--allow", "192.0.2.10/32", "--allow", "2001:db8::/64", "--ports", "443,22", "--timeout", "180"]
    check(actual == [stage, stage + ["--console-ready", "--apply"]], "management staging collects sources, ports, timeout and console assertion")
    for number, command in [("3", "management-enforce"), ("4", "management-confirm"), ("5", "management-rollback")]:
        actual, output = drive("10\n" + number + "\ntoken123\ny\n0\n\n0\n")
        flags = ["--apply"] if number == "5" else ["--access-tested", "--apply"]
        check(actual == [["management-status"], [command, "--token", "token123"], [command, "--token", "token123"] + flags], command + " preserves its existing assertions")
    actual, output = drive("11\n\n12\n\n0\n")
    check(actual == [["logs"], ["help"]], "saved logs and help are available from the same menu")
    actual, output = drive("13\ny\n\n0\n")
    check(actual == [["reboot"]], "ordinary yes cannot trigger a reboot")
    actual, output = drive("13\nREBOOT\n\n0\n")
    check(actual[-1] == ["reboot", "--console-ready", "--apply"], "explicit reboot confirmation reaches the guarded handler")
    actual, output = drive("99\n\n0\n")
    check(not actual and "Choose a number" in output, "invalid selection does not run a command")
    actual, output = drive("")
    check(not actual, "EOF exits without a busy loop")
    definitions = (repo / 'lib/pf-start.php').read_text().split('$definitions = [', 1)[1].split('];', 1)[0]
    commands = set(re.findall(r"'([a-z][a-z-]*)'\s*=>\s*\[", definitions))
    check(commands <= seen_commands, 'every native tool has an exercised menu route')

    # Exercise the actual launcher too, replacing only host dependency paths/checks.
    (root / "lib").mkdir()
    (root / "lib/menu.sh").write_text((repo / "lib/menu.sh").read_text())
    (root / "php").write_text('#!/bin/sh\n' + backend)
    (root / "php").chmod(0o700)
    (root / "lockf").write_text('#!/bin/sh\nprintf "lock\\n" >>"$PF_TEST_LOCK"\nshift 4\nexec "$@"\n')
    (root / "lockf").chmod(0o700)
    (root / "php.ini").touch()
    (root / "config.inc").touch()
    launcher = (repo / "pf-start.sh").read_text().replace('$(uname -s)', 'FreeBSD').replace('$(id -u)', '0')
    for native, fixture in [("/usr/local/bin/php", "php"), ("/usr/local/etc/php.ini", "php.ini"),
                            ("/etc/inc/config.inc", "config.inc"), ("/usr/bin/lockf", "lockf")]:
        launcher = launcher.replace(native, str(root / fixture))
    (root / "pf-start.sh").write_text(launcher)
    for args, expected, locked in [([], [], True), (["audit"], ["audit"], True), (["logs", "--list"], ["logs", "--list"], False)]:
        trace.unlink(missing_ok=True)
        locks.unlink(missing_ok=True)
        result = subprocess.run(["/bin/sh", str(root / "pf-start.sh")] + args,
                                input="", text=True, capture_output=True, env=environment, timeout=5)
        check(result.returncode == 0 and calls() == [expected] and locks.exists() == locked,
              "launcher dispatch/lock behavior: " + str(args))
    result = subprocess.run(["/bin/sh", str(root / "pf-start.sh"), "menu"],
                            input="", text=True, capture_output=True, env=environment, timeout=5)
    check(result.returncode != 0 and "interactive terminal" in result.stderr, "explicit menu rejects redirected input")

    trace.unlink(missing_ok=True)
    locks.unlink(missing_ok=True)
    pid, master = pty.fork()
    if pid == 0:
        os.environ.update(environment)
        os.execv("/bin/sh", ["/bin/sh", str(root / "pf-start.sh")])
    captured = b""
    finished = False
    try:
        deadline = time.monotonic() + 8
        sent = False
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                captured += chunk
                if not sent and b"Select:" in captured:
                    check(not locks.exists() and not calls(), "interactive menu holds no operation lock while idle")
                    os.write(master, b"1\n\n0\n")
                    sent = True
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                finished = True
                break
        if not finished:
            done, status = os.waitpid(pid, os.WNOHANG)
            finished = bool(done)
        check(finished and os.waitstatus_to_exitcode(status) == 0 and calls() == [["audit"]],
              "no arguments in a real terminal open the menu and return after an operation")
    finally:
        if not finished:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(master)

print(f"{checks} shell menu/launcher checks passed with a simulated backend.")
