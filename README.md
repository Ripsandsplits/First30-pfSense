**pfSense Competition Kit 0.2.0**

This kit provides separate commands for an opening audit, local password rotation,
session removal, staged management restrictions, and individual service restarts.
Run it from console menu option 8 on a practice pfSense VM first.

The default command saves an audit and a protected configuration backup. Commands
that change credentials, sessions, services, or rules require `--apply`. Reboot is
a separately selected command.

**1. Extract the kit and run the opening audit**

Copy the ZIP to the firewall using an event-approved transfer method. Extract it
under `/root` using the FreeBSD archive utility.

```sh
cd /root
tar -xf pfsense-competition-kit-0.2.0.zip
cd pfsense-competition-kit
sh pf-start.sh help
sh pf-start.sh audit
```

Keep the whole directory together. The launcher loads the PHP files under `lib`.
It requires root/UID 0, the pfSense PHP CLI, and current configuration APIs such
as `config_get_path()`. Optional commands also check their native service/session
APIs. A missing API produces an error that identifies the required adaptation.

The audit includes privileged accounts and why they were selected, effective
local group privileges, SSH key-line digests, management settings, interfaces,
routes, listening sockets, active PF/NAT rules, terminal metadata, and service
status. Configuration review hints identify scheduled jobs, installed packages,
and early/after-boot commands. Inspect those entries in the GUI and compare them
with the team packet. Package-specific persistence and arbitrary sudo policies
still need a human review.

Audit reports, backups, transaction state, and a timestamped action log are kept
under `/conf/pf-start`, with root-only permissions. The backup `config.xml`
contains sensitive credentials, hashes, certificates, and keys. Keep it inside
the approved competition environment. GUI session reports show opaque hashes
of session filenames, rather than usable session-cookie identifiers. The saved
session-file list can include anonymous browser sessions.

Each run also saves `master.passwd.reference` as a protected reference for OS-only
accounts. It contains password hashes. Use the console and native account tools
for recovery; restoring this reference requires rebuilding the OS account databases.

**2. Review and rotate local credentials**

Preview the default selection. It includes local administrators, root-capable GUI
privileges, UID-0/wheel accounts, and shell users because they may have sudo rights.
Disabled, expired, and locked accounts are excluded from rotation.

```sh
sh pf-start.sh rotate
sh pf-start.sh rotate --apply
```

Each selected account receives its own interactive native password prompt. The
built-in administrator updates root's password through pfSense. Passwords are
never passed as command arguments or stored by the kit. The native tools still
operate within the firewall's normal logging and configuration history.

For a smaller scope, use explicit usernames. These select only the named accounts.

```sh
sh pf-start.sh rotate --user admin
sh pf-start.sh rotate --user admin --apply
```

To target only passwords matching `pfsense`, the username, or an empty password,
add `--defaults-only`. A custom password may still be known to Red Team, so choose
the scope using the competition packet and your team's plan.

The kit verifies that the hash changed, the account's identity/disabled/expiration
state stayed consistent, and managed OS hashes match the configuration. It also
checks root synchronization. Open a NEW login to verify the actual authentication
path. Keep your console available until that succeeds.

Remote GUI authentication and HA synchronization block password rotation until
the handler is adapted for that deployment. LDAP/RADIUS passwords, VPN secrets,
and SSH authorized keys are separate credentials. Review SSH keys through User
Manager. Existing keys can authenticate after a password change.

A failure stops the remaining password sequence and reports the verified changes.
Earlier successful changes remain active. A native tool can change a password
before reporting a failure, so inspect the account whose attempt was interrupted.
Retry using the credentials that are now active. Coordinate with teammates and
avoid concurrent GUI configuration edits during password rotation.

**3. Review and remove unwanted sessions**

```sh
sh pf-start.sh sessions
sh pf-start.sh sessions-kill --tty pts/2
sh pf-start.sh sessions-kill --tty pts/2 --apply
```

Choose a terminal that actually appears in your inventory. To signal every other
detected interactive terminal, use `sessions-kill --others`, then add `--apply`
after reviewing the preview. The kit protects the operator's current terminal,
captures before/after metadata, and sends SIGTERM. A process may ignore SIGTERM;
inspect the after-report. Background processes and SSH connections without a
terminal remain visible in the process snapshot and require separate review.

GUI sessions have a separate command. Use an opaque key from `sessions`.

```sh
sh pf-start.sh gui-revoke --session SESSION_KEY
sh pf-start.sh gui-revoke --session SESSION_KEY --apply
sh pf-start.sh gui-revoke --all --apply
```

This briefly stops PHP-FPM, removes the selected saved PHP session files, and
restarts PHP-FPM if it was running. Other browser requests can be interrupted.
All-session revocation affects every file-backed PHP session in that GUI session
directory. Custom session handlers or nested storage layouts cause an error.
The kit restores PHP-FPM through the native restart script even if deletion fails.
If the GUI recovery fails, use the console's Restart PHP-FPM option.

**4. Stage management restrictions using your actual topology**

Identify every management ingress interface, the actual GUI/SSH TCP ports, and the
source addresses your team and required competition staff will use. Include any
scoring or support sources that need those management services. A port forward
to an internal web server has a different destination from the firewall itself.
Choose the ports carefully when the firewall also hosts HAProxy or another scored
application. Only the selected interfaces and TCP ports are restricted.

The address `192.0.2.10` below is a documentation example. Replace it with the
management source address as the firewall sees it. Replace the interface/ports
as needed. Repeat `--allow` and `--interface` for additional sources/interfaces.
IPv6 sources use their IPv6 CIDR. The kit blocks unmatched sources in BOTH IP
families when enforcing the selected ports, including when only IPv4 is allowed.

```sh
sh pf-start.sh management-stage --interface lan --allow 192.0.2.10/32 --ports 443,22 --timeout 300
```

After reviewing that plan and verifying recovery-console access, stage it.

```sh
sh pf-start.sh management-stage --interface lan --allow 192.0.2.10/32 --ports 443,22 --timeout 300 --console-ready --apply
```

Staging adds runtime allow rules while keeping existing restrictions and the
anti-lockout setting intact. It prints a transaction token and arms a watchdog.
The timeout is for the ENTIRE stage/enforce/confirm sequence. It accepts 60 to
600 seconds, with 180 seconds as the default.

Open a fresh allowed management connection, then replace `TOKEN` with the printed
token and enforce the trial.

```sh
sh pf-start.sh management-enforce --token TOKEN --access-tested --apply
```

Enforcement adds quick floating blocks below the explicit source allows, limited
to inbound TCP management ports addressed to the firewall. It disables automatic
LAN anti-lockout in the trial when that protection would override the selected
scope. All business rules are retained. Existing states are left to the native
filter reload behavior; the kit never requests a blanket state-table flush.

Test another NEW GUI/SSH login after enforcement. Existing connections can keep
working through existing PF states even when a new connection would fail. If
confirming over SSH, use a new connection, with SSH connection multiplexing
disabled. The kit rejects confirmation using the same SSH connection tuple as
the enforcement command. When running from the console, `--access-tested` is your
assertion that you tested a fresh remote login.

```sh
sh pf-start.sh management-confirm --token TOKEN --access-tested --apply
```

Confirmation saves the tested rules. Until that point, the trial exists in the
runtime ruleset and is absent from the saved configuration. The watchdog reloads
saved rules when an unconfirmed trial expires. A reboot before confirmation also
loads the saved configuration. Other GUI/package filter reloads may replace a
runtime trial; the kit checks expected rule labels before confirming.

Inspect or roll back a pending trial with these commands.

```sh
sh pf-start.sh management-status
sh pf-start.sh management-rollback --token TOKEN --apply
```

Other mutating kit commands are blocked during a pending trial. The kit detects
saved-configuration edits between staging and confirmation. Rollback preserves
unrelated saved changes, and handles a partial commit by removing this transaction's
tagged rules and restoring the anti-lockout field it changed. Old watchdogs leave
confirmed transactions alone. If a timeout recovery fails, the pending state and
watchdog log remain available. A subsequent kit command retries an expired trial's
rollback. Native reload or boot failure can still require console recovery.

HA synchronization blocks automated management changes. Confirming across peers
requires a topology-specific procedure.

**5. Restart a selected service and verify it**

```sh
sh pf-start.sh services
sh pf-start.sh service-restart --service SERVICE_KEY
sh pf-start.sh service-restart --service SERVICE_KEY --apply
```

Replace `SERVICE_KEY` with the opaque key from the service inventory. Keys include
instance identity so separate OpenVPN instances can be distinguished. The kit
uses pfSense's service controller and checks whether the target reports running.
If it cannot distinguish entries, it stops and directs you to the GUI.

The special key `gui` restarts the GUI web server and PHP-FPM.

```sh
sh pf-start.sh service-restart --service gui --apply
```

Verify application behavior and scoring after each restart. A running process
does not establish that the application is working for clients.

**6. Check reachability and keep a change record**

```sh
sh pf-start.sh check --tcp 192.0.2.20:443 --tcp 192.0.2.30:25
```

Use real service endpoints in place of these documentation addresses. IPv6 uses
`--tcp '[2001:db8::20]:443'`. These probes run from the firewall and verify only TCP
reachability. Check content, authentication, DNS behavior, and scoring from the
required client network too. The command exits 2 when a target fails.

Review `/conf/pf-start/actions.jsonl` and the run directories after a change. They
record timestamps, selections, attempted changes, and verification outcomes. The
kit retains logs and evidence. Protect backups and reports under the event rules.

**7. Reboot only when deliberately selected**

```sh
sh pf-start.sh reboot --console-ready --apply
```

This saves a backup, logs the request, and reboots. It interrupts traffic, VPNs,
and your shell session. Password rotation and session revocation do not invoke it.

**Validation and scope**

Shell syntax and PHP parsing are checked. Sixty automated regression checks run under
PHP 8.3 in WebAssembly with mocked pfSense account, configuration, service, and
filter APIs. The tests cover privilege inheritance, account selection, credential
verification, CIDR validation, operator-session protection, management previews,
staging, enforcement, confirmation, rollback, concurrent saved-configuration edits,
service targeting, and saved-session removal.

Full integration has not been tested on an actual pfSense CE or Plus firewall.
Native filter generation, watchdog process behavior, account prompts, PHP-FPM
handling, and application availability must be validated on your practice VM.
Retain console access and verify both allowed and denied management sources in
that test. Then practice the sequence with your whole team and the event packet.

Confirm your event's rules for prewritten scripts, publication, freezing, and
approval before competition use.

**Sources used for the implementation**

- User Manager shell commands and password handling. https://docs.netgate.com/pfsense/en/latest/usermanager/shell.html
- Management settings and anti-lockout behavior. https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html
- SSH access, authorized keys, and sudo considerations. https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html
- Native service control and PHP shell tooling. https://docs.netgate.com/pfsense/en/latest/development/php-shell.html
- Firewall-rule configuration and the firewall-self destination. https://docs.netgate.com/pfsense/en/latest/firewall/configure.html
- State-table behavior after rule changes. https://docs.netgate.com/pfsense/en/latest/troubleshooting/firewall.html
- Configuration storage and dynamically generated runtime files. https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html
- Native account logic. https://github.com/pfsense/pfsense/blob/master/src/etc/inc/auth.inc
- Native filter reload implementation. https://github.com/pfsense/pfsense/blob/master/src/etc/inc/filter.inc
- Published national competition rules. https://nationalccdc.org/rules.html
