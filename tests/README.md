Run these checks on a Linux workstation (or WSL) with Node.js 20 or newer:

```sh
cd tests
npm ci
npm test
```

The pinned PHP WebAssembly runtime supplies PHP 8.5. Host commands and pfSense
APIs are simulated; the tests do not access or change a firewall. Test files and
generated password hashes are disposable fixtures. Regression test directories
are created in the workstation's temporary directory and removed on success.

`check-cli.mjs` executes the whole CLI entry point against modern and legacy
configuration-loader contracts. It checks that authentication initialization sees
the configuration, audit inspection never starts a PHP browser session, session
files survive unchanged, group privileges are retained without missing-member
warnings, and custom session storage prevents destructive revocation. It also
uses actual PHP compile/runtime warnings to check private diagnostic storage,
deduplication, visible kit warnings, and error-handler restoration.

`check-regressions.mjs` covers account targeting and credential verification,
session selection and removal, service identity, management restrictions,
confirmation, rollback, and concurrent saved-configuration edits.

Passing these tests does not establish compatibility with every pfSense release.
Validate native service status, PHP-FPM storage, interactive credential prompts,
filter rules, and application availability on a practice VM with console access.
