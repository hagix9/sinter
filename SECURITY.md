# Security Policy

Sinter connects to hosts over SSH and, with `--sudo`, changes them as root.
A vulnerability in it can affect every host it manages, so please report
suspected vulnerabilities privately, as described below.

## Supported versions

Sinter has a single release line. Security fixes are made on `main` and
shipped in a new release; earlier releases are not patched. Only the
[latest release](https://github.com/hagix9/sinter/releases/latest) receives
security fixes, so the fix for a vulnerability in an older version is to
upgrade.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:

1. Open <https://github.com/hagix9/sinter/security/advisories/new>
   (or **Security** → **Report a vulnerability** in this repository).
2. Describe the problem. Only you and the repository maintainers can see the
   report.

Do **not** report a suspected vulnerability in a public issue, pull request,
or discussion.

A vulnerability is anything in this repository that breaks one of Sinter's
[security and safety properties](README.md#security-and-safety-properties)
or otherwise lets an attacker gain access or privileges they should not
have. Examples: SSH host-key verification being bypassed, a remote command
having its argv reinterpreted by a shell, a file mutation escaping its trust
boundary, `plan` or `audit` changing a target, or a sensitive value appearing
in any output. Ordinary bugs go to the [issue tracker](https://github.com/hagix9/sinter/issues)
instead; see [Contributing](https://sinter.fulltrust.co.jp/en/contributing/).

A useful report includes:

- the Sinter version (`sinter --version`) and how it was installed;
- the controller OS and the target OS and version;
- the smallest recipe and command line that reproduce the problem;
- what happened, what you expected, and the impact you see;
- whether the problem is already known publicly.

Replace real hostnames, credentials, keys, and tokens with placeholders.

## Disclosure

Please do not disclose the vulnerability publicly until a fixed release is
available or we have agreed on a disclosure date together.

## What to expect

Sinter is a small project. Reports are handled on a best-effort basis,
without a fixed response time. After you report:

- the report is acknowledged, and discussion continues in the private
  advisory;
- if it is confirmed, the fix is shipped in a new release and a GitHub
  security advisory is published, crediting you unless you ask otherwise;
- if it is not treated as a vulnerability, you get an explanation, and you
  may be asked to file it as a public issue instead.
