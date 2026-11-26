---
title: crypto_policy
description: Set the system-wide cryptographic policy of a RHEL-family host with update-crypto-policies.
---

**Purpose:** declare the system-wide cryptographic policy of a RHEL-family
host (`update-crypto-policies`): a base policy such as `DEFAULT` or `FUTURE`,
optionally with subpolicies such as `NO-SHA1`.

## Synopsis

```yaml
- id: crypto
  type: crypto_policy
  with:
    policy: "DEFAULT:NO-SHA1"
```

```toml
[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "DEFAULT:NO-SHA1"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `policy` | yes | string | — | `BASE[:SUBPOLICY...]`. Each part is `[A-Z0-9][A-Z0-9_-]{0,31}`; at most 8 subpolicies; no subpolicy twice. Examples: `DEFAULT`, `FUTURE`, `DEFAULT:NO-SHA1`. |
| `allow_weaker` | no | boolean | `false` | Must be written as a literal `true` to accept a change Sinter would otherwise refuse as possibly weakening cryptography (see below). |

- `policy` may use variables but not facts, registers or sensitive values;
  it is resolved and checked when the recipe is loaded.
- `allow_weaker` cannot come from a variable: the flag has to be visible in
  the recipe text.
- One `crypto_policy` per recipe; a second one is a validation error.

## Rules against silently weakening cryptography

Checked when the recipe is loaded:

- Base `FIPS` is refused, with or without `allow_weaker`. Switching FIPS mode
  needs `fips-mode-setup` and a reboot; Sinter does not do that.
- Base `LEGACY` is refused unless `allow_weaker: true`.
- Subpolicies `NO-SHA1`, `NO-CAMELLIA` and `OSPP` are accepted. Any other
  subpolicy (for example `SHA1`, `AD-SUPPORT`, `AD-SUPPORT-LEGACY`,
  `NO-ENFORCE-EMS`, or a module your site defined) is refused unless
  `allow_weaker: true`, because Sinter cannot tell whether it weakens the
  policy.

Checked in plan and apply, against the policy the host reports, when it
differs from the declared one:

- Lowering the base in the order `LEGACY` < `DEFAULT` < `FUTURE` is refused
  unless `allow_weaker: true`.
- A base outside that order (a custom policy, `EMPTY`) is not ordered:
  changing from or to it is refused unless `allow_weaker: true`.
- Removing a hardening subpolicy (`NO-SHA1`, `NO-CAMELLIA`, `OSPP`) that is
  applied on the host is refused unless `allow_weaker: true`: that weakens
  the policy. Removing any other applied subpolicy needs no flag (for example
  `DEFAULT:SHA1` to `DEFAULT`): the declared policy passed the rules above on
  its own, so the result is a base Sinter knows.
- A host whose current policy is `FIPS` is never changed.

## Expected behavior

- **Observation.** Sinter runs `/usr/bin/update-crypto-policies --show`
  (read-only). Only an exit of zero with exactly one policy line on standard
  output is accepted. Any other exit, extra lines, empty or truncated output
  or a timeout is an error; Sinter does not guess the policy.
- **Plan** compares that line with `policy` exactly (subpolicy order
  included). If they differ, plan checks that the base exists as
  `<BASE>.pol` and every subpolicy as `modules/<SUB>.pmod` under
  `/usr/share/crypto-policies/policies` or `/etc/crypto-policies/policies`.
  A missing definition stops the plan and names it, so an unknown policy is
  refused before anything runs.
- **Apply** runs `/usr/bin/update-crypto-policies --set <POLICY>` as root,
  with no shell. Right before that it observes the policy once more; if it
  is no longer the one the decision was based on, nothing is changed and the
  resource fails (run again). A non-zero exit is a failure. An exit of zero is not trusted
  on its own: the policy is observed again and must equal `policy`,
  otherwise the resource fails. If the tool is killed, times out or the
  connection is lost, the result says the policy may or may not have been
  applied; Sinter does not report success.
- A second apply changes nothing and does not run `--set`.
- **Audit** compares the configured system-wide policy with `policy` and
  reports a difference as drift in `policy`. It says nothing about running
  services: a service started before the last policy change may still use
  the previous policy. An observation that fails, and a host without
  `update-crypto-policies`, are errors.

## Services and SSH

Sinter never restarts a service and never reboots for this resource. Every
plan and apply result that changes the policy carries this note:

- Running services, including `sshd`, keep the previous policy until they are
  restarted.
- A stricter policy can make **new** SSH connections fail (old key types or
  algorithms). Open and verify a second connection before you close the
  current one.
- The vendor recommends a reboot for the policy to take full effect.

A change notifies handlers like any other resource, so a recipe can restart
an application with a `service` handler. Restarting `sshd` that way is your
explicit choice; Sinter does not suggest or do it on its own.

## Unsupported cases

- Hosts without `/usr/bin/update-crypto-policies` (Debian, Ubuntu): plan and
  apply fail with "crypto_policy is not supported on this host
  (update-crypto-policies was not found)"; audit reports an error.
- FIPS mode, in either direction.
- Writing policy or subpolicy definition files. Use a
  [`file`](/en/reference/resources/file/) resource for a site-defined
  `.pol`/`.pmod` file and list it in `depends_on`. When an earlier resource
  of the same run may still create the definition (or install the tool),
  plan reports that instead of failing, and apply checks again.
- Not root: plan adds a note; apply fails before the tool is run.
- Not available through MCP: the observation is not measured on real hosts
  yet.

## Supported systems

- RHEL, Rocky Linux and AlmaLinux 9 and 10.
- Not Debian or Ubuntu.

## Not yet verified on real hosts

The behaviour above is tested against a scripted target. The following has
not been measured on a real RHEL-family host yet:

- that `update-crypto-policies --show` changes nothing, prints exactly one
  line and prints subpolicies in the form they were set
  (`DEFAULT:NO-SHA1`), on EL 9 and EL 10;
- the exit codes and messages of `--set` for an unknown policy or module and
  when not root;
- which subpolicy modules each release ships (for example `NO-CAMELLIA` and
  `OSPP` are not present on every release; a missing one stops the plan);
- how long `--set` takes, and its effect on new SSH connections.

## Examples

Remove SHA-1 from the default policy:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    with:
      policy: "DEFAULT:NO-SHA1"
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "DEFAULT:NO-SHA1"
```

Raise the policy to `FUTURE` and restart an application that should pick it
up:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    notify: [restart-app]
    with:
      policy: FUTURE
handlers:
  - id: restart-app
    service: myapp
    action: restart
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"
notify = ["restart-app"]

[resources.with]
policy = "FUTURE"

[[handlers]]
id = "restart-app"
service = "myapp"
action = "restart"
```

Lower the policy to `LEGACY`, explicitly:

```yaml
version: 1
resources:
  - id: crypto
    type: crypto_policy
    with:
      policy: LEGACY
      allow_weaker: true
```

```toml
version = 1

[[resources]]
id = "crypto"
type = "crypto_policy"

[resources.with]
policy = "LEGACY"
allow_weaker = true
```
