---
title: dnf_repository
description: Manage the declared keys of one DNF repository section in a .repo file, without weakening package signature checking.
---

:::caution[Not yet verified on real hosts]
`dnf_repository` is tested against Sinter's scripted target only. How DNF
reads a file edited this way, and what `/usr/bin/dnf` links to on each
supported distribution, are not yet measured on real hosts. Anything Sinter
cannot read with certainty is refused, never assumed.
:::

**Purpose:** declare one DNF repository: the `[id]` section of a `.repo` file
under `/etc/yum.repos.d/`. Sinter manages only the keys you declare in only
that section, and keeps every other section, key, comment and blank line of
the file byte for byte.

## Synopsis

```yaml
- id: crb
  type: dnf_repository
  with:
    name: crb
    file: /etc/yum.repos.d/rocky.repo
    enabled: true
```

```toml
[[resources]]
id = "crb"
type = "dnf_repository"

[resources.with]
name = "crb"
file = "/etc/yum.repos.d/rocky.repo"
enabled = true
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | static string | — | Repository id (the section name): `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}`. `main` is refused (it is DNF's own configuration section). |
| `state` | no | string | `present` | `present` or `absent`. |
| `file` | no | static string | `/etc/yum.repos.d/<name>.repo` | The file that holds the section: a plain file name directly inside `/etc/yum.repos.d/` that ends in `.repo`. |
| `description` | no | string | — | The section's `name=` key: one line, 1–256 bytes. |
| `baseurl` | no | string or list | — | `baseurl=`. |
| `mirrorlist` | no | string | — | `mirrorlist=`. |
| `metalink` | no | string | — | `metalink=`. |
| `enabled` | no | boolean | — | `enabled=1` or `enabled=0`. |
| `gpgcheck` | no | boolean | — | Only `true` is accepted: `gpgcheck=1`. |
| `repo_gpgcheck` | no | boolean | — | Only `true` is accepted: `repo_gpgcheck=1`. |
| `gpgkey` | no | string or list | — | `gpgkey=`. |

- `name` and `file` may use variables but not facts or registers.
- With `state: present`, at least one of the fields from `description` to
  `gpgkey` is required. `state: absent` allows only `name` and `file`.
- Only declared keys are managed. A key of the section that you do not
  declare is left alone and is never drift. `baseurl`, `mirrorlist` and
  `metalink` are alternatives: declaring one does **not** remove the others
  from the section.
- To manage a repository that a distribution file defines (for example `crb`
  in `rocky.repo`), set `file` to that file. If the section is not in the
  file and no `baseurl`, `mirrorlist` or `metalink` is declared, the resource
  fails and says to set `file`.
- URLs (`baseurl`, `mirrorlist`, `metalink`): `https://`, `http://` or
  `file:///`, printable ASCII without spaces, at most 2048 bytes, no
  backslash. `$releasever`, `$basearch` and other `$var` tokens are allowed.
  A URL with credentials (`user@host` or `user:password@host`) is refused:
  credentials in repository URLs are not supported.
- `gpgkey`: `file:///` or `https://` only. An `http://` key URL is refused,
  because the key that packages are checked against must not arrive over an
  unauthenticated channel.
- Entries of `baseurl` and `gpgkey` may not contain a comma (DNF splits list
  values at commas); a list has at most 32 entries.
- A value built from a sensitive variable makes the resource sensitive: its
  diff and audit details are redacted.

## Signature checking is never weakened

- `gpgcheck: false` and `repo_gpgcheck: false` are validation errors. Sinter
  never writes `gpgcheck=0`. A repository that is not signature-checked stays
  a [`file`](/en/reference/resources/file/) resource with your own content.
- A section that Sinter creates always gets `gpgcheck=1`, also when
  `gpgcheck` is not declared, and `enabled=1` unless `enabled` is declared.
  Creating a section requires `baseurl`, `mirrorlist` or `metalink`.
- An edit that enables a repository (`enabled: true` while the section has
  `enabled=0`, no `enabled` key or an unusable value), or that writes
  `baseurl`, `mirrorlist` or `metalink`, is refused in plan unless the
  section has an explicit `gpgcheck=1` after the edit. Declare
  `gpgcheck: true` to turn it on in the same change. In the file, `1`,
  `true` and `yes` (any letter case) count as on.
- A repository that is already enabled with `gpgcheck=0` (or without a
  `gpgcheck` key) and that the resource does not enable or re-point is not
  Sinter's decision: there is no error, and plan, apply and audit carry a
  note that signature checking is not on for it.
- Sinter writes the `gpgkey=` setting only. It does not download, import
  (`rpm --import`) or trust a key. Deploy a key file with a `file` resource;
  DNF itself imports the configured key when a package from the repository
  is first installed.

## Expected behavior

- Sinter reads the repository **file**; it does not ask DNF. The following
  are therefore not observed: command-line overrides (`--enablerepo`,
  `--disablerepo`, `--setopt`), a second definition of the same repository id
  in another file, and DNF 5 override directories.
- The file must be valid UTF-8 without NUL bytes and without CR line endings,
  at most 256 KiB, and a regular file (a symlink is refused, never followed).
- Only the repository's own section has to be readable with certainty. It is
  refused when: the id has two section headers in the file; a key appears
  twice in the section; a line of the section is neither blank, a comment
  (`#` or `;` in column one), `key=value`, nor an indented continuation line
  directly after a key; a key differs from a managed key only in letter case.
  A line anywhere in the file that starts with `[` but is not a `[id]` header
  is refused too. Refusals name line numbers, never file content.
- An existing key is replaced in place and keeps its position; a missing key
  is added after the section's last key. A key is rewritten only when its
  value differs: booleans are compared by meaning, lists as sequences of
  entries, so different spacing or line breaks alone are not a change. A list
  is written one entry per line.
- A new file contains exactly the new section, owner `root:root`, mode
  `0644`. An existing file keeps its owner, group and mode. A new section in
  an existing file is added at the end.
- `state: absent` removes the section: its header and everything up to its
  last key. Comments above the header, and blank or comment lines after the
  last key, stay. The file itself is never deleted, even when no section is
  left. A missing section or file is nothing to do.
- The change goes through the same code as a
  [`file`](/en/reference/resources/file/) resource: parent path checks,
  staging, atomic replacement and verification. A file that changed between
  observation and replacement is not overwritten.
- If the file holds a `password`, `username`, `proxy_password`,
  `proxy_username` or `sslclientkey` key, or a URL with credentials, in any
  section, the diff is redacted so those values never appear in output.
- Sinter does **not** refresh repository metadata after a change. A
  `package` resource that depends on the repository acquires metadata itself
  when it installs.
- Two `dnf_repository` resources with the same `name`, or a `dnf_repository`
  whose file is also the path of a `file`, `template`, `link` or `directory`
  resource, are validation errors. Several repositories in one file are
  allowed.
- Changing a repository file needs root (connect as root or use `--sudo`);
  plan says so.
- Audit: compliant when the section exists and every declared key has the
  declared value, or when the section is absent for `state: absent`. Drift
  names each differing field (`enabled`, `gpgcheck`, `baseurl`, …; `state`
  for a missing or unwanted section; a missing file is drift). An unreadable,
  oversized, symlinked or ambiguous file, a refused parent directory and an
  unsupported host are errors, never drift.
- Not available through MCP.

## Supported systems

DNF 4 only: Rocky Linux, RHEL and AlmaLinux 9 and 10. Refused clearly on
hosts whose package manager is not DNF (Ubuntu, Debian) and on DNF 5 hosts
(`/usr/bin/dnf` linking to `dnf5`). A host whose `/usr/bin/dnf` is not a
symbolic link to a DNF 4 program is refused as well: Sinter does not guess.

## Examples

Enable a repository that the distribution defines:

```yaml
version: 1
resources:
  - id: crb
    type: dnf_repository
    with:
      name: crb
      file: /etc/yum.repos.d/rocky.repo
      enabled: true
```

Define a signed third-party repository, then install from it. The key file
is a `file` resource; check its fingerprint before you ship it.

```yaml
version: 1
resources:
  - id: example-key
    type: file
    with:
      path: /etc/pki/rpm-gpg/RPM-GPG-KEY-example
      source: repo/RPM-GPG-KEY-example
      owner: root
      group: root
      mode: "0644"

  - id: example-repo
    type: dnf_repository
    depends_on: [example-key]
    with:
      name: example
      description: Example packages
      baseurl: https://repo.example.com/el$releasever/$basearch/
      gpgcheck: true
      gpgkey: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example

  - id: example-app
    type: package
    depends_on: [example-repo]
    with:
      name: example-app
      state: present
```

The same repository in TOML:

```toml
[[resources]]
id = "example-repo"
type = "dnf_repository"
depends_on = ["example-key"]

[resources.with]
name = "example"
description = "Example packages"
baseurl = "https://repo.example.com/el$releasever/$basearch/"
gpgcheck = true
gpgkey = "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example"
```

Disable a repository, and remove another:

```yaml
version: 1
resources:
  - id: no-crb
    type: dnf_repository
    with:
      name: crb
      file: /etc/yum.repos.d/rocky.repo
      enabled: false

  - id: no-example
    type: dnf_repository
    with:
      name: example
      state: absent
```

```toml
[[resources]]
id = "no-crb"
type = "dnf_repository"

[resources.with]
name = "crb"
file = "/etc/yum.repos.d/rocky.repo"
enabled = false

[[resources]]
id = "no-example"
type = "dnf_repository"

[resources.with]
name = "example"
state = "absent"
```
