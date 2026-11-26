---
title: file_merge
description: Manage one declared part of an existing text file and keep every other byte.
---

**Purpose:** manage only a declared part of a text file — one exact line, one
marked block, or one `key = value` setting — and keep everything else in the
file byte for byte.

[`file`](/en/reference/resources/file/) and
[`template`](/en/reference/resources/template/) manage a **whole** file: what
is not in the declared content is removed. `file_merge` is for files that
Sinter does not own alone, such as `~/.ssh/authorized_keys` (other keys stay),
`/etc/hosts` (other entries stay) or a simple configuration file where one
setting matters.

## Synopsis

```yaml
- id: deploy-key
  type: file_merge
  with:
    path: /home/deploy/.ssh/authorized_keys
    merge: line
    line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
    owner: deploy
    group: deploy
    mode: "0600"
```

## Parameters

Common to every `merge`:

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `path` | yes | string (absolute path) | — | The file. Same rules as `file.path`. DNF configuration is refused (see [Paths that are refused](#paths-that-are-refused)). |
| `merge` | yes | string | — | `line`, `block` or `key_value`. |
| `state` | no | string | `present` | `present` or `absent` — of the managed part, not of the file. |
| `create` | no | boolean | `false` | Whether a file that does not exist may be created (`state: present` only). |
| `owner` | no | string | — | Owner name. Unset keeps an existing file's owner. |
| `group` | no | string | — | Group name. Unset keeps an existing file's group. |
| `mode` | no | string | — | Quoted four-digit octal, e.g. `"0600"`. Unset keeps an existing file's mode. |

`merge: line`:

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `line` | yes | string | — | Exactly one line: no line feed, carriage return or NUL, not empty and not only whitespace, and not the words of a marker line (`BEGIN SINTER MANAGED BLOCK` / `END SINTER MANAGED BLOCK`). |

`merge: block`:

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `marker` | yes | string | — | Name of the block: 1–64 characters of `[A-Za-z0-9_.-]`. |
| `content` | when `present` | string | — | The lines between the two marker lines. May be several lines or empty. No carriage return or NUL, and no line that carries the words of a marker line. |
| `comment_prefix` | no | string | `#` | How a marker line starts: `#`, `;`, `//` or `--`. |

`merge: key_value`:

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `key` | yes | string | — | 1–128 characters of `[A-Za-z0-9_.-]`. Compared case-sensitively. |
| `value` | when `present` | string | — | One line, may be empty. No leading or trailing space or tab. Quote numbers and booleans (`"100"`, `"true"`). |
| `separator` | no | string | `=` | What Sinter writes between key and value: `=`, ` = `, `:`, `: ` or a single space. |

- `path`, `merge`, `marker`, `comment_prefix`, `key` and `separator` are static:
  they may use variables (and `item` in a loop) but not facts or registers, and
  not sensitive values.
- `line`, `content` and `value` may use any expression; they are checked again
  when their value is known.
- A field of another `merge` (for example `key` with `merge: line`) is a
  validation error.

## The three merges

### `line`: one exact line

The identity of the line is the **whole line, byte for byte** (compared
against each existing line without its line feed). There is no regular
expression, no prefix match and no fuzzy match.

- `present`: if no existing line equals `line`, it is appended at the end. If
  it is already there — once or several times — nothing changes; a duplicate is
  never added.
- `absent`: every line exactly equal to `line` is removed. Nothing else.
- `line` looks at **every** line of the file, also at a line inside a managed
  block of `merge: block`. `absent` removes an equal line there too, and
  `present` counts it as already there. Do not manage the same text with a
  `line` and inside a `block` of one file.
- A `line` that carries the words `BEGIN SINTER MANAGED BLOCK` or
  `END SINTER MANAGED BLOCK` is a validation error: it would damage or imitate
  a block. Use `merge: block` for a block.

### `block`: the lines between two marker lines

Sinter writes the block as

```text
# BEGIN SINTER MANAGED BLOCK <marker>
<content lines>
# END SINTER MANAGED BLOCK <marker>
```

- `present`: no block of this marker → the block is appended at the end. A
  block with other content → only the lines between the two marker lines are
  replaced. The same content → no change.
- `absent`: the block is removed together with both marker lines.
- Blocks with **other** marker names are unmanaged content and are kept.
- One trailing line feed of `content` ends its last line; it is not an extra
  empty line. `content: ""` is a block with no line between the markers.

### `key_value`: one setting

A line belongs to `key` when it starts with the key **in the first column**,
followed by optional spaces or tabs and `=` or `:` — or, for the space
separator, by at least one space or tab (or the end of the line). The key
must end there: `port` does not match `port_max = 1`. Comment lines (first
non-blank character `#` or `;`) never match.

Two kinds of lines are **refused** instead of edited (see the fail-closed
cases): a line that sets the key after leading spaces or tabs, and a line
whose key differs from the declared key only in letter case.

- `present`, no matching line: `key<separator>value` is appended.
- `present`, exactly one matching line: the whole line is replaced by
  `key<separator>value` **only if its value differs**. The current value is the
  text after the separator without surrounding spaces and tabs, so
  `max_connections   =100` already has the value `100` and is not rewritten.
- `absent`: the one matching line is removed; no matching line → no change.
- Values are written as they are. Sinter adds no quotes and escapes nothing.
- A replaced line is rewritten as exactly `key<separator>value`. Sinter does
  not know comment or quoting syntax: an inline comment or quotes on the old
  line are part of its value, so `a = "1" # note` has the value `"1" # note`
  and becomes `a=2` when `value: "2"` is declared. Write the quotes and the
  comment into `value` if the file needs them.

## Expected behavior

- **Everything outside the managed part is kept byte for byte**, including
  comments, blank lines, the order of lines and a missing final line feed.
  Only when Sinter appends something to a file that does not end with a line
  feed does it add that line feed first.
- **When nothing has to change, the file is not written at all** (no
  replacement, same inode). Declared `owner`, `group` and `mode` are still
  enforced, without rewriting the content.
- A change is written like a `file` resource writes: staged beside the file,
  published atomically by rename, verified afterwards. The file is read before
  the edit; if it changed between that read and the publication, the
  publication is refused and the other writer's content stays. Two checks
  do this: the SHA-256 the target reports for the file must be that of the
  bytes Sinter read (a comparison of content, so a change that keeps the
  size and the timestamps is noticed too), and the file's identity (inode,
  size, owner, mode, timestamps) is checked again right before the rename.
  A write that lands in the last moment between that check and the rename
  is not detected; Sinter takes no lock on the file.
- The file must have **one name only**. A regular file with more than one
  hard link is refused in plan, apply and audit: the replacement would leave
  the other name with the old content.
- The path must be a regular file. A symlink is refused and never followed;
  a directory or another object is refused.
- Plan shows the change as the normal file diff. When `merge: line` with
  `state: absent` removes several equal lines, the diff lists those lines
  only, not the unmanaged lines between them. Plan and audit only read.
- `sensitive: true` on the resource, or a value that comes from a sensitive
  variable, redacts the diff and every value in plan, apply and audit. A new
  file of a sensitive resource gets mode `0600` unless `mode` says otherwise.
- For a resource that is not sensitive, plan and audit show the old and the
  new value of a `key_value` setting. Set `sensitive: true` when either may be
  a secret.
- A change notifies handlers like any other resource.
- Not available through MCP.

### Paths that are refused

`file_merge` does not edit DNF configuration. A `path` that is
`/etc/yum.conf`, or is inside `/etc/yum.repos.d/`, `/etc/distro.repos.d/`,
`/etc/dnf/` (for example `dnf.conf`, `modules.d/`, `vars/`), `/etc/yum/`,
`/etc/rpm/` (RPM macros) or `/etc/pki/rpm-gpg/` (signing keys), is a validation error
when the recipe is loaded. One added line there could switch off package
signature checking (`gpgcheck=0`). Manage repositories with
[`dnf_repository`](/en/reference/resources/dnf_repository/) and module
streams with [`dnf_module`](/en/reference/resources/dnf_module/), which keep
package signature checking, or write a whole file with
[`file`](/en/reference/resources/file/).

### When the file does not exist

| `state` | `create` | Result |
|---------|----------|--------|
| `present` | `false` (default) | Plan error: set `create: true`, or create the file first. Nothing is created. |
| `present` | `true` | The file is created with the managed part only. `owner`/`group`/`mode` apply; without them it belongs to the applying user (inside another account's home directory: to that account) with mode `0644`. |
| `absent` | either | Nothing to do: compliant and unchanged. The file is not created. |

The parent directory must exist, exactly as for `file`, and passes the same
trust boundary (a directory listed in
[`allow_writable_parents`](/en/reference/recipe-format/#allow_writable_parents)
is accepted for the whole-file publication `file_merge` makes; audit of a path
whose direct parent others can write reads it without following links). In
such a directory the existing file may be one another account renamed there,
and `file_merge` keeps its content, so: plan shows only the sizes (never the
existing lines), audit does not show the current value of a key, and a
publication that would make the existing file readable by more accounts is
refused in plan and apply — a declared `mode` that adds a read bit the existing
mode lacks (for example `0600` to `0644`), or a declared `owner` or `group`
other than the existing one. Leave them unset or declare the existing values;
a narrower mode is allowed. A file that does not exist yet gets the declared
`owner`, `group` and `mode`. If an earlier resource
of the same run creates the file, plan reports this resource as unknown
(deferred to apply) instead of failing.

### Fail-closed cases

In each of these cases plan fails (exit 4), apply fails without changing the
file, and audit reports an **error** (never drift). Sinter does not repair or
guess.

- The file is not valid UTF-8, contains a NUL byte, or contains a carriage
  return (CRLF files are refused, not converted).
- The file, or the result of the edit, is larger than 256 KiB.
- `block`: two BEGIN lines for the marker; a BEGIN without its END; an END
  without or before its BEGIN; a marker line of another block inside the
  block; marker lines of this marker written with another `comment_prefix`
  than the declared one; a line that carries the words
  `BEGIN SINTER MANAGED BLOCK` / `END SINTER MANAGED BLOCK` but is not a
  well-formed marker line (for example with trailing spaces).
- `key_value`: the key appears on two or more lines ("Sinter does not guess
  which one is in effect"); the file contains a section header (a line that is
  only `[...]`); a line sets the key with another separator style than the
  declared one (for example `key value` in a file declared with `=`); a
  line sets the key but is indented (indentation usually means a structure
  Sinter does not understand: a nested YAML mapping, an `sshd_config`
  `Match` block); a line sets a key that differs from the declared key only
  in letter case (Sinter does not guess whether the file's reader treats
  them as the same setting).
- The file has more than one hard link.

### Several resources on one file

- Several `file_merge` resources may manage the same `path` when their parts
  differ: different lines, different block markers, different keys.
- Two `file_merge` resources of one path with the same line, the same marker
  or the same key are a validation error. (A `line` that is not known when the
  recipe is loaded — for example from a register — is not compared.)
- Two `file_merge` resources of one path that declare different `owner`,
  `group` or `mode` are a validation error. Write the same value, or declare
  it on one of them only.
- A `file`, `template`, `link`, `directory` or `systemd_timer` resource on the
  same path is a validation error: managing the whole path and a part of it
  contradict each other. So is a `dnf_repository` on the same file, in either
  order of declaration (the path is refused for `file_merge` anyway).

### Audit

- Compliant when the managed part is as declared and the declared metadata
  matches. **Unmanaged content is never drift.**
- Drift names the dimension: `line`, `block`, `value`, `owner`, `group`,
  `mode`, or `state` when the file itself is absent but the part should be
  present (`absent -> present`, whatever `create` says).
- The fail-closed cases above, an unreadable file and a symlink are errors.

## `authorized_keys`

```yaml
version: 1
resources:
  - id: deploy-key
    type: file_merge
    with:
      path: /home/deploy/.ssh/authorized_keys
      merge: line
      line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
      create: true
      owner: deploy
      group: deploy
      mode: "0600"
  - id: old-key-removed
    type: file_merge
    with:
      path: /home/deploy/.ssh/authorized_keys
      merge: line
      line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 old@example.invalid"
      state: absent
```

```toml
version = 1

[[resources]]
id = "deploy-key"
type = "file_merge"

[resources.with]
path = "/home/deploy/.ssh/authorized_keys"
merge = "line"
line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid"
create = true
owner = "deploy"
group = "deploy"
mode = "0600"

[[resources]]
id = "old-key-removed"
type = "file_merge"

[resources.with]
path = "/home/deploy/.ssh/authorized_keys"
merge = "line"
line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 old@example.invalid"
state = "absent"
```

- The other keys in the file are kept exactly as they are, with their options
  and comments.
- The identity is the exact line. The same key with another comment, or with
  options such as `from="192.0.2.10",no-pty` in front, is a **different line**:
  `present` appends the declared line beside it, and `absent` does not remove
  it. Sinter never edits or drops the options of an existing line.
- Declare `owner` and `mode: "0600"` so that `sshd` accepts the file. The
  `.ssh` directory itself is not created by `file_merge`; use a
  [`directory`](/en/reference/resources/directory/) resource (mode `"0700"`).
- Removing the key that your own connection uses can lock you out. Sinter
  does not detect this.
- The key material above is synthetic.

## A block in `/etc/hosts`

```yaml
version: 1
resources:
  - id: app-hosts
    type: file_merge
    with:
      path: /etc/hosts
      merge: block
      marker: app-hosts
      content: |
        192.0.2.10 app1.example.invalid
        192.0.2.11 app2.example.invalid
```

```toml
version = 1

[[resources]]
id = "app-hosts"
type = "file_merge"

[resources.with]
path = "/etc/hosts"
merge = "block"
marker = "app-hosts"
content = """
192.0.2.10 app1.example.invalid
192.0.2.11 app2.example.invalid
"""
```

Result (the lines above the block were there before and are untouched):

```text
127.0.0.1 localhost
# BEGIN SINTER MANAGED BLOCK app-hosts
192.0.2.10 app1.example.invalid
192.0.2.11 app2.example.invalid
# END SINTER MANAGED BLOCK app-hosts
```

## One setting in a configuration file

```yaml
version: 1
resources:
  - id: max-connections
    type: file_merge
    notify: [restart-app]
    with:
      path: /etc/app/app.conf
      merge: key_value
      key: max_connections
      value: "100"
      separator: " = "
handlers:
  - id: restart-app
    service: app.service
    action: restart
```

```toml
version = 1

[[resources]]
id = "max-connections"
type = "file_merge"
notify = ["restart-app"]

[resources.with]
path = "/etc/app/app.conf"
merge = "key_value"
key = "max_connections"
value = "100"
separator = " = "

[[handlers]]
id = "restart-app"
service = "app.service"
action = "restart"
```

`key_value` is for **flat** files in which a key appears once and the order of
lines does not matter. It is **not safe** for:

- files with sections (`[section]`): refused; INI-aware editing is not
  supported;
- order-sensitive files, where a new setting must not simply go to the end;
- formats where a key legitimately appears several times or the first match
  wins, such as `sshd_config` with `Match` blocks (an indented setting of the
  key is refused, but a `Match` block written without indentation is not
  recognised);
- formats whose keys are case-insensitive: a line with the key in another
  letter case is refused, not treated as the same setting;
- files that `Include` other files: Sinter sees only this one file, so the
  value in effect may come from somewhere else.

For such files, manage a whole drop-in file with
[`file`](/en/reference/resources/file/) or
[`template`](/en/reference/resources/template/) instead.

## Limits

- No regular expressions, no pattern or prefix matching, no "replace the line
  that looks like …".
- No sections, and no structured merge of YAML, JSON or TOML documents.
- UTF-8 text with LF line endings only; at most 256 KiB.
- No insertion at a chosen position: new parts go to the end of the file.
- Comments and commented-out settings are never changed or uncommented.
- No `validate` command before publication (unlike `file`).
- The file is not removed when its last managed part is removed; an empty
  file stays.
- Verified against Sinter's scripted test target. The behavior on a real
  host (the staged replacement of a real `authorized_keys`, including as the
  owning account with `setpriv`; real ACL and extended-attribute answers) uses
  the same code as `file`, but has not been measured for `file_merge` itself.

## Supported OS

The same targets as `file`: `file_merge` uses only the commands of the `file`
resource and needs no package or service backend.
