---
title: locale
description: Set the system default locale (LANG and LC_*) of a host with localectl.
---

**Purpose:** declare the system default locale of a host: `LANG` and,
optionally, single `LC_*` categories, as the OS keeps them in its locale
file.

## Synopsis

```yaml
- id: default-locale
  type: locale
  with:
    lang: en_US.UTF-8
    lc:
      LC_TIME: en_GB.UTF-8
```

```toml
[[resources]]
id = "default-locale"
type = "locale"

[resources.with]
lang = "en_US.UTF-8"

[resources.with.lc]
LC_TIME = "en_GB.UTF-8"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `lang` | no | string | — | The value of `LANG`. |
| `lc` | no | map | — | `LC_*` categories and their values. Keys: `LC_CTYPE`, `LC_NUMERIC`, `LC_TIME`, `LC_COLLATE`, `LC_MONETARY`, `LC_MESSAGES`, `LC_PAPER`, `LC_NAME`, `LC_ADDRESS`, `LC_TELEPHONE`, `LC_MEASUREMENT`, `LC_IDENTIFICATION`. |

- At least one setting is required.
- A value is `C`, `POSIX` (optionally with a codeset, `C.UTF-8`), or
  `ll[_CC][.codeset][@modifier]` such as `en_US.UTF-8`, `ja_JP.UTF-8` or
  `sr_RS@latin`: letters, digits, `_ . @ -`, at most 64 bytes.
- `lang` may use variables but not facts, registers or sensitive values; it
  is resolved and checked when the recipe is loaded. Values under `lc` are
  literal strings.
- `LC_ALL` and `LANGUAGE` are refused: `LC_ALL` overrides every other
  setting and is not meant as a system default, and `LANGUAGE` is a list of
  languages, not a locale.
- One `locale` per recipe; a second one is a validation error.
- `/etc/locale.conf` and `/etc/default/locale` belong to this resource
  (both, whatever the OS): a `file`, `template` or `file_merge` on either
  path in the same recipe is a validation error.

## Expected behavior

- **Where the default lives.** On Rocky Linux, RHEL and AlmaLinux:
  `/etc/locale.conf`. On Ubuntu: `/etc/default/locale`. On a host whose OS
  family Sinter does not recognize, the resource is refused: "locale is not
  supported on this host".
- **The Ubuntu link.** Ubuntu 24.04 and later ship `/etc/default/locale` as
  the link `../locale.conf`, and the values live in `/etc/locale.conf`.
  Sinter follows exactly this link: owned by root, with the text
  `../locale.conf` or `/etc/locale.conf`, to a `/etc/locale.conf` that is a
  regular file (or absent). Any other link, a link owned by another account,
  or a link at `/etc/locale.conf` itself is refused. The link is checked
  again after the read. If `localectl` replaces or removes the link, the
  apply fails with the change reported: Sinter does not restore it.
- **Observation (read-only).** Sinter reads that file without following any
  other symbolic link and accepts only lines `KEY=value` or `KEY="value"`, blank
  lines and `#` comments. A key set twice, single quotes, `export`, `$`,
  backticks, a carriage return and anything else is an error: Sinter does
  not guess what a shell would make of it. A missing file means that no key
  is set.
- **Only the declared keys are managed.** Other keys in the file are not
  compared and are not part of the change.
- **Availability (plan, read-only).** When something must change, every
  declared value other than `C` and `POSIX` must be listed by
  `/usr/bin/locale -a`. Codesets are compared without regard to case and
  `-`, so `en_US.UTF-8` matches `en_US.utf8`. A locale that is not listed
  is an error: "locale … is not installed on this host; install or generate
  it first (a language-pack / glibc-langpack package, or locale-gen) —
  Sinter does not do that". If an earlier resource in the run (for example
  a language-pack package) may provide it, plan says it is checked again in
  apply.
- **Apply** runs `/usr/bin/localectl set-locale KEY=value ...` as root, with
  no shell, passing every declared key (also those already set, so they are
  kept even if the tool replaces the whole set). A non-zero exit is a
  failure. An exit of zero is not trusted on its own: the file is read again
  and every declared key must have its declared value, otherwise the
  resource fails. If `localectl` changed or removed a key you did not
  declare, the result says so in a note. If the tool is killed, times out
  or the connection is lost, the result says the default may or may not
  have been changed; Sinter does not report success.
- A second apply changes nothing and runs neither `locale -a` nor
  `localectl`.
- **Audit** reports each declared key that differs as drift in a dimension
  named after the key (`LANG`, `LC_TIME`, …). A file Sinter cannot read or
  understand and an unknown OS family are errors, never drift.

## What Sinter does not do

- It does not install language packs and never runs `locale-gen` or
  `localedef`.
- It does not write the locale file itself; `localectl` does.
- It restarts nothing and changes no running session. The default applies
  to new logins and to services started afterwards; existing sessions and
  running services keep their locale. Every plan and apply result that
  changes the default says so.
- It does not set the console keymap or the X11 layout (`localectl
  set-keymap`, `set-x11-keymap`).

## Privilege

Changing the default needs root: connect as root or use `--sudo`. Plan says
so when the connection is not root. A run that has nothing to change needs
no root.

## Unsupported cases

- Hosts whose OS family is neither the Red Hat nor the Debian family.
- Hosts without `/usr/bin/localectl` (for example containers without
  `systemd-localed`): plan and apply fail with "locale is not supported on
  this host (/usr/bin/localectl was not found)" when a change is needed.
- Locale files with shell syntax beyond `KEY=value` / `KEY="value"`.

## Supported OS

Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 9 and 10.

This resource is tested against Sinter's scripted target. The v1.16.0 RC 2
acceptance found the link above on Ubuntu 24.04 (RC 2 refused it). A read-only
look at Rocky Linux 10.2 showed `/etc/locale.conf` as `LANG=en_US.UTF-8`,
no `/etc/default/locale`, and `locale -a` listing names such as `C`,
`C.utf8`, `en_US` and `en_US.utf8`. **Not verified on real hosts:** how
`localectl set-locale` rewrites the file on each OS, and whether it keeps
keys and comments it is not given; that `localectl` on Ubuntu writes
`/etc/locale.conf` and keeps the link; the exit codes and
messages of `localectl`; `locale -a` on Ubuntu, EL 9, RHEL and AlmaLinux.
