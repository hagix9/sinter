# Changelog

All notable changes to Sinter are documented in this file.

## [1.6.0] - 2026-10-20

### Added

- **Host and group variables: `--vars-file`.** `plan`, `apply` and `audit`
  take a variables file (YAML or TOML, `version: 1`) that gives the variables
  the recipes declare other values for the whole run (`vars`), for the hosts
  of an inventory group (`groups`, needs `--inventory`) or for one host
  (`hosts`). Precedence is the recipe's value < `vars` < `groups` < `hosts`;
  two groups of a host that disagree are an error unless the host sets the
  variable. Every variable must be declared by a recipe of the run and keep
  its type; a sensitive variable cannot be set; with a bundle, a value applies
  to the recipes that declare the variable. Every selected host is checked
  before any host is contacted: a problem exits 2, nothing connects, and the
  messages name the file position (when the parser gives one), layer,
  variable and field but never show a value from the file. The file is plain
  text and its values appear in normal output like recipe values; `validate`
  accepts the option and ignores it. A
  file with only `version: 1` changes no value or result (only how some
  static recipe errors are reported). See
  [Host and group variables](https://sinter.fulltrust.co.jp/en/reference/cli/#host-and-group-variables).

## [1.5.2] - 2026-10-18

### Added

- **OpenStack 2026.1 all-in-one recipes for Rocky Linux 10.2** in
  `examples/openstack/` (example recipes, not a Sinter feature): a builder
  recipe that builds the OpenStack RPMs from the upstream sources (no RPM is
  distributed), the all-in-one recipe (Keystone, Glance, Placement, Nova,
  Neutron with OVN, Horizon) and helper scripts. A verification and demo
  setup, not hardened for production (SELinux permissive, unsigned RPMs,
  `gpgcheck=0`). Accepted on a real GCE host on 2026-10-17 with an earlier
  revision of the recipes: two later changes (the Keystone key steps' output
  handling and `tools/gen-secrets.sh`) are covered by tests but have not run on
  a real host. `tools/gen-secrets.sh` needs `openssl`, checks every value,
  writes no file when a value cannot be generated and never replaces an
  existing one.
- **OpenStack tutorial** on the documentation site, in English and Japanese,
  linked from the home page.

### Fixed

- **A lost wait is reported as unknown, not as "failed, nothing changed".**
  When a local run could start a command but the wait for it then failed, the
  result said the command failed and nothing changed, although the command may
  have run. It is now indeterminate with a possible change (exit 6, like a
  timeout after dispatch), the command is not retried and nothing after it
  runs. The command is not killed after a failed wait, so it may still be
  running when Sinter reports. Normal exits, failing exit codes, signals and timeouts are reported as
  before.
- **Backup directories are created private.** The backup store and run
  directories are created with `mkdir -m 0700` instead of a plain `mkdir` that
  left them with the umask's mode until the following `chmod 0700`. With GNU
  coreutils they never exist with a wider mode; the `chmod 0700` is kept (for a
  `mkdir` that applies the mode only after creating the directory), so the
  commands and checks are otherwise unchanged.

### Changed

- **`needs root` is shown in the default plan output.** The plan note that a
  change needs root (a run that is neither root nor `--sudo`) used to appear
  only with `--verbose` and in JSON. Other notes stay verbose-only; a sensitive
  resource shows `needs root (details redacted)`; JSON is unchanged.
- **"Permission denied" while inspecting a path is said in words.** A `stat`
  refused with exactly the coreutils "Permission denied" record was reported as
  "the capture carried an unrecognized diagnostic". It is still an error
  (nothing is assumed about the path), now `permission denied`, with a hint to
  connect as root or use `--sudo` only when the run is not root.

## [1.5.1] - 2026-10-17

### Added

- **`postgresql_role`: manage a role of a local PostgreSQL server.** Existence,
  the declared attributes only (`login`, `superuser`, `createdb`,
  `createrole`, `inherit`, `replication`, `bypassrls`, `connection_limit`) and
  a SCRAM-SHA-256 verifier read from an encrypted secret
  (`password_verifier: { secret: … }`; plaintext and md5 are refused). `psql`
  runs as the cluster owner (peer authentication, root required); the
  verifier travels only on standard input, and the change runs only after the
  session's statement logging (`log_statement`, `log_min_error_statement`,
  `log_min_messages`, duration/sampling/debug logging, `pg_stat_statements`,
  `pgaudit`) has been silenced and read back. Nothing is granted implicitly;
  `absent` is `DROP ROLE` without `CASCADE`. Planned from observation and
  audited per dimension without values. Verified on PostgreSQL 10, 13, 16 and
  17.
- **`validate.args` can place the staged file inside an argument** with
  `{{ staged }}` (`--config-file={{ staged }}` for `postgres -C`,
  `Include {{ staged }}` for `httpd -t -c`). Without a placeholder the staged
  path is still appended last.
- **`facts.os.version_major`**: the integer major release (`8.10` → `8`), for
  branching recipes per EL release; only a plain numeric `VERSION_ID` yields a
  value.
- **RHEL-family recipes** in `examples/recipes/`: Python on EL8, PostgreSQL 16
  from the OS and 17 from PGDG (pinned key, repository files), EPEL +
  CRB/PowerTools, any signed RPM repository, Apache with htpasswd.

- **`validate` warns about `{{ … }}` in `template.vars`.** Template vars are
  passed as written, so such text was rendered literally; the behavior is
  unchanged, and the warning (stderr, and `warnings` in JSON) points to
  `vars.*` / `facts.*` in the template body.

### Fixed

- **A failed package mutation no longer echoes raw package-manager output that
  could contain repository credentials.** dnf: a recognized cause (`GPG check
  FAILED`, an unreachable repository) is named, otherwise only the size of the
  withheld output is shown. apt: the message is kept, single-line and bounded,
  with `scheme://user:pass@` credentials redacted.
- **A name dnf only reaches through provides is refused before installing.**
  `name: python3` on EL8 used to install `python36`, then report Failed and
  never converge. Sinter now checks that the dry-run transaction installs the
  requested name itself (or that dnf's "nothing to do" is not caused by
  another installed package) and otherwise fails with no change, naming the
  real package (`name: python36`).
- **dnf refusals name their cause** instead of "repository metadata not
  locally complete": no such package, a missing dependency (with the
  capability), `GPG check FAILED`, an unreachable repository (by id), a failed
  download. Only fixed text and validated names are shown; unknown output is
  reported by size and still fails closed.
- **Plan explains package-created accounts.** An owner/group that a package's
  scriptlet will create is still unknown in plan; the error now says to
  declare the account (with the package's attributes) before the package,
  which makes plan defer instead of fail.

### Release validation

- The acceptance harness (`release/acceptance-harness/`) takes every
  environment- and release-specific value from the environment and stops
  before any cloud call when one is missing. It records each target's boot
  image, verifies the tarball before upload, and stops a target on a raw-log
  hash mismatch, a stale or failed preparation step or a failed metadata
  refresh. Target preparation waits for a package manager that is already
  running (a timer-started `dnf makecache` on a fresh RHEL-family VM) instead
  of letting the acceptance race it. GO needs all eight targets.
- The approval-set tools are in the repository:
  `release/make_approval_set.py` assembles the set and
  `release/verify_approval_set.py` checks it against the acceptance assets,
  the collector record, the release candidate and the recorded evidence
  (layout `sinter-approval-set/2`).
- CI validates every example recipe and every complete recipe in the docs,
  and guards the public tree against committed local work products.

### Security

- **Gateway: rustls 0.23.46** (from 0.23.45) for RUSTSEC-2026-0346,
  RUSTSEC-2026-0347, RUSTSEC-2026-0348 and RUSTSEC-2026-0349, in
  `gateway/Cargo.lock` only; the yanked `yoke-derive` 0.8.3 is replaced by
  0.8.4. The `sinter` binary does not use rustls and is unaffected. The
  gateway's API, configuration and TLS client settings are unchanged.

## [1.5.0] - 2026-10-16

### Changed

- **A cold dnf metadata cache no longer blocks an install.** On RHEL-family
  targets an install still runs cache-only against a private snapshot of the
  target's dnf metadata, but when an enabled repository has no cached
  metadata — a fresh image, or a repository added since the last refresh — the
  install no longer fails with "repository metadata not locally complete" and
  no longer needs a manual `dnf makecache` first. Sinter refreshes the
  target's own metadata cache once, exactly as `dnf makecache` does (only
  absent metadata is fetched, `metadata_expire=-1`; no package payload is
  downloaded by that step), then rebuilds and re-verifies the private
  snapshot. It is attempted once and bounded: a refresh that cannot make the
  cache complete fails the resource closed before any package mutation, and
  later packages in the same run reuse the warmed cache. The private snapshot
  still never removes or copies the live cache.

### Added

- **`file` / `template` can validate the new content before it is published.**
  A `validate` block (`program`, `args`, optional `timeout_seconds`) runs a
  command against the **staged** file — `program args... <staged-file>`,
  argv-only, as the operation's identity — and publishes only if it exits 0.
  On a non-zero exit, a signal, a timeout or a lost response nothing is
  published and the destination is left unchanged (a timeout is reported as
  indeterminate). Use a tool's non-applying syntax check: `sshd -t -f`,
  `visudo -cf`, `rsyslogd -N1 -f`, `testparm -s`. The command never sees the
  production path, and a sensitive resource's validator output is never shown.

- **A recipe-wide default environment for `package` and `command`.** A
  top-level `env` map is applied to every `package`/`command` resource, so a
  common HTTP(S) proxy is written once. A resource's own `env` overrides it per
  name; the default never reaches a connection step, a package query, a
  service, or a file operation. Names are case-sensitive (Sinter does not fold
  `HTTP_PROXY`/`http_proxy`), `PATH`/`LANG`/`LC_ALL`/`HOME` are reserved, and a
  value derived from a `sensitive` variable is redacted. `env` is allowed only
  in the recipe that is run.

- **DNF module-stream transactions are recognized.** A transaction table that
  dnf prints with an `Enabling module streams:` section (measured on Rocky
  Linux 8 when a default module stream is enabled during resolution) is parsed:
  the `<module> <stream>` pairs name no payload and are validated and skipped,
  while the package rows are handled exactly as before. No stream is chosen and
  no module is enabled by Sinter — dnf enables the default stream in its own
  transaction; only the output is understood. Any other module/profile section
  still fails closed.

- Quick, single-behaviour example recipes under `examples/quick/` (packages,
  dnf metadata, a DNF module stream, a proxy, accounts/paths, a
  package/user/service recipe, config validation).

## [1.4.0] - 2026-10-14

### Added

- **Root can manage files and directories inside an unprivileged user's
  directory, without `--sudo`.** When Sinter runs as root (a root login, or
  `--sudo`), a path such as `/home/alice/page` is accepted when the first
  untrusted ancestor is a plain directory of an unprivileged account (not
  group- or other-writable, no ACL, nothing below it owned by a third account,
  no symlink). Sinter's file operations on that path then run as that account
  (`setpriv`; capabilities dropped), so the account's tree cannot be used to
  make root write elsewhere. A new entry without `owner` belongs to the
  account (except directly in `/tmp`, see the shared-directory entry below); an `owner` other than the account, an account without an
  account-database entry, a backup of such a path, and a non-root login stay
  refused. `setpriv` (util-linux) is required on the target for this case.

- **Shared directories (`/tmp`, `/var/tmp`) work without any option.** A
  directory that others can write is now accepted as a parent when it is owned
  by root (without `--sudo` also by the connecting user) and has the sticky bit.
  In such a directory Sinter manages only entries owned by root: an entry of
  another account is not read, changed or removed (plan refuses it, apply fails
  without touching it, audit reports an observation error), a regular file with
  more than one hard link is refused, and an `owner` other than root is
  refused. A new file or template is created exclusively — the content, owner,
  mode and extended attributes are fixed on a private staging file, which is
  then hard-linked at the final path (`ln -T`) — so a name another account took
  first is never replaced; the resource fails and a rerun converges. An existing
  file of root is still replaced by a rename. A converged file in `/tmp` plans
  as unchanged and audits as compliant again. Directories that others can write
  without the sticky bit, shared directories owned by another account, and
  shared directories inside another account's tree stay refused. Below a
  directory of another account in `/tmp` (for example `/tmp/alice/file`) the
  operations still run as that account, but only when the recipe sets `owner`
  (to that account): any local account can make `/tmp/app` before the recipe's
  author does, and a `file`, `template` or `directory` there that would be
  created, replaced or changed without an `owner` is refused in `plan` and
  `apply` (before anything is written, even when the entry exists), because
  what Sinter wrote would belong to that account, which could read it and
  replace it. An `owner` of anyone else is refused too. A directory made by a
  `directory` resource (root's), a root-owned directory such as `/opt/app`, and
  `/home/<user>` are not affected; neither are links and `state: absent`
  (no content, no owner). A refusal for a `sensitive` resource names no path and
  no uid. What plan and audit report about such
  an entry is the metadata the check itself saw (no second look that another
  account could have changed), and apply confirms the entry is the observed
  object before it changes or removes it. A `backup` of a directory directly in
  a shared directory is refused (the recursive copy would read what other
  accounts put there); files and links there, and directories elsewhere, are
  backed up as before.

### Fixed

- **Packages signed with a key that is not installed no longer fail the
  payload check.** The `rpm -qp` query that identifies a downloaded package
  (name, version, architecture) now runs with `--nosignature`. Before, rpm's
  `NOKEY` warning on stderr (a payload from a CentOS SIG, RDO or another
  third-party repository whose key is not in the rpm database) made the stderr
  guard refuse the whole transaction. Only the identity query changed:
  whether a signature is trusted is still decided by dnf (`gpgcheck`) and the
  payload digest.

- **dnf install tables with a wrapped long package name are parsed.** dnf puts
  a name that is wider than its column on a line of its own and the remaining
  columns, indented, on the next. Sinter now joins a lone name token with the
  following indented line of 4 or 5 columns into one row, which goes through
  the same validation as any other row; anything else still fails closed.
  Before, such a transaction (for example `openstack-neutron-periodic-workers`)
  stopped with `cannot establish the install transaction set`.

- **Package install works again on hosts whose dnf cache contains downloaded
  packages, and no longer touches the live cache.** A metadata snapshot made
  from the live dnf cache copied every `.rpm` already lying in the cache, and
  the payload check then treated those files as unexpected downloads, so the
  install failed closed on hosts with cached packages — for example right
  after a kernel update. The copied payload is now removed from the private
  snapshot in checked batches of at most 128 operands before the download
  step, and the snapshot payload parser accepts only `.rpm` paths recorded
  inside the private snapshot, so the live cache stays out of the removal
  path. Snapshot-scoped dnf calls now run with
  `--disableplugin=generate_completion_cache`: that plugin writes
  `/var/cache/dnf/packages.db` even under a private cachedir, which changed
  the live cache during an install. Other plugins keep running, a host
  without the plugin still works (the exact one-line warning is tolerated),
  and an unchanged live cache is a hard requirement again on every target.

- **`plan` no longer fails a recipe that `apply` accepts when an account is
  created by a resource that simply runs earlier (F-3).** A `file`, `directory`
  or `template` whose `owner`/`group`, and a `user` whose `group`/`groups`, name
  an account created by a `user`/`group` resource that comes earlier in the
  execution order was a plan error (rc 4) unless the creator was listed in
  `depends_on`, while `apply` succeeded. `plan` now defers such a resource
  (unknown until apply), as it does for a listed dependency. Nothing else
  changes: no dependency is added, the execution order and the blocking and
  fail-fast rules are as before, and a creator that runs later, is `absent`,
  is skipped by a false `when` or is blocked by a skipped dependency still
  leaves the plan error (and `apply` fails
  the same way). A `user` without `group` whose same-named group certainly runs
  earlier is now refused in `plan`, as `apply` refuses it.
- **A new link is created with `ln -sT`.** A directory symlink that someone had
  put at the link path no longer makes the link appear inside the directory it
  points to; an existing name is an error.
- **A root login needs no `sudo`.** When the target user is already root
  (effective UID 0 on the target), Sinter runs target operations directly, with
  or without `--sudo`: no `sudo` executable is needed, and the environment and
  working directory contract is the same as under `--sudo`. `--sudo` stays
  accepted and changes nothing else; the backup store location still follows
  the flag.
- **`password_hash` follows the effective privilege.** A `user` resource with
  `password_hash` is accepted for a root login as well as with `--sudo`, and
  refused for a non-root user without `--sudo`, as before.
- **A failing `sudo -n` is no longer reported as a non-Linux target.** The
  connect error now says which it is: sudo not installed, a password required,
  sudoers refusing the user, or a cause that was not identified. A cause is
  named only when sudo's own sentence names it; otherwise one read check runs
  without sudo, only on that failure path, to tell a sudo failure from an
  unreadable `/etc/os-release`. What a command printed is never copied into the
  message. A target whose `/etc/os-release` is unreadable is still reported as
  a non-Linux target.
- **`--sudo` asks sudo for root explicitly.** Commands are sent as
  `sudo -n -u root -- …`, over SSH and locally. Before, they were sent as
  `sudo -n -- …`, which sudo runs as the sudoers `runas_default` user: root
  unless a site sets another user, while Sinter treated the run as root. Now
  sudo runs the command as root or refuses it; a refusal of the first command
  is reported at connect. A rule that allows root for some commands only is
  refused at connect when it does not cover that first command, and otherwise
  makes a later command fail like any other command failure. Sinter still does
  not measure the uid of a wrapped command; it relies on sudo honouring
  `-u root`. No command is added, and a root login and a run without `--sudo`
  are unchanged; a root login needs no sudo. For a user who goes through sudo,
  the sudoers rule must allow running commands as root: `(root)`, `(ALL)`,
  `(ALL:ALL)` or `(#0)`, or no Runas_Spec when `runas_default` is root (its
  default). With NOPASSWD, `targetpw` and `rootpw` were checked only in
  `(ALL) NOPASSWD: ALL`, on sudo 1.9 and sudo-rs: commands still ran as root
  with either set.
  **Compatibility:** this matters only where sudoers sets `runas_default` to
  another user (sudo 1.9; sudo-rs has no `runas_default`). A rule that allows
  root, such as `(ALL) NOPASSWD: ALL`, is not refused: commands now run as root
  instead of as that user. The old wrapper ran them as that user, so they
  failed wherever that user could not enter `/root`, Sinter's default working
  directory under `--sudo`. A rule that allows only that user, or has no
  Runas_Spec, is now refused at connect and nothing is applied. sudo 1.9 words
  every such refusal as "a password is required" (it does the same for a user
  with no rule), so Sinter's connect error mentions a password although the
  rule has NOPASSWD. sudo-rs, which has no `runas_default`, words a rule that
  allows another user only as a refusal, and the error then says that sudoers
  does not allow the user. Allow root in the rule.

### Changed

- **A managed path is observed only through a parent path the trust check
  accepted (`plan`, `apply` and `audit`).** The parent walk now comes first and
  `stat`, link target and content digest of the path are read only after it;
  inside another account's directory they are read as that account. A planted
  symlink in a directory another account controls can no longer make root look
  at a file only root can read, and nothing of such a file (mode, owner, size,
  link text, whether a digest matched) can reach the output. `audit` reports
  an observation error, never drift, for a path whose parent is refused. A path
  below a parent that does not exist yet still plans as a creation. A refused
  parent is now reported even for a resource that would have been unchanged.
  Cost: one walk (a batched `stat` and `getfattr`) per directory of managed
  paths in `plan` and `audit`, and one more walk per changed path in `apply`.
- `plan` adds a `needs root: …` note (in the existing `notes`) to a package,
  user or group change, and to creating, replacing or removing an entry in a
  directory the target user cannot write, when the target user is not root and
  `--sudo` was not given. Information only: no new status, field, exit code or
  command.
- With `--sudo` over SSH, connecting costs one more command (`id -u`, run
  without sudo) to learn whether the user is root.

- **Staging, publication and cleanup of a file or link are steps of one fixed
  script (FS-2, I4/I5).** The private staging directory beside a file or link
  was reached by separate commands (`mktemp`, `chown`, `chmod`, `dd`, `mv`,
  `rm`, `rmdir`) that each named it again, so an account that can rename
  entries in the parent could redirect a later command (measured on a real
  host: 114 of 1500 runs with separate commands). They are now two calls of one
  constant shell script that is part of the Sinter binary (`stage`, then
  `publish`; `discard` when nothing is published), which opens the directory
  once and keeps working on it. This is a limited exception to the argv-only
  rule: the script is a constant, never built at run time, every value is an
  argument, and its SHA-256 is pinned by a test (DESIGN §20, §23.5). Staging
  and publishing a new file take two target commands instead of seven
  (`mktemp`, `chown`, `chmod` twice, `dd`, `mv`, `rmdir` before; on the
  scripted target, creating a file three directories deep costs 21 commands in
  all, 25 before, including the observation walk described below). As root the
  staging directory is identified by a
  random group it was created with (`setpriv --regid`), so `setpriv` (util-linux)
  is required on the target for a file or link that goes through staging; a
  plain user needs a parent directory nobody else can rename entries in. The
  script needs a POSIX `sh` and GNU-style `stat -c`, `mktemp -d -p`, `mv -T`,
  `ln -T`, `find -P` and `readlink`, and a mounted `/proc` (run against dash and bash with GNU
  coreutils; busybox and uutils coreutils are not tested). The
  empty staging directory is removed by name only in such a directory;
  elsewhere it is left and its path is reported. What is published and what
  became of the staging directory are reported separately: an empty directory
  left behind is a note and the publication stands, a second name of the file
  left behind (or an unknown state) is a failed resource with `change:
  changed` that names the path.
  A publication step that ends with an exit code the script does not define is
  reported as indeterminate (the file may have been published), never as "not
  published"; a failed resource that blocks later ones through fail-fast, or a
  failed dependency, no longer copies its reason into them when it is
  sensitive.
- **A directory with the setgid bit refuses the staging of a file or link.** A
  directory made in it would inherit its group, so Sinter could not prove it is
  its own. The resource fails before anything is written (`change: none`) and
  names the reason. Nothing else changes for setgid directories: directories,
  links that are new, metadata-only changes and removals there are managed as
  before. Remove the setgid bit, or manage the file below another directory.

### Known limitations

- **A failed apply drops pending handler notifications.** Handlers run only
  after every resource has succeeded; if an apply fails after a resource already
  changed a file that notifies a handler, the handler does not run and the next
  apply, finding the file correct, notifies nobody. Restart or reload the
  affected services by hand after a failed apply.
- **`package` cannot install from a `file://` repository.** dnf uses such a
  repository in place and its payloads are not in the download snapshot, so the
  install fails with `expected payload missing from snapshot`. Serve the
  repository over HTTP(S).

## [1.3.0] - 2026-10-11

Progress output for `plan`, `apply` and `audit`, on standard error only.
Progress changes no recipe, command line, `--format json` document, standard
output, exit code or output of a non-interactive run unless `SINTER_PROGRESS` is
set. Separately, `plan` now reports refusals that `apply` would make, and
validation refuses Jinja template tags (see Changed), and dnf packages whose
version contains `~` or `^` can be installed (see Fixed).

### Added

- **Transient progress line on interactive terminals.** When stderr is a
  terminal, `TERM` is not `dumb` and the output format is text, `plan`, `apply`
  and `audit` show one line that names the stage, the count of finished items
  (`17/42`, never a percentage or an estimate), the resource type and `id` in
  flight, and, after a quiet spell, the time since Sinter last moved on to a new
  item. The line is erased when the run ends, so the output that remains is what
  it was without progress.
- **Opt-in persistent progress lines: `SINTER_PROGRESS=plain`.** Writes
  `progress: ...` lines to stderr for logs and CI: run, stage and count
  milestones, and heartbeat lines (`30s since last progress`) after 30 seconds of
  silence, backing off to one per 300 seconds. The number of lines depends on the
  stages and on waiting time, not on the number of resources. It applies on a
  terminal too, where it replaces the transient line, and even with
  `TERM=dumb`. Only the exact value `plain` has an effect; any other value is
  ignored. There is no command-line flag or configuration setting.
- **No progress where it could interfere.** `--format json` never produces
  progress on any stream, and neither does a recipe that references an encrypted
  secret, whatever `SINTER_PROGRESS` says. By default a non-terminal stderr gets
  no progress, so scripted and CI output is byte-for-byte unchanged.
- Progress contains only the stage, counts, the resource type and `id` of the
  item and fixed outcome words: no host, address, user, command, file content,
  diff, secret reference or error text. Progress text is informational and, like
  other stderr text, not part of the stable 1.x interface. See
  [Progress output](https://sinter.fulltrust.co.jp/en/reference/cli/#progress-output).

### Changed

- **`plan` reports what `apply` would refuse.** For a `file`, `directory`,
  `link` or `template` change, `plan` now runs the same read-only checks as
  `apply`: the parent path check (an ancestor owned by another user, writable by
  group or other, a symlink, an ACL, or missing), the security metadata check of
  a file whose content is replaced, and, for `directory` with `state: absent`,
  whether the directory is empty. When no earlier change in the run can affect
  the path, a refusal is a plan error (exit 4) with `apply`'s reason; previously
  `plan` showed a change and `apply` failed. When an earlier change can (a
  directory this run creates, a package, a command), the change is shown with a
  note (`--verbose`, JSON `notes`) and `apply` decides. `plan` still changes
  nothing. Plans of a `directory` with `state: absent` run one more read-only
  command (`find <dir> -mindepth 1 -maxdepth 1 -print -quit`).
  A recipe with `backup:` paths also counts the backup store directory that
  `apply` creates first (`/var/lib/sinter[/backups]` with `--sudo`,
  `~/.sinter[/backups]` otherwise) as such an earlier change, and `plan` reads
  that directory (one `stat`) to see whether it exists.
  A `command` skipped because its `creates`/`removes` guard holds is treated the
  same way when an earlier change can flip the guard, including a guard whose
  path has a symlinked ancestor (observed through the symlink, so a lexical
  comparison cannot tell).
- **Parent path refusals say what to do**, for example: with `--sudo` only
  root-owned parents are trusted, so connect as that user without `--sudo` or
  use a root-owned location such as `/opt` or `/srv`.
- **Jinja tags in a template are an error.** Templates render only
  `{{ expression }}`. A `{% ... %}` statement or `{# ... #}` comment tag used to
  be written to the target unchanged; `validate`, `plan` and `apply` now refuse
  it (exit 2) and name the resource, the source file, and the line and column.
  Write `{{ "{%" }}` for a literal `{%`. Only an opener followed by its own
  closer is a tag; an opener with no closer (such as an Elixir `{%{...}`), a
  closer written inside `{{ ... }}`, and a `{#` right after `$` (shell
  `${#var}`) are plain text and are published as written.

### Fixed

- **dnf packages whose version or release contains `~` or `^`** (rpm pre-release
  and snapshot versions, such as `1.0~rc1`) can be installed. The transaction
  used to be refused as uninterpretable. Other characters outside rpm version
  text are still refused.

### Notes

- If Sinter is interrupted or stops because of an internal error, the plain
  progress stream ends without a closing `run: ... completed` or `failed` line.
- A stalled terminal cannot change a run's exit code; at the end of each
  progress scope (each execution that runs, and target resolution in an
  inventory run or a bundle run with `--host`) Sinter waits at most half a
  second for the progress writer. The wait applies to each scope, not to the run
  as a whole.

## [1.2.0] - 2026-10-06

Local account management (`group` and `user` resources), encrypted secrets, and
fewer remote commands per run on some targets. Recipes, command lines and
`--format json` documents that do not use the new features are unchanged: the
additions are new resource types, a new command group (`sinter secrets`), new
optional fields, and internal changes to how a run observes the target. This
release is a new capability release, not only a performance release.

### Added

- `group` and `user` resource types for **local** Linux accounts.
  - `group`: `name`, `state` (`present`/`absent`, default `present`), `gid`,
    `system` (create-time only).
  - `user`: `name`, `state`, `uid`, `group` (primary, by name), `groups`
    (supplementary, by name, **additive**), `shell`, `home` (record only),
    `create_home` and `system` (create-time only).
  - Only declared dimensions are managed and audited. Observation uses
    `getent -s files`; an account that only another identity source (NSS)
    provides is an error, never a create. Every command is a fixed executable
    with explicit argv (`groupadd`, `groupdel`, `useradd`, `usermod`,
    `userdel`), never a shell.
  - An existing account is never renumbered (a `uid`/`gid` mismatch is
    refused in `plan`/`apply` and reported as `DRIFT` by `audit`) or renamed,
    and its home is never moved. Supplementary membership is never removed.
    `absent` runs `userdel`/`groupdel` without `-r`/`-f`; the home directory
    and mail spool are kept. Refused for root/uid 0, the account this run
    executes as, the session account, and a group that is some user's primary
    group.
  - Dependencies stay explicit. In `plan`, a `user` whose group is created by a
    `group` listed in its `depends_on`, and a `file`/`directory`/`template`
    whose `owner`/`group` names an account created by a `user`/`group` listed
    in its `depends_on`, are deferred (unknown until apply) instead of failing
    the plan. Without `depends_on` the plan error for an unknown account is
    unchanged.
  - Unit tests use a scripted fake target. A real-host `group` → `user` →
    `directory` → `file` lifecycle scenario (create, converge, update, drift and
    audit, refusals, removal) on the eight supported targets is part of the
    v1.2.0 release acceptance; its result is recorded in the acceptance
    evidence published with the release.

- `sinter secrets encrypt | decrypt | list`: encrypt and
  decrypt secret files in the standard age format, built on the encrypted-secret
  core. The command itself works on files; recipes use secrets through the
  entries below (`file.content`, `user.password_hash`, `list --recipe`), and
  MCP never does: MCP manifest tools refuse secret references.
  - `encrypt` takes recipients (`-r`, or the nearest `recipients.txt` up to the
    repository root) or a passphrase (`--passphrase`, terminal only, echo off);
    input is opaque bytes up to 16 MiB; the output is written atomically
    (0600, synced), never replaces an existing file silently (`--force` replaces
    only an age file) and never writes through a symbolic link; the original is
    never changed or deleted.
  - `decrypt` writes plaintext to stdout only and refuses a terminal. Identities
    are found in this order: `--identity`, `SINTER_IDENTITY` (a path), the
    default `~/.config/sinter/identity` (outside any repository), then a
    passphrase-protected `identity.age` in the repository (explicit opt-in; a
    plaintext identity is never discovered in a repository). Plaintext identities
    must be mode 0600 and owned by the user.
  - `list` derives status, method and recipient count from age headers; it
    decrypts nothing.
  - Passphrases are accepted only on the terminal: never from argv, the
    environment or stdin. Automation uses recipients and identities.

- `file.content: { secret: <path> }`: a `file` resource can
  take its bytes from an encrypted secret (age). The reference is a static path
  relative to the recipe that names it (no absolute path, `..`, interpolation or
  symbolic link). `validate` checks the reference and that an age file is there,
  and never decrypts; `plan`, `apply` and `audit` decrypt through the same
  identity discovery as `sinter secrets decrypt` without `--identity` (on
  plan/apply/audit `--identity` stays the SSH key): `SINTER_IDENTITY`, the
  default identity, then a passphrase-protected repository `identity.age`.
  - A resource that holds a secret is always sensitive (redacted diff, 0600
    default, redacted report text). An unavailable key fails that resource in
    `plan` and `apply` and is `ERROR` in `audit` (when the target file exists),
    never `COMPLIANT`; the cause is printed once on standard error.
  - Content is exact bytes, published through the unchanged file pipeline; the
    plaintext is held in buffers Sinter zeroizes, never printed, and
    `ExecRequest` standard input is zeroized when the request is dropped.
  - MCP manifest tools refuse `content: { secret: … }`.
  - Real-Linux acceptance of the secrets features on all eight supported
    targets was completed on 2026-10-04 on a pre-release build, not on the
    v1.2.0 release artifact; see
    [Supported Platforms](https://sinter.fulltrust.co.jp/en/compatibility/platforms/#real-host-acceptance-of-the-unreleased-secrets-features).

- `sinter secrets list --recipe FILE` (repeatable): adds
  what the recipes you name say about the listed secrets, and still never
  decrypts, prompts or looks for an identity.
  - Each recipe (or bundle) is loaded by the `validate` loader; only the state
    of the referenced file is observed instead of required. Output adds
    `referenced_by` (`type:id` and the recipe argument as written), the
    `missing` status (a valid reference whose file is absent; exit 0, while
    `validate` still rejects it) and a "not referenced by the N recipe(s) given"
    conclusion that is withheld unless every recipe loaded, the file is a parsed
    age file whose identity could be matched (device and inode), and it is not a
    possible `identity.age`. Links, directories, unreadable and non-age
    references are never called `missing`.
  - Any recipe that fails to load makes the command exit 2 with every failing
    recipe named on standard error and nothing on standard output. Without
    `--recipe` the output is exactly as before.
  - Also in this change: a canary-in-all-outputs test suite across the secrets
    surfaces, `Debug` hygiene tests for secret carriers, and threat-model tests.

- `user.password_hash: { secret: <path> }`: set a local
  user's password from a pre-generated hash kept as an encrypted secret. There
  is no plaintext `password` field.
  - The secret is one `$y$` (yescrypt) or `$6$` (sha512crypt) hash; anything
    else is refused without echoing it; `$y$` is refused on RHEL-family 9.
  - Applied with `sudo -n /usr/sbin/chpasswd -e` reading `name:hash` on standard
    input (never argv, never `usermod -p`), only on a mismatch. The stored field
    is read with `getent -s files shadow` under sudo and compared in memory; a
    leading `!` is ignored, and an account locked with a different hash is
    refused rather than silently unlocked.
  - Always sensitive; `--sudo` is required (plan, apply and audit error without
    it, never "no change"); `validate` never decrypts; audit names each
    drifting dimension of the user but shows both sides of every one as
    `[redacted]` (the whole resource is sensitive); MCP manifest tools refuse
    the reference.
  - Real-host acceptance on all eight supported targets was completed on
    2026-10-04 on a pre-release build, not on the v1.2.0 release artifact,
    including `sudo-rs` on Ubuntu 26.04 and the `$y$` refusal on
    RHEL-family 9; see
    [Supported Platforms](https://sinter.fulltrust.co.jp/en/compatibility/platforms/#real-host-acceptance-of-the-unreleased-secrets-features).
  - Not yet: a lock field, `on_create` mode.

- New dependencies: `age` 0.12.1 (exact pin, default features off: standard age
  format only, no plugins) and `zeroize`, with their transitive crates.

### Changed

- Fewer remote commands per run in two situations. Both are internal: output,
  `--format json` documents and the safety checks are unchanged, apart from the
  refusal wording noted below. Remote commands are also counted internally for
  tests and measurement (program name, resource-type label, duration and
  outcome; never arguments, environment, input or output; the program name is
  `[redacted]` for a sensitive request); the counts are never printed or sent
  anywhere.
  - Repeated lookups of the same owner, group or primary group within one run
    on one target are answered once and reused until the run changes the
    target (any command, file, directory, link or account change clears them).
    A lookup for a sensitive resource is never reused, and only a numeric id is
    ever kept.
  - On targets that do not have `getfacl` (in pre-release testing on real hosts:
    Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 10), the trusted-parent check
    before a write observes every ancestor directory with one `stat` command
    and, only when every ancestor passes that check, one `getfattr` command,
    instead of separate commands for each ancestor. Every trusted-parent check
    is a fresh observation (nothing is carried from one check to the next), a
    failed `stat` check ends the walk before `getfattr` is run, and a dispatched
    batch is never retried through the per-ancestor path. Targets that have `getfacl` (Rocky Linux,
    RHEL and AlmaLinux 9) keep the per-ancestor check, unchanged. A path whose
    batch command would be unusually long, or that contains control characters other
    than tab and newline, also uses the per-ancestor check, decided before anything is sent.
    Example, measured on real hosts without `getfacl` with a pre-release
    build: applying three resources
    (a new file, a new directory and a replaced file) under a seven-directory
    path took 149–150 remote commands before and 65–66 after; the trusted-parent
    checks alone went from 98 to 14 commands. These are command counts, not
    timings. For a missing ancestor directory the refusal message says that
    `stat` failed and a parent directory may be missing or inaccessible,
    instead of naming the missing ancestor; the operation is refused either
    way.

### Documentation

- English and Japanese reference pages for the `group` and `user` resources and
  for `sinter secrets`, the secrets sections of the `file` and `user` pages,
  the CLI, MCP and recipe-format references, and a Supported Platforms section
  recording the pre-release real-host acceptance of the secrets features.

## [1.1.3] - 2026-10-03

systemd manager synchronization and a service-stop fix. There is no new resource
type, handler action, recipe option or command-line flag; `--format json`
documents gain one additive key.

### Changed

- systemd manager synchronization. Sinter now runs `systemctl daemon-reload`
  itself when a `file`, `template` or `link` resource really changes systemd
  manager input (a unit file, a drop-in, an alias/mask/`.wants` link, or
  `system.conf` and its drop-ins) or when a fresh observation reports
  `NeedDaemonReload=yes`: before a `service` resource decides, before each
  notified handler runs, and at the end of a successful apply. A `service`
  or handler decision is always made on a fresh observation of the unit taken
  after the manager has been synchronized. The final reload at the end of an
  apply has no `service` or handler consumer, but it re-observes the managed
  units it identified; only a manager-only flush with no corresponding
  identifiable unit reports unit verification as not applicable. This is not
  a proof of global systemd consistency. `plan` and `audit` never reload, and
  an unchanged second apply performs none. A manual `daemon-reload` command
  resource is normally no longer needed. There is no new resource type,
  handler action or recipe option.
- Service observation now requests four properties
  (`LoadState,ActiveState,UnitFileState,NeedDaemonReload`) and rejects an
  answer that is missing, duplicating or malforming any of them. `audit`
  gains an independent `manager_reload` drift dimension.
- `--format json` plan/apply documents gain an additive top-level
  `manager_reloads` array. Existing keys and value sets are unchanged. The
  text output and the MCP plan tools report the reloads in the same way. A
  `plan` is still read-only: a `service` that depends on a pending manager
  input is reported as unknown (deferred until apply) instead of unchanged.
- Scope: the synchronization covers the system manager only (not
  `systemctl --user`), is local to one run, and keeps no persistent journal,
  rollback or retry. A reload that fails is reported as a failure, and the
  dependent `service` or handler does nothing.

### Fixed

- A `service` with `state: stopped` no longer fails after a successful stop of
  a unit that systemd has already unloaded (a running unit that is neither
  enabled nor referenced by another unit). `systemctl reset-failed` answering
  "Unit … not loaded." is accepted only when a fresh observation then shows the
  unit inactive; every other `reset-failed` failure is still a failure. A
  unit that is missing is still not treated as stopped.

### Documentation

- English and Japanese pages for the `service`, `file`, `template` and `link`
  resources, the execution model, the CLI and MCP references and
  troubleshooting describe the manager synchronization, its `plan` and
  `audit` behavior, its failure modes and its limits, with a unit → service →
  handler recipe example.

### Contributors

- [hagix9](https://github.com/hagix9)

## [1.1.2] - 2026-09-30

SSH security hardening, plus a stricter release validation gate. The only
change to the `sinter` runtime is the SSH algorithm policy below. Recipes,
command lines, and `--format json` documents are unchanged.

### Security

- SSH connections negotiate only modern algorithms. Key exchange, host key,
  cipher and MAC negotiation are restricted to explicit allowlists:
  curve25519, ECDH and SHA-2 Diffie-Hellman key exchange (group exchange
  with at least 2048-bit groups); Ed25519, ECDSA and RSA host keys with
  SHA-2 signatures; ChaCha20-Poly1305, AES-GCM and AES-CTR; HMAC-SHA2.
  The legacy fallbacks that the bundled libssh2 offered by default can no
  longer be negotiated: 1024-bit and SHA-1 key exchange, SHA-1 `ssh-rsa`
  host key signatures, CBC, RC4, Blowfish, CAST and 3DES ciphers, and MD5,
  SHA-1 and RIPEMD-160 MACs. Host certificate key types are no longer
  offered either, because `known_hosts` verification cannot validate them.
  There is no option to re-enable any of this. A server that offers only
  legacy algorithms is refused at the handshake (`Unable to exchange
  encryption keys`); current OpenSSH releases offer the allowed algorithms
  by default. RSA host keys keep working through `rsa-sha2-256` and
  `rsa-sha2-512`, and host key types already recorded in `known_hosts` are
  still tried first. The policy is installed before every handshake, and a
  failure to install it fails the connection.
- The public Gateway (`gateway/`, deployed separately and not part of the
  release artifact) validates JWTs with `jsonwebtoken` 10 (`aws_lc_rs`
  backend), with regression tests for `nbf` handling and the 2048-bit RSA
  key floor.

### Release validation

- The Linux validation gate runs the root test suite as `env
  SINTER_TEST_STRICT=1 SINTER_TEST_LOCAL_SSHD=1 cargo test --locked
  --all-targets --all-features`, and the acceptance checker requires exactly
  that command for every release after v1.1.1. In strict mode a test whose
  prerequisite is missing fails instead of being skipped and counted as
  passed; strict mode now also covers the throwaway-`sshd` suites and the
  extended-attribute and `script(1)` tests, which used to skip silently. The
  gate host is documented as Ubuntu 24.04 x86_64 with its prerequisites.
- The checker derives the root test harnesses and Linux-only suites from the
  candidate commit itself and requires the gate log to show every harness
  passing, adding up to the recorded counts, instead of trusting
  operator-supplied lists.
- Integration tests now prove the state they depend on before running:
  fixture setup steps that could fail silently (unit removal, private
  directory creation, seeded file contents, extended-attribute setup) are
  checked, and regression tests cover each.
- Per-commit CI builds (but does not run) the root test binaries and runs the
  gateway, installer and checker tests; a separate workflow scans
  dependencies for known advisories. The privileged root suite runs only in
  the release gate.

### Documentation

- Added `SECURITY.md` (private vulnerability reporting) and a contributing
  guide, and linked them from the README.

## [1.1.1] - 2026-09-29

Fail-closed validation fixes. Valid recipes, command lines, and `--format
json` documents are unchanged; recipes that could never run correctly are
now rejected by `validate` (exit 2) before anything connects, or fail
before any change is made.

### Fixed

- A `template` whose `state` resolved to a value other than `present` or
  `absent` was written as if it were `present`. It now fails before
  anything is observed or changed: `plan` exits 4 and `apply` reports the
  resource as failed.
- A `link` `state` other than `present` or `absent` was applied as
  `present`. It is now rejected.
- `validate` now rejects: a `file`, `directory`, `link`, or `template`
  `state` other than `present` or `absent`; a `link` whose `state` is
  `present` (or omitted) without a `target`; a literal string as a
  `service` `enabled` value; and a handler with an empty `service`.
  Previously these were accepted and failed only when the resource ran. An
  interpolated value is still checked when it is resolved.
- Mutating `systemctl` calls (`start`, `stop`, `enable`, `disable`,
  `reset-failed`, and handler `restart`/`reload`) now pass the unit name
  after `--`, as service observation already did, so a unit name beginning
  with `-` can never be read as a `systemctl` option.
- Documentation: corrected stale statements (the current release in
  `llms.txt`, the `validate` summary in the CLI reference, the WebMCP page's
  description of Sinter's own MCP server, hashed `known_hosts` and inventory
  on the supported-platforms page, `link` `target` requiredness in the
  resource metadata, and the agent skill's top-level recipe fields and
  target-option defaults) and four GitHub links missing the repository
  name.

## [1.1.0] - 2026-09-28

A small, fail-closed foundation for managing several hosts, plus SSH that
follows the operator's OpenSSH setup. Existing single-host command lines,
recipes, and `--format json` documents are unchanged.

### Added

- Inventory (`--inventory <file>`, alias `--hosts`): hosts and flat host
  groups in YAML or TOML. A host in the inventory is never a target by
  itself.
- Recipe `targets` (`hosts` / `groups`, union). With `--inventory`, a recipe
  without `targets`, an unknown host or group name, or a selection of zero
  hosts is an error before anything connects. Plan/apply/audit print the
  target resolution (MATCH/SKIP per host).
- Recipe bundles (`version: 1`, `recipes: [...]`): several recipes in one
  invocation, each resolved against its own `targets`; no nesting.
- Multi-host execution: (recipe, host) pairs run one at a time; `plan` and
  `audit` visit every selected host, `apply` stops at the first execution
  that exits non-zero (later executions are `not_run`); the
  exit code is the most severe execution code, so a partial failure is never
  0. JSON output is one document per invocation.
- Recipe `backup.paths`: copied on each selected target before `apply`
  changes anything (`~/.sinter/backups/<run-id>/` or, with `--sudo`,
  `/var/lib/sinter/backups/<run-id>/`), preserving mode, ACLs, ownership and
  timestamps. A failed backup stops the apply before any resource runs.
  Backups are not a rollback.
- OpenSSH client configuration inheritance for `--host` and inventory hosts
  through `ssh -G`: HostName, User, Port, IdentityFile, IdentitiesOnly,
  IdentityAgent, HostKeyAlias, UserKnownHostsFile. `--no-ssh-config`
  disables it. ProxyJump/ProxyCommand fail closed.
- Structured multi-host evidence: with `--inventory` or a bundle, `--format
  json` prints one document per invocation with the target resolution
  (selected/excluded hosts and why) and, per execution, the recipe, the
  target identity (inventory name, address, port, user), status, exit code,
  the single-target document or error, and a backup record (`planned`,
  `completed`, `failed`, `not_started`, `not_run`, or `null`). File content
  never appears in it. Single-target documents are unchanged.
- Colored status words on terminals only (respects `NO_COLOR`, `TERM=dumb`;
  never in pipes or JSON).

### Changed

- `validate` accepts every target option (`--host`, `--inventory`, SSH
  options) and ignores it; it reads no inventory, key or known_hosts file.
  Unknown options are still rejected.
- `--port` no longer defaults to 22 on the command line; the default comes
  from the inventory or OpenSSH configuration, then 22.
- Default identity files are `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`
  (`id_ecdsa` was not tried before).
- SSH authentication failures now say what was tried (agent, key files) and
  that passphrase-protected keys need ssh-agent.

### Fixed

- A host enrolled in `known_hosts` with only its Ed25519 or RSA key was
  refused as a "host key mismatch" when the server also offered ECDSA:
  known key types are now negotiated first.
- Hashed (`|1|...`) `known_hosts` entries are supported.
- Keys on `@revoked` lines in `known_hosts` are refused (they were ignored).
- Landing page: on narrow screens the audit pulse of the architecture
  diagram moved sideways across the vertical SSH line; it now travels along
  it like the other pulses.

### Not included

ProxyJump/ProxyCommand (such hosts fail closed), dynamic inventory, nested
groups, host or group variables, host patterns, parallel execution,
rollback or restore, and backup retention are not part of this release.

## [1.0.0] - 2026-09-27

First stable release. It declares the 1.x compatibility contract for the
`--format json` output and puts every release from here on behind a
mandatory Linux validation gate and published, independently verifiable
acceptance evidence. The `sinter` source is unchanged from 0.5.1 apart from
the version; configuration management behavior is unchanged.

### Added

- Documented the v1 machine-readable output contract for `--format json` on
  `validate`, `plan`, `apply`, and `audit`, with 1.x compatibility rules, and
  added contract tests for it. Output is unchanged.
- Acceptance evidence retention for v1.0.0 candidates onward
  (`release/ACCEPTANCE_EVIDENCE.md`): an Evidence Manifest, a published
  evidence bundle, acceptance checksums, and a checker
  (`release/check_acceptance_manifest.py`) with offline threat-model tests
  (`release/tests/`). The checker verifies the bundle archive in memory
  (containment, completeness, no links or special files), the artifact and
  executable hashes, the acceptance checksums, all eight required targets,
  the Linux validation gate record, and a sensitive-data scan.
- `RELEASE.md` is now a single ordered release state machine: source
  candidate, metadata, source validation, a mandatory Linux x86_64
  validation gate, one build and freeze, acceptance of that exact artifact,
  evidence and checker, human review, then tag and publish, with explicit
  invalidation rules.

### Fixed

- Documentation now attributes the current support claim to the v0.5.1
  release artifact (eight hosts, 344 checks passed, 0 failed); the v0.4.1
  acceptance is kept as history.
- The documentation site no longer defines each legacy redirect twice, which
  removes the route-collision warnings from the docs build. The generated
  site is unchanged.

## [0.5.1] - 2026-09-27

MCP tool annotations for the read-only `sinter mcp` interface, plus ChatGPT
Plugin documentation and public Gateway operator tooling. No change to
configuration management behavior.

### Added

- MCP tool annotations: every `sinter mcp` tool now declares
  `readOnlyHint: true`, `destructiveHint: false`, and `openWorldHint: false`,
  making the existing read-only guarantee explicit to MCP clients (required
  for ChatGPT plugin directory review). Tool behavior is unchanged.
- Documentation: ChatGPT Plugin guide (English and Japanese) covering the
  public Gateway / `sinter-bridge` architecture, setup, troubleshooting, and
  security/privacy, plus a README section.
- Gateway operator onboarding: `gateway/scripts/sinter-gw-admin` wraps the
  existing `sinter-gateway` operator CLI with account validation, an
  existing-controller pre-check, confirmation, `--dry-run`, and read-only
  `list`/`status`; `gateway/scripts/sinter-gw-admin-selftest` checks the
  issue → register → revoke path against a throwaway local Gateway;
  `gateway/docs/OPERATOR_ONBOARDING.md` is the operator runbook.
- `gateway/contrib/systemd/`: user unit and environment template for running
  `sinter-bridge` on Linux.

### Fixed

- `gateway/docs/PRODUCTION_DEPLOYMENT.md`: the bridge bootstrap ran
  `sinter-bridge register` twice; the first run consumed the single-use
  registration token. It now runs once and writes the credential file.

### Changed

- Gateway operator docs: administrative SSH to the Gateway host goes through
  IAP (`gcloud compute ssh --tunnel-through-iap`); the onboarding example sets
  `SINTER_GW_ADMIN_GCE_IAP=1`, and the break-glass path is documented.

## [0.5.0] - 2026-09-22

Core MCP: a read-only Model Context Protocol interface over stdio.

### Added

- `sinter mcp`: a strictly read-only MCP server speaking newline-delimited
  JSON-RPC 2.0 (protocol revision `2025-03-26`) over stdio. It is a thin
  adapter over the authoritative parser, planner, and audit engine — no
  validation or planning rule is reimplemented. stdout carries protocol
  frames only; diagnostics go to stderr.
- Eight read-only tools: `sinter_get_version`, `sinter_classify_platform`,
  `sinter_validate_manifest`, `sinter_inspect_manifest`, `sinter_plan`
  (supplied-facts in-process targets — no SSH), `sinter_list_targets`,
  `sinter_plan_host`, and `sinter_audit_host`. There is intentionally no
  apply, exec, or shell tool, and no mutation capability is exposed.
- Named target profiles via `sinter mcp --targets-file targets.toml`: an
  immutable, startup-loaded registry of administrator-owned SSH profiles.
  MCP callers reference targets by opaque name only — host, port, user,
  known_hosts, identity files, and sudo policy can never be supplied or
  overridden through tool arguments. `sinter_plan_host` and
  `sinter_audit_host` observe real hosts through the production `Mode::Plan`
  and `run_audit` paths; strict `known_hosts` verification and the existing
  bounded SSH behavior are unchanged.

### Security

- Read-only is enforced structurally, not by convention: host tools run on a
  `Mode::Plan` `TargetFs` that cannot produce a mutation permit, and
  `run_audit` independently refuses any mutation-capable engine. Command
  resources are never executed and audit as `NOT_AUDITABLE`.
- MCP manifests accept inline content only. `include:` and `source:` are
  rejected on the parsed structure before loading, so an MCP manifest grants
  no controller-local filesystem read authority. Staging uses a private
  0700 directory and a `create_new` 0600 manifest file.
- Profile internals (host, user, key paths) and staged paths are redacted
  from tool-facing diagnostics; host-plan file/template content diffs are
  always redacted regardless of manifest sensitivity flags.

### Changed

- Remote `systemctl show` observation now terminates option parsing with
  `--` before the unit name, so a manifest-controlled unit name can never
  be interpreted as a systemctl option.
- The documentation site gained a refreshed landing page, sidebar
  containment fixes, and a README terminal demo.

## [0.4.1] - 2026-09-21

Expanded acceptance-tested Linux x86_64 platform coverage and a more robust
DNF package path.

### Added

- RHEL 9 and RHEL 10 x86_64 as supported, acceptance-tested targets (`dnf`
  backend).
- AlmaLinux 9 and AlmaLinux 10 x86_64 as supported, acceptance-tested
  targets (`dnf` backend).
- DNF transaction-table parsing now accepts the wrapped header DNF emits
  when a repository ID is too long to fit on one line.

### Changed

- RPM payload acquisition now uses the native `dnf`/librepo download
  transport instead of direct URL fetching, so repository authentication —
  including authenticated cloud repository services — works without any
  Sinter-specific credential handling. Each downloaded RPM's identity is
  verified against the frozen transaction set before the final cache-only
  `dnf` install; if completeness or identity cannot be proven, the
  operation fails closed before mutation.

### Acceptance

- Sinter v0.4.1 was acceptance-tested on eight real x86_64 Linux hosts —
  Ubuntu 24.04.5 LTS, Ubuntu 26.04.1 LTS, Rocky Linux 9.8, Rocky Linux
  10.2, RHEL 9.8, RHEL 10.2, AlmaLinux 9.8, and AlmaLinux 10.2 — running
  the same frozen candidate binary and the same logical acceptance
  scenario: 344/344 checks passed, including the previously accepted
  Ubuntu and Rocky targets without regression.

## [0.4.0] - 2026-09-20

Read-only audit workflow, a verified Linux x86_64 installer, and Ubuntu
26.04 coreutils compatibility.

### Added

- `sinter audit <recipe>`: read-only audit mode answering whether the
  target currently matches the recipe. Reports `PASS`/`DRIFT`/
  `NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR` per resource — `command`
  resources are always `NOT_AUDITABLE` and never executed, `when`-skipped
  resources are `NOT_APPLICABLE` — with deterministic dependency order,
  text and JSON output, and sensitive-value redaction. Exit codes: 0 when
  clean (non-auditable/skipped resources may still be present), 7 on drift,
  6 when one or more observation errors dominate.
- Hardened remote observation contracts in `src/targetfs.rs`: `stat`
  diagnostics are accepted only on exact program identity, exact quoted
  path, and whole-field message text on a single newline-terminated line
  with empty stdout; truncation, multiline output, wrong errno suffixes,
  and unrelated diagnostics remain ambiguous and fail closed.
- `install.sh`: verified Linux x86_64 installer that selects the latest
  stable GitHub release (or a `SINTER_VERSION` pin), verifies SHA256SUMS
  before extraction, and installs into `$HOME/.local/bin` (or
  `SINTER_INSTALL_DIR`) without sudo — atomically replacing an existing
  user-owned executable and refusing symlinks and non-regular objects.
  Covered by `tests/installer/test_install.py` against a mocked release
  server, including rejection of traversal, `;`, and multiline versions.

### Fixed

- Ubuntu 26.04 Rust coreutils emit errno-suffixed `stat` diagnostics
  (`No such file or directory (os error 2)`); the absence classifier now
  accepts the exact `No such file or directory`/errno-2 and
  `Not a directory`/errno-20 pairs and stays fail-closed for any other
  suffix, message, or shape.
- The installer rejects multiline destination values before any mutation.

### Changed

- Documentation integrates `audit` into the validate → plan → apply →
  audit workflow across README EN/JA and the documentation site, and
  improves first-recipe guidance.

## [0.3.0] - 2026-09-19

Platform extension: Ubuntu 26.04 LTS and Rocky Linux 10 support, plus a
unified Linux x86_64 release artifact.

### Added

- **Ubuntu 26.04 LTS amd64** managed-target support. Detection is unchanged
  in substance: `src/facts.rs` derives the family from `/etc/os-release`
  `ID`/`ID_LIKE` with no version gate, so 26.04 resolves to `debian` and the
  `apt` backend exactly like 24.04. Real-host acceptance on Ubuntu 26.04.1
  x86_64 passed for command, file, template, package, and service resources,
  plan/apply idempotency, and converge-back purge idempotency.
- **Rocky Linux 10 x86_64** managed-target support (family resolves to
  `redhat`, `dnf` backend). The dnf snapshot-install contract built for dnf
  4.14 on Rocky 9 holds unchanged on dnf 4.20 / rpm 4.19, verified by
  on-target output captures (`repolist -v`, `install --assumeno`,
  `repoquery --location`) and a full real-host acceptance matrix on
  Rocky Linux 10.2 x86_64.
- Actionable error when the target lacks `/usr/bin/getfattr`: filesystem
  resources still fail closed (DESIGN §24.4), but the refusal now names the
  missing program and the `attr` package that provides it. Stock Ubuntu
  cloud images ship no `attr` package, so this is a documented target
  prerequisite.
- `tests/platform_next.rs`: backend selection, apt argv, dnf snapshot
  contract, and rpm 4.19 absent-marker classification for the two new
  targets, plus real `/etc/os-release` parser fixtures for both.
- Integration suites are now family- and unit-name-agnostic (they discover
  the controller's `ssh`/`sshd` unit and OS family), so they execute
  truthfully on both Debian- and RHEL-family controllers.

### Changed

- Linux x86_64 release artifacts are unified into one
  `sinter-v${VERSION}-linux-x86_64.tar.gz` built on the oldest supported
  baseline (Rocky Linux 9 x86_64, glibc 2.34) and verified, byte-identical,
  on Ubuntu 24.04, Ubuntu 26.04, Rocky Linux 9, and Rocky Linux 10. The
  previous per-target `ubuntu24.04-amd64` and `rocky9-x86_64` artifacts are
  superseded for future releases; published v0.2.0/v0.2.1 assets are not
  renamed or re-released. See `RELEASE.md` Phase D for the required
  per-target extraction/run verification.

### Validation

- Linux-native `cargo test` executed on Ubuntu 26.04.1 x86_64, Ubuntu 24.04.4
  x86_64, and Rocky Linux 9.8 x86_64, including the previously compile-only
  Linux-gated integration suites and the SSH suite against a real loopback
  target. `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean.
- Exact-binary experiment: one Rocky-9-built binary (SHA-256
  `af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2`)
  executed on all four supported Linux x86_64 platforms with identical
  checksums, `ldd` resolution, and a non-mutating `plan` on each.

- Frozen unified candidate from source `acbca6f8c726b4aed94c0b0b87c8a5506a4795af`
  passed the full four-real-host matrix on Ubuntu 24.04.5 LTS, Ubuntu 26.04.1
  LTS, Rocky Linux 9.8, and Rocky Linux 10.2 (all x86_64), including xattrs,
  applicable SELinux preservation, guard/refusal/redaction, idempotency and
  cleanup. This qualifies the candidate, not an already-published unified asset.

## [0.2.1] - 2026-09-17

Maintenance release adding explicit per-operation environment variables to
package resources.

### Added

- Optional `with.env` maps for package resources. Variables are passed to the
  selected `apt` or `dnf` operation, including privileged execution, without
  changing the host-wide environment.
- Environment variable names are validated and values are handled through the
  existing structured command and sensitive-value redaction paths.

### Validation

- Ubuntu 24.04.4 x86_64 / apt and Rocky Linux 9.8 x86_64 / dnf real-host
  acceptance passed, including plan safety, sudo propagation, idempotency,
  and sensitive-output checks.
- Forced-proxy/Squid connectivity was not part of this release acceptance.

## [0.2.0] - 2026-09-16

Second release of Sinter: RHEL-family platform support while preserving the
v0.1 contract on Ubuntu.

### Added

- RHEL-family platform detection from `/etc/os-release`.
- Rocky Linux 9 x86_64 support (`dnf` package backend, `systemd`).
- DNF package observation, install, and removal through the same
  platform-neutral `type: package` recipe contract; the backend (`apt` or
  `dnf`) is selected from the detected platform.

### Changed / improved

- Package installation on RHEL-family targets runs through a private snapshot
  of the DNF metadata cache: cache-only metadata validation and transaction
  resolution, validated RPM payload prefetch, then the final cache-only `dnf`
  mutation.
- DNF output is parsed under strict per-command grammars compatible with
  native DNF 4.14 streams, including real `repolist -v` preambles, benign
  informational stderr lines, and `--assumeno` transaction trailers.

### Security and safety

- DNF output parsing fails closed on malformed, ambiguous, or unexpected
  output.
- The private metadata snapshot is created with 0700 permissions and removed
  after the operation, including on failure.
- Mutation, cleanup, and verification outcomes are reported truthfully,
  including failure-after-mutation.
- Sensitive and derived-sensitive values remain redacted in output,
  diagnostics, and errors.
- Ubuntu 24.04 LTS behavior is unchanged.

### Supported environment

- Ubuntu 24.04 LTS amd64 — apt, systemd, OpenSSH, `/bin/sh`, passwordless
  `sudo -n` when privilege escalation is required (existing target).
- Rocky Linux 9 x86_64 — dnf, systemd, OpenSSH, `/bin/sh`, passwordless
  `sudo -n` when privilege escalation is required (new in v0.2.0).

Rocky Linux 9 acceptance reference: Rocky Linux 9.8 x86_64, DNF 4.14.0.
Other Rocky 9 minor releases share the same interfaces; 9.8 is the verified
reference.

### Validation

- Rocky Linux 9.8 x86_64 final acceptance: real SSH, `sudo -n`, package
  install/remove/idempotency, file/service/command resources, sensitive-output
  redaction, and failure-truth verification against DNF 4.14.0.
- Automated test suite green; fmt/clippy/diff-check clean.

### Known limitations

- No inventory, roles, plugins, orchestration, or embedded scripting.
- Hashed `known_hosts` entries are not supported.
- Managed hosts require no Sinter agent or runtime.

## [0.1.0] - 2026-09-13

First public release of Sinter.

### Added

- Agentless configuration management over SSH.
- `validate`, `plan`, and `apply` workflows.
- YAML and TOML recipe frontends.
- File, directory, template, link, command, package, and service resources.
- Resource dependencies, loops, variables, and delayed service handlers.
- Idempotent stateful resource management.
- Ubuntu 24.04 LTS amd64 support.
- `apt` package management.
- `systemd` service management.
- OpenSSH transport with strict `known_hosts` verification.
- Non-interactive privilege escalation through `sudo -n`.
- Text and JSON output.
- Sensitive-value redaction.
- Fail-fast execution and explicit failed/indeterminate result reporting.
- Atomic file publication and filesystem parent-path safety checks.

### Security and safety

- Plan mode performs observation only and does not mutate target state.
- Apply re-observes resources immediately before mutation decisions.
- Unknown or changed SSH host keys are rejected.
- Non-default SSH ports require an explicit `[host]:port` identity.
- Unexpected symlinks and unsafe parent paths are rejected.
- Indeterminate mutations are not automatically retried.
- Verification failures are promoted to failed execution where appropriate.

### Supported environment

The v0.1 reference target is:

- Ubuntu 24.04 LTS
- amd64
- OpenSSH
- apt
- systemd
- `/bin/sh`
- passwordless `sudo -n` when privilege escalation is required

### Known limitations

- RHEL-family distributions are not supported in v0.1.
- Hashed `known_hosts` entries are not supported.
- Sinter does not provide inventory, roles, plugins, orchestration, or embedded scripting.
- Managed hosts require no Sinter agent or runtime.
