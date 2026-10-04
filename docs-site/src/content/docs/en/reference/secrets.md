---
title: sinter secrets
description: Encrypt, decrypt and list secret files in the standard age format (unreleased, after v1.1.3).
---

:::caution[Unreleased]
`sinter secrets` and the recipe field `file.content: { secret: … }` are on the
`main` branch after v1.1.3. They are **not** in the v1.1.3 release binary. The
`file` resource (`content`) and the `user` resource (`password_hash`) are the
only recipe uses of a secret so far; MCP use is not available. `secrets list
--recipe` ("used by", "missing", "not referenced") is new on `main` as well.
:::

**Purpose:** keep secret files (SSH keys, `.env` files, tokens, password hashes,
any binary) encrypted in a repository, using the standard
[age](https://age-encryption.org/v1) file format. The files are ordinary `.age`
files: they can be recovered without Sinter by any age-compatible tool.

## Commands

```
sinter secrets encrypt [--passphrase | -r, --recipient RECIPIENT ...] [-o, --output OUT] [-f, --force] <FILE | ->
sinter secrets decrypt [-i, --identity IDENTITY] <FILE>
sinter secrets list [--format text|json] [--recipe FILE ...] [PATH ...]
```

These are the complete flag sets; the short and long forms shown are the only
spellings (there are no other aliases). `--passphrase` cannot be combined with
`-r`/`--recipient`, which may be repeated. `--identity` on `decrypt` is an
**age** identity, not an SSH key, and is an error for a passphrase-encrypted
file. `--recipe` is repeatable and belongs to `list` only.

- **encrypt** writes `FILE.age` (or `-o OUT`; `-` reads stdin and then needs
  `-o`). The input is opaque bytes (no UTF-8 assumption, no newline changes),
  at most 16 MiB. The original file is **never changed or deleted**; Sinter
  cannot guarantee secure deletion on SSDs and copy-on-write filesystems, so
  remove it yourself.
- **decrypt** writes the plaintext to **stdout only** and refuses a terminal
  (redirect or pipe it). It never creates a file: `sinter secrets decrypt x.age > x`.
- **list** shows `*.age` files under the given paths (default `.`; `.git` is
  skipped; symbolic links are not followed) from their headers: status, method
  (`passphrase` or `recipients`) and the number of recipients. Nothing is
  decrypted. An explicitly named file is inspected by its content, whatever its
  name. The recipient count does not include the decoy stanza the age format
  adds on purpose, and age does not say *which* recipients; Sinter never claims
  a "recovery recipient".
  - **`--recipe FILE`** (repeatable; a recipe or a bundle) adds what the
    recipes you name say about the files. Nothing is discovered: only the
    recipes you give are read, and a recipe is never searched for. Each is
    loaded by the same loader as `validate`, so its structure, fields,
    includes and the *text* of every secret reference are checked exactly as
    there; only the state of the referenced file is observed afterwards
    instead of required. The output adds, for each secret, **referenced by**
    (`type:id` and the recipe argument as you wrote it, never a value from the
    resource), and these conclusions:
    - `missing` status: a valid reference whose file is absent. It does not
      make the command fail (exit 0), and `validate` still rejects the same
      recipe. A reference that passes through a symbolic link, names a
      directory or other non-regular file, or cannot be inspected (for example
      permission denied) is shown as `unreadable` with a note, a file that is
      not age is `not-age`/`invalid`; none of these is called `missing`.
    - **not referenced by the N recipe(s) given**: an age file in the listed
      paths that none of the recipes you named references. This is a statement
      about those recipes only, **not** that the file is unused or safe to
      delete: another recipe, another repository, or a person may use it.
      Files are matched by file identity (device and inode), so another
      spelling, a hard link, or a different letter case on a case-insensitive
      filesystem still counts as referenced; if a match cannot be established
      the conclusion is withheld. Resources that are conditional
      (`when`) or `state: absent` still count as references.
    - A file Sinter's identity discovery could pick (`identity.age`) gets a
      note instead of the "not referenced" conclusion; it is never offered as
      unreferenced. Only a file named `identity.age` (or the very same file
      under another name in that directory) is recognised; an identity kept
      elsewhere or under another name, for example one named by `--identity` or
      `SINTER_IDENTITY`, is not, so do not treat the listing as a deletion list.
      If a reference cannot be inspected (for example permission denied), no
      "not referenced" conclusion is made at all.
    If **any** recipe fails to load (invalid YAML, an unknown field, a bad
    reference, a bad include, an unreadable file), the command exits 2, names
    every failing recipe on standard error and prints **no** listing and no
    conclusion. `--recipe` does not change which paths are listed, and it
    never decrypts, prompts, or looks for an identity. Without `--recipe` the
    output is unchanged.

## `list` output

`list` prints nothing but what it can derive from the files; it never decrypts,
prompts or looks for an identity. Nothing it says is proof about a secret's
content or about how a secret is used elsewhere.

**Text.** A header line `STATUS METHOD RECIPIENTS PATH`, then one line per file
(`-` where a column does not apply) with any note and, with `--recipe`, the
`[referenced by …]` and "not referenced" remarks. No file at all prints
`no age files found`. If a limit was reached the last lines say the listing was
truncated. With `--recipe`, a final line states that the analysis covers only
the recipes given.

**JSON** (`--format json`):

```json
{
  "command": "secrets list",
  "secrets": [
    {
      "path": "secrets/app.age",
      "status": "ok",
      "method": "recipients",
      "recipients": 2,
      "armored": false,
      "note": null,
      "referenced_by": [{ "recipe": "site.yaml", "resource": "file:app_key" }],
      "not_referenced": false,
      "possible_identity_file": false
    }
  ],
  "truncated": false,
  "recipes": ["site.yaml"]
}
```

`method` and `recipients` are `null` unless the status is `ok`. `referenced_by`,
`not_referenced`, `possible_identity_file` and the top-level `recipes` appear
**only with `--recipe`**. `not_referenced` is `true`, `false` or `null` (`null`
means no conclusion is justified: the file is not a parsed age file, it may be
an identity file, its identity could not be established, or some reference
could not be inspected).

| Status | Meaning (all from the file's header and its path; nothing is decrypted) |
|---|---|
| `ok` | A regular file with a well-formed age header: method, recipient count and armor are reported. |
| `not-age` | A regular file that is not in the age format, or whose header is malformed or outside Sinter's bounds. |
| `unsupported` | An age-style file in a format or version Sinter does not read. |
| `too-large` | Larger than the largest age file Sinter accepts for a 16 MiB secret. |
| `invalid` | Starts like an age file but cannot be read as one (for example corrupt armor). |
| `unreadable` | Not a regular file, a symbolic link (not followed), or it could not be read or inspected; also a file skipped because the read budget was reached. A note says which. |
| `missing` | `--recipe` only: a valid reference whose file does not exist. |

A status describes one file's header. `ok` does not mean the file decrypts with
any key you hold, that the key exists, or that the recipient list is what you
intended; `list` cannot say *which* recipients, and a single-recipient or
passphrase file is flagged with a note because losing that key or passphrase
loses the secret.

**Limits.** The walk goes at most 32 directories deep, at most 10,000 files,
at most 100,000 directory entries, and reads at most 512 MiB in total; when any
limit stops it, `truncated` is `true` (text: "listing truncated"). `.git` is
skipped and symbolic links are not followed.

**Exit codes.** `0` after a listing, including one that shows `missing`,
`unreadable` or `not-age` entries; `2` when a given path does not exist, or when
any `--recipe` fails to load (nothing is listed then). `list` never fails
because a secret is unreferenced.

**Reading `not referenced` correctly.** It means exactly: *an age file in the
listed paths that none of the N recipes you named references.* It does **not**
mean the file is unused anywhere, nor that it is safe to delete: other recipes,
other repositories, other branches, scripts and people may use it, and
conditional (`when`) or `state: absent` resources still count as references.
`possible_identity_file` marks a file Sinter's identity discovery could pick
(named `identity.age`, or the same file under another name in that directory);
such a file is never reported as not referenced, and an identity kept elsewhere
is not recognised, so never treat a listing as a deletion list.

## Encryption methods

| Method | How | Notes |
|---|---|---|
| Recipient | `-r age1…` (repeatable), or the nearest `recipients.txt` | Anyone holding **one** matching identity (private key) can decrypt. Several recipients give redundancy. |
| Passphrase | `--passphrase` | Typed on the terminal, echo off, asked twice, at least 12 characters. Strength depends entirely on the passphrase. |

Recipients (`-r`, and every line of `recipients.txt`) must be **native age
recipients, `age1…`** (X25519). SSH public keys (`ssh-ed25519`, `ssh-rsa`),
plugin recipients (`age1plugin1…`) and other types are rejected, at most 256 per
file. Identities are likewise native `AGE-SECRET-KEY-1…` keys or an age file
encrypted with a passphrase. The files Sinter writes are standard age files, so
any age tool can read them; Sinter itself reads only passphrase files whose
scrypt work factor is at most 2^20 and files for native identities, so it cannot
open a file made by another tool for an SSH or plugin recipient.

A passphrase and recipients cannot be mixed in one file (the age format
forbids it). With neither flag, Sinter uses the nearest `recipients.txt` in the
output's directory or a parent **up to the repository root** (the directory
containing `.git`; without a repository only the output's directory is
searched). Sinter always prints which `recipients.txt` it used and a short
fingerprint of each recipient, and on a terminal asks you to confirm: **a
`recipients.txt` that came with a cloned repository decides who can read what you
encrypt, so review it** (or pass `-r`). If there is none and a terminal is
available, it asks (passphrase, or a new key pair); without a terminal it fails
and names the two flag forms.

Passphrases are accepted **only from the terminal** (`/dev/tty`): never as an
argument, from an environment variable, from stdin or from a file. Automation
and CI therefore use recipients and identities, not passphrases.

## Identities (private keys) and where they live

`decrypt` finds the identity for a recipient-encrypted secret in this order, and
uses the **first** one it finds (no trial and error across candidates):

1. `--identity PATH`
2. `SINTER_IDENTITY` — a **path**, never the key itself
3. the default identity, outside any repository: `$XDG_CONFIG_HOME/sinter/identity`
   (absolute `XDG_CONFIG_HOME` only), else `~/.config/sinter/identity`
4. a passphrase-protected `identity.age` in the secret's directory or a parent,
   up to the repository root

An identity file is either a plaintext age identity (`AGE-SECRET-KEY-1…`) or an
age file encrypted with a passphrase (asked on the terminal). A **plaintext**
identity must be readable only by you (`chmod 600`) and owned by you, otherwise
it is refused. A plaintext `identity.age` found inside a repository is **never**
used automatically; an `identity.age` symlink in a repository is refused.

When you create a key pair interactively (the second menu choice of
`encrypt`), Sinter asks where to keep the private key. It is always protected by
a passphrase, and:

- **outside the repository** (`~/.config/sinter/identity`, the recommended
  default), or
- **in this repository** (`identity.age` next to `recipients.txt`), an explicit
  choice for closed-network or simplified setups.

## Two operating models

| | A. Production / separated | B. Closed network / simplified |
|---|---|---|
| Ciphertext | in the repository | in the repository |
| Private key | **outside** the repository (unprotected for automation, or passphrase-protected) | passphrase-protected `identity.age` **in** the repository |
| Who can decrypt a stolen repository copy | nobody without the key file | anyone who can guess the passphrase |
| Automation / CI | an unprotected identity kept outside the repository | not possible without the passphrase (terminal only) |

**Model B is not equivalent to key separation.** If the repository is copied,
the passphrase becomes the only remaining protection, and one passphrase then
protects *every* secret. Choose a long passphrase (or a generated one), and use
Model A when that trade-off is not acceptable. A plain unprotected identity for
automation is created with the standard `age-keygen`; Sinter does not generate
unprotected identities.

## Using a secret in a recipe

A `file` resource can take its content from an encrypted secret instead of a
literal or a controller file:

```yaml
- id: app_key
  type: file
  with:
    path: /home/app/.ssh/id_ed25519
    content: { secret: secrets/app-id-ed25519.age }
    owner: app
    mode: "0600"
```

- **The reference** is a static path, relative to the recipe file that names it
  (an included recipe's own directory), at most 1024 bytes. It is refused if it
  is absolute, contains a backslash, control characters, `{{`/`}}` (any
  interpolation), or an empty, `.` or `..` component, or if any component below
  that directory is a symbolic link; the target must be a regular file holding a
  well-formed age header. The value must be exactly `{ secret: <path> }`;
  `content` and `source` stay mutually exclusive. Only `file.content` and
  `user.password_hash` accept a secret reference.
- **The method is not in the recipe.** The age header says whether the file
  opens with a passphrase or an identity; Sinter follows it.
- **A secret-holding resource is always sensitive**: its diff is redacted, a
  new file defaults to mode `0600`, and diagnostics are redacted, whatever the
  resource declares.
- **`validate`** checks that the reference is allowed, and that the file exists
  and is a well-formed age file. It **never decrypts** and needs no key.
- **`plan`, `apply` and `audit` decrypt**, because the desired SHA-256 of the
  file needs the plaintext (a stored hash of a low-entropy secret would be a
  guessing oracle). The plaintext goes through the unchanged file pipeline to
  the target; no controller temporary file is written. Content is compared and
  published as exact bytes (no newline or line-ending change). If the key is not
  available, `plan` and `apply` fail that resource, and `audit` reports `ERROR`
  for a file that exists on the target: it never reports `COMPLIANT`, and an
  apply never writes a partly decrypted file. The report text is redacted (the
  resource is sensitive); the cause (for example that no identity was found, or that a
  passphrase-protected secret needs a terminal) is printed once on standard
  error as `secret unavailable: <reference>: <cause>`; the cause wording is
  diagnostic text, not a stable interface. A target file that does not
  exist is `DRIFT` in `audit` without opening the secret. `state: absent` needs
  no key. `apply` opens each secret as it reaches the resource, so run `plan`
  first: it reports an unavailable key before anything is changed.
- **Identity discovery** is the order above without `--identity`: on `plan`,
  `apply` and `audit`, `--identity` already means an **SSH** private key and is
  never used for secrets. Use `SINTER_IDENTITY` (a path), the default identity
  file, or a passphrase-protected repository `identity.age`. A protected
  identity is unlocked once per invocation (a failed unlock is not asked again),
  on the terminal only. A passphrase-encrypted secret asks for its passphrase on
  the terminal once per file and invocation; use recipient-encrypted secrets for
  unattended runs.
- **`user.password_hash: { secret: <path> }`** uses the same reference rules and
  identity discovery; the secret is one password hash line. See the
  [user resource](/en/reference/resources/user/#password-hash).
- **MCP** manifest tools refuse any `content` or `password_hash` secret
  reference: a manifest sent by a client cannot make the gateway decrypt a file.

The plaintext is held in memory in buffers that Sinter zeroizes when it is done
with them, and is sent to the target over the existing SSH channel (or local
pipe) on standard input; it is not put on a command line or in the environment.
Copies inside the SSH library or the operating system are outside Sinter's
control. Sinter does not protect against root on the controller or on the
target.

## Output safety

- The ciphertext is written to a temporary file in the destination directory
  (mode 0600, exclusive create), synced, then published atomically, and the
  directory entry is synced. No plaintext temporary file is ever created.
- An existing output is **never replaced silently**. `--force` replaces an
  existing file only if it is itself an age file. A symbolic link at the output
  is always refused. The input file must be a regular file (a symbolic link is
  refused).
- Where the filesystem has no hard links (some network or exFAT volumes) the
  no-clobber publish falls back to an exclusive create, which never replaces a
  file but is not atomic.
- Ciphertext is never written to stdout or a terminal.
- stdin and stdout are used unbuffered, and a signal at the passphrase prompt
  restores the terminal's echo.
- The process disables core dumps (and, on Linux, ptrace attach) before it
  handles a secret; decrypted buffers are zeroized on a best-effort basis.
  This does not protect against root on the same machine.

## Exit codes

`0` success; `2` a usage, policy or input problem (missing flag, missing or
refused file, no identity found, unsafe permissions, an identity setting that
contains a key instead of a path, recipients not confirmed); `5` the operation
failed (the key or passphrase does not open the secret, corrupt data, I/O).
Messages are fixed text plus the paths you gave (control and bidirectional
characters in names are replaced); they never contain plaintext, passphrases,
keys or full recipients.

## Recovery and rotation

- If **every** usable identity and passphrase is lost, the secret is
  unrecoverable. Sinter has no recovery mechanism and does not escrow keys.
- Add another recipient (a spare or recovery key held elsewhere) *before* you
  need it: `sinter secrets decrypt a.age | sinter secrets encrypt -r NEW1 -r NEW2 --force -o a.age -`.
  Sinter cannot tell from a file whether a recipient is a "recovery" key.
- Re-encrypting does **not** revoke ciphertext that was already copied: whoever
  holds an old copy and the old key can still read that copy. If a key or
  passphrase may have been exposed, **rotate the underlying secret at its
  source** (new SSH key, new password, new token).
- `list` warns about files with a single recipient and about passphrase files
  (a forgotten passphrase cannot be recovered).

## Limits

16 MiB per secret; at most 256 recipients per file; passphrase length at most
1024 bytes; age headers are bounded and oversized or hostile headers are
rejected before any key work.

**Transfer deadline.** A secret-backed file is written to the target by one
command that receives the content on standard input, and every target command
has a 300 second deadline. A 16 MiB secret therefore needs a sustained rate of
about 56 KiB/s or better (measured: 4.2 s and 4.4 s over loopback SSH on real
targets; that is a best case, not a network measurement). If the deadline
passes during the write, the resource is reported **indeterminate** (exit code
6) and the run stops. The content is written to a private staging file and moved
into place only after the write completes, so the destination is not left
partly written; because the outcome is unknown, the private staging directory
beside the destination may remain. Transfers slower than this are not
supported: use a faster path to the target. Every other file write has the same
deadline.
