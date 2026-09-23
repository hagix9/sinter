---
title: Contributing
description: Build, test, and contribution workflow for Sinter.
---

## Build

```sh
cargo build --release
# binary: target/release/sinter
```

## Quality gates

The full local gate set used for releases:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
```

## Test layout

| Suite | Scope |
|-------|-------|
| lib unit tests | value model, frontends, expressions, paths, argv quoting |
| `frontends` | YAML/TOML equivalence, schema rejection, includes |
| `engine` | file/dir/link/template, plan safety, idempotency, fail-fast |
| `commands` | guards, registers, changed_when, env baseline, exit codes |
| `handlers` | delayed handlers, dedup, verification gating |
| `package_service` | apt/dnf install/remove/idempotency, systemd states |
| `file_safety` | trust boundary, symlink rejection, atomic publication |
| `truthfulness` | result-dimension matrix |
| `cli` | exit codes, JSON output, sensitive redaction |
| `ssh` | real SSH integration (env-gated) |

SSH integration tests need a disposable Ubuntu target:

```sh
export SINTER_TEST_SSH_HOST=127.0.0.1
export SINTER_TEST_SSH_PORT=22
export SINTER_TEST_SSH_USER=ubuntu
export SINTER_TEST_SSH_KNOWN_HOSTS=/path/to/known_hosts
export SINTER_TEST_SSH_IDENTITY=/path/to/test_key
cargo test --test ssh
```

## Documentation

This site lives in `docs-site/` (Astro + Starlight):

```sh
cd docs-site
npm ci
npm run dev      # local dev server
npm run build    # static build to dist/
```

Resource metadata shared by the docs and the WebMCP tools lives in
`src/data/resources.json` — update it when resource parameters change.

## Releases

Release procedure: see
[RELEASE.md](https://github.com/hagix9/blob/main/RELEASE.md) in the
repository.
