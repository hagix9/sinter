# Try Sinter in a Codespace

**English** | [日本語](README.ja.md)

This codespace is a disposable Ubuntu 24.04 x86_64 container in your own
GitHub account. When it was created, it installed the published Sinter
v1.1.1 release into `~/.local/bin` with the repository's `install.sh`, which
verifies the download against the release `SHA256SUMS`, and added the `attr`
package that Sinter requires on every machine it manages. Nothing connects to
any other machine.

Open a terminal and run:

```sh
sinter --version
sinter validate examples/start/hello.yaml
sinter plan examples/start/hello.yaml    # observes only; changes nothing
sinter apply examples/start/hello.yaml   # creates ~/sinter-start/hello.txt
sinter plan examples/start/hello.yaml    # nothing left to change
sinter audit examples/start/hello.yaml
```

[`hello.yaml`](hello.yaml) manages only `~/sinter-start` inside this
codespace. (Sinter refuses to write under world-writable directories such as
`/tmp` — one of its safety checks.) Without `--host`, Sinter targets the machine it runs on. Edit the
recipe and run the commands again to explore.

This container has no systemd, so `service` resources are best tried on a
real supported host over SSH — see the
[documentation](https://sinter.fulltrust.co.jp/).

Codespaces usage counts against your GitHub account's Codespaces quota.
Stop or delete the codespace when you are done.
