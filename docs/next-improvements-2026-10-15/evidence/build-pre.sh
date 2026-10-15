#!/bin/bash
# Build the pre-fix (origin/main, v1.4.0) source on a disposable Rocky VM.
# Used as the "before" binary for the N-2 and DNF-metadata comparisons.
set -euxo pipefail
TARBALL=/home/a0000/sinter-pre-src.tar.gz
WORK=/root/sinter-pre-src

export PATH=/root/.cargo/bin:$PATH
cd "$WORK" 2>/dev/null || { mkdir -p "$WORK"; }
rm -rf "$WORK"; mkdir -p "$WORK"
tar -xzf "$TARBALL" -C "$WORK"
cd "$WORK"
echo "ARGV: cargo build --locked -j1" > /root/pre-build-argv.txt
cargo build --locked -j1 2>&1 | tee /root/pre-build.log | tail -5
strip target/debug/sinter
sha256sum target/debug/sinter | tee /root/pre-binary.sha256
install -m 0755 target/debug/sinter /usr/local/bin/sinter-pre
/usr/local/bin/sinter-pre --version
echo "=== PRE BUILD DONE ==="
