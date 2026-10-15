#!/bin/bash
# Build the Sinter v1.5-improvements source on a disposable Rocky VM (run as root).
set -euxo pipefail
TARBALL=/home/a0000/sinter-v15-src.tar.gz
WORK=/root/sinter-src

echo "=== STEP swap ==="
if ! swapon --show | grep -q .; then
  (fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096)
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
fi
free -m | sed -n 1,3p

echo "=== STEP toolchain deps ==="
dnf -y install gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl tar

echo "=== STEP rustup ==="
if ! [ -x /root/.cargo/bin/cargo ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh
  sh /tmp/rustup.sh -y --profile minimal --default-toolchain stable
fi
export PATH=/root/.cargo/bin:$PATH
rustc --version
cargo --version

echo "=== STEP extract ==="
rm -rf "$WORK"
mkdir -p "$WORK"
tar -xzf "$TARBALL" -C "$WORK"

echo "=== STEP build ==="
cd "$WORK"
echo "ARGV: cargo build --locked -j1" > /root/build-argv.txt
cargo build --locked -j1 2>&1 | tee /root/build.log | tail -25
ls -la target/debug/sinter
sha256sum target/debug/sinter | tee /root/binary.sha256
echo "=== BUILD DONE ==="
