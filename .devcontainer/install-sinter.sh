#!/usr/bin/env bash
# Start environment setup: install the published Sinter release with the
# repository's installer, which downloads the official GitHub Release asset
# and verifies it against the release SHA256SUMS before installing.
# Update SINTER_VERSION when a new release is published.
set -euo pipefail
# Sinter requires /usr/bin/getfattr (the attr package) on every machine it
# manages; the base image does not include it.
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends attr
SINTER_VERSION=v1.1.1 SINTER_INSTALL_DIR="$HOME/.local/bin" sh ./install.sh
"$HOME/.local/bin/sinter" --version
echo
echo "Try: sinter validate examples/start/hello.yaml"
echo "     sinter plan examples/start/hello.yaml"
