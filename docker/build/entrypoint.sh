#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y curl pkg-config libpcsclite-dev libpcsclite-dev:arm64

# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

exec /entrypoint.sh $@
