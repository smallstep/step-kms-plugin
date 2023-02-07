#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y libpcsclite-dev libpcsclite-dev:arm64
git log -1
exec /entrypoint.sh $@