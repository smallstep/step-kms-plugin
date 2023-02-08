#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y pkg-config libpcsclite-dev libpcsclite-dev:arm64

exec /entrypoint.sh $@