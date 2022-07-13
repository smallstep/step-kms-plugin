#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y libpcsclite-dev libpcsclite-dev:arm64

exec /entrypoint.sh $@