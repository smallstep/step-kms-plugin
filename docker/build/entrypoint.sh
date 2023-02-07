#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y libpcsclite-dev libpcsclite-dev:arm64
git config --global --add safe.directory /go/src/github.com/smallstep/step-kms-plugin
git log -1
exec /entrypoint.sh $@