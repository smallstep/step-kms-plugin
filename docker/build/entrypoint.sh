#!/bin/sh

set -e

# Add build dependencies
apt update
apt install --no-install-recommends -y libpcsclite-dev libpcsclite-dev:arm64 
apt install --no-install-recommends -y pkg-config pkg-config:arm64

# Fix "dubious ownership in repository" error
git config --global --add safe.directory /go/src/github.com/smallstep/step-kms-plugin
exec /entrypoint.sh $@