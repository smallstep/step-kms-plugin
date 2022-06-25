#!/bin/sh

set -e

apt update
apt install -y libpcsclite-dev

exec /entrypoint.sh $@