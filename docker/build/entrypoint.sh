#!/bin/sh

set -ex

# Fix for missing bullseye repos:
echo 'deb http://archive.debian.org/debian bullseye main
deb http://deb.debian.org/debian-security bullseye-security main
deb http://archive.debian.org/debian bullseye-updates main' > /etc/apt/sources.list

apt-get install debian-archive-keyring

apt update
apt install --no-install-recommends -y curl pkg-config libpcsclite-dev libpcsclite-dev:arm64

# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

exec /entrypoint.sh $@
