#!/bin/sh

set -e

apt update
apt install --no-install-recommends -y curl pkg-config libpcsclite-dev libpcsclite-dev:arm64

# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install llvm-mingw compiler for arm64 if necessary
if [ ! -e /llvm-mingw ]; then
    cd /
    curl -sSfL "https://github.com/mstorsjo/llvm-mingw/releases/download/20251021/llvm-mingw-20251021-ucrt-ubuntu-22.04-x86_64.tar.xz" | bsdtar -xf -
    ln -snf $(pwd)/llvm-mingw-20251021-ucrt-ubuntu-22.04-x86_64 /llvm-mingw
    cd -
fi

exec /entrypoint.sh $@
