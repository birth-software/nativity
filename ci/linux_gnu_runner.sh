#!/bin/sh
set -ex

# Install LLVM and system dependencies
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 all
sudo apt install liblld-17-dev libclang-17-dev liblld-17 ninja-build cmake -y

# Install Zig
ZIG_VERSION=0.12.0
ZIG_PACKAGE_NAME=zig-linux-x86_64-$ZIG_VERSION
wget https://ziglang.org/download/$ZIG_VERSION/$ZIG_PACKAGE_NAME.tar.xz
tar xf $ZIG_PACKAGE_NAME.tar.xz

# Build and test
$ZIG_PACKAGE_NAME/zig build test -Dthird_party_ci=true
