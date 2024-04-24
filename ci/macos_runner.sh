#!/bin/sh
set -ex

# Install LLVM and system dependencies
brew update
brew install llvm@17 ninja

# Install Zig
ZIG_VERSION=0.12.0
ZIG_PACKAGE_NAME=zig-macos-aarch64-$ZIG_VERSION
wget https://ziglang.org/download/$ZIG_VERSION/$ZIG_PACKAGE_NAME.tar.xz
tar xf $ZIG_PACKAGE_NAME.tar.xz

# Build and test
$ZIG_PACKAGE_NAME/zig build test -Dthird_party_ci=true
