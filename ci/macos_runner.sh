#!/bin/bash
set -ex

# Install LLVM and system dependencies
brew update
brew install llvm@17 ninja

# Install Zig
source ci/download_zig.sh
download_zig master aarch64-macos

# Build and test
zig build test -Dthird_party_ci=true
