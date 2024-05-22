#!/bin/bash
set -ex

# Install LLVM and system dependencies
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
MY_LLVM_VERSION=18
sudo ./llvm.sh $MY_LLVM_VERSION all
sudo apt install liblld-$MY_LLVM_VERSION-dev libclang-$MY_LLVM_VERSION-dev liblld-$MY_LLVM_VERSION ninja-build cmake -y

# Install Zig
source ci/download_zig.sh
download_zig master x86_64-linux

# Build and test

zig build test -Dthird_party_ci=true -Doptimize=Debug
zig build test -Dthird_party_ci=true -Doptimize=ReleaseSafe
zig build test -Dthird_party_ci=true -Doptimize=ReleaseSmall
zig build test -Dthird_party_ci=true -Doptimize=ReleaseFast
