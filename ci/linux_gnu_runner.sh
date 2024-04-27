#!/bin/bash
set -ex

# Install LLVM and system dependencies
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 all
sudo apt install liblld-17-dev libclang-17-dev liblld-17 ninja-build cmake -y

# Install Zig
source ci/download_zig.sh
download_zig master x86_64-linux

# Build and test
zig build test -Dthird_party_ci=true
