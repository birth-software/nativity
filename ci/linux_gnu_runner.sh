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

i=$((0))
while ((i < 1000)); do
    zig build run -Dthird_party_ci=true -Dprint_stack_trace=true -Doptimize=Debug -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dthird_party_ci=true -Dprint_stack_trace=true -Doptimize=ReleaseSafe -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dthird_party_ci=true -Dprint_stack_trace=true -Doptimize=ReleaseSmall -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dthird_party_ci=true -Dprint_stack_trace=true -Doptimize=ReleaseFast -- exe -main_source_file retest/standalone/first/main.nat
    i=$((i + 1))
done
