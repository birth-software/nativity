#!/bin/bash
set -ex

# Install LLVM and system dependencies
brew update
brew install llvm@18 ninja

# Install Zig
source ci/download_zig.sh
download_zig master aarch64-macos

# Build and test
i=$((0))
while ((i < 1000)); do
    zig build run -Dprint_stack_trace=true -Doptimize=Debug -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSafe -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSmall -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseFast -- exe -main_source_file retest/standalone/first/main.nat
    i=$((i + 1))
done
