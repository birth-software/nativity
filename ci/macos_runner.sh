#!/bin/sh
set -ex
brew update
brew install llvm@17 ninja
zig build test -Dthird_party_ci
