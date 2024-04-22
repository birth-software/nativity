#!/bin/sh
set -ex

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 all

sudo apt install liblld-17-dev libclang-17-dev liblld-17 ninja-build cmake -y

zig build test -Dthird_party_ci=true
