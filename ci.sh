#!/usr/bin/env bash

set -xe
zig build test -Dall --summary all

for dir in test/*
do
    zig build run -- $dir/main.nat
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        nat/${dir##*/}
    fi
done
