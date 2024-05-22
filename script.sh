#!/bin/bash

set -ex

MY_SOURCE_FILE=retest/standalone/first/main.nat

i=$((0))
while ((i < 1000)); do
    zig build run -Dprint_stack_trace=true -Doptimize=Debug -- exe -main_source_file $MY_SOURCE_FILE
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSafe -- exe -main_source_file $MY_SOURCE_FILE
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSmall -- exe -main_source_file $MY_SOURCE_FILE
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseFast -- exe -main_source_file $MY_SOURCE_FILE
    i=$((i + 1))
done
