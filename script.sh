#!/bin/sh

set -e 

i=$((0))
while ((i < 1000)); do
    zig build run -Dprint_stack_trace=true -Doptimize=Debug -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSafe -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseSmall -- exe -main_source_file retest/standalone/first/main.nat
    zig build run -Dprint_stack_trace=true -Doptimize=ReleaseFast -- exe -main_source_file retest/standalone/first/main.nat
    i=$((i + 1))
done
