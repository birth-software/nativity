#!/usr/bin/env bash

echo "Testing Nativity with Zig"
zig build test -Dall -Doptimize=ReleaseSafe --summary all
echo "Compiling Nativity with Zig"
time zig build -Doptimize=ReleaseSafe
failed_test_count=0
passed_test_count=0
test_directory_name=test
test_directory=$test_directory_name/*
total_test_count=$(ls 2>/dev/null -Ubad1 -- test/* | wc -l)
ran_test_count=0
test_i=1

for dir in $test_directory
do
    MY_TESTNAME=${dir##*/}
    zig build run -Doptimize=ReleaseSafe -- $dir/main.nat
    if [[ "$?" == "0" ]]; then
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            nat/$MY_TESTNAME
            if [[ "$?" == "0" ]]; then
                passed_test_count=$(($passed_test_count + 1))
                result="PASSED"
            else
                failed_test_count=$(($failed_test_count + 1))
                result="FAILED"
            fi
            echo "[$test_i/$total_test_count] [$result] $MY_TESTNAME"
            ran_test_count=$(($ran_test_count + 1))
        fi
    else
        "$MY_TESTNAME failed to compile"
    fi
    test_i=$(($test_i + 1))
done

echo "Ran $ran_test_count tests ($passed_test_count passed, $failed_test_count failed)."

if [[ $failed_test_count == "0" ]]; then
    true
else
    false
fi
