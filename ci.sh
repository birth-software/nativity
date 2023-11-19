#!/usr/bin/env bash

echo "Testing Nativity with Zig"
echo "Compiling Nativity with Zig"
nativity_use_llvm=false
zig build -Duse_llvm=$nativity_use_llvm
failed_test_count=0
passed_test_count=0
test_directory_name=test
test_directory=$test_directory_name/*
total_test_count=$(ls 2>/dev/null -Ubad1 -- test/* | wc -l)
ran_test_count=0
test_i=1
passed_compilation_count=0
failed_compilation_count=0
failed_compilations=()
failed_tests=()

for dir in $test_directory
do
    MY_TESTNAME=${dir##*/}
    zig build run -Duse_llvm=$nativity_use_llvm -- $dir/main.nat -log ir
    if [[ "$?" == "0" ]]; then
        passed_compilation_count=$(($passed_compilation_count + 1))
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            nat/$MY_TESTNAME
            if [[ "$?" == "0" ]]; then
                passed_test_count=$(($passed_test_count + 1))
                result="PASSED"
            else
                failed_test_count=$(($failed_test_count + 1))
                result="FAILED"
                failed_tests+=("$test_i. $MY_TESTNAME")
            fi
            echo "[$test_i/$total_test_count] [$result] $MY_TESTNAME"
            ran_test_count=$(($ran_test_count + 1))
        fi
    else
        failed_compilation_count=$(($failed_compilation_count + 1))
        echo "$MY_TESTNAME failed to compile"
        failed_compilations+=("$test_i. $MY_TESTNAME")
    fi
    test_i=$(($test_i + 1))
done

echo "Ran $total_test_count compilations ($passed_compilation_count succeeded, $failed_compilation_count failed)."
echo "Ran $ran_test_count tests ($passed_test_count passed, $failed_test_count failed)."

if [[ "$failed_compilation_count" != "0" ]]; then
    echo "Failed compilations:"
    for failed_compilation in "${failed_compilations[@]}"
    do
        echo "$failed_compilation"
    done
fi

if [[ "$failed_test_count" != "0" ]]; then
    echo "Failed tests:"
    for failed_test in "${failed_tests[@]}"
    do
        echo "$failed_test"
    done
fi

if [[ "$failed_test_count" == "0" && "$failed_compilation_count" == "0" ]]; then
    true
else
    false
fi
