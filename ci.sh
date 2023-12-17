#!/usr/bin/env bash

echo -e "\e[90mCompiling Nativity with Zig...\e[0m"
nativity_use_llvm=true
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
    zig build run -Duse_llvm=$nativity_use_llvm -- $dir/main.nat

    if [[ "$?" == "0" ]]; then
        passed_compilation_count=$(($passed_compilation_count + 1))
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            nat/$MY_TESTNAME

            if [[ "$?" == "0" ]]; then
                passed_test_count=$(($passed_test_count + 1))
                result="\e[32mPASSED\e[0m"
            else
                failed_test_count=$(($failed_test_count + 1))
                result="\e[31mFAILED\e[0m"
                failed_tests+=("$test_i. $MY_TESTNAME")
            fi

            ran_test_count=$(($ran_test_count + 1))
        else
            result="\e[31mOS NOT SUPPORTED\e[0m"
        fi
    else
        failed_compilation_count=$(($failed_compilation_count + 1))
        result="\e[31mCOMPILATION FAILURE\e[0m"
        failed_compilations+=("$test_i. $MY_TESTNAME")
    fi

    echo -e "[$test_i/$total_test_count] [$result] $MY_TESTNAME"

    test_i=$(($test_i + 1))
done

printf "\n"
echo -e "\e[35m[SUMMARY]\e[0m"
echo -e "\e[35m=========\e[0m"
echo -e "Ran $total_test_count compilations (\e[32m$passed_compilation_count\e[0m succeeded, \e[31m$failed_compilation_count\e[0m failed)."
echo -e "Ran $ran_test_count tests (\e[32m $passed_test_count\e[0m passed, \e[31m$failed_test_count\e[0m failed)."

if [[ "$failed_compilation_count" != "0" ]]; then
    printf $"\nFailed compilations:\n"
    for failed_compilation in "${failed_compilations[@]}"
    do
        echo -e "\e[31m$failed_compilation\e[0m"
    done
fi


if [[ "$failed_test_count" != "0" ]]; then
    echo $'\n'
    echo "Failed tests:"
    for failed_test in "${failed_tests[@]}"
    do
        echo -e "\e[31m$failed_test\e[0m"
    done
fi

echo -e "\e[35m=========\e[0m"

if [[ "$failed_test_count" == "0" && "$failed_compilation_count" == "0" ]]; then
    echo -e "\e[32mSUCCESS!\e[0m"
    true
else
    echo -e "\e[31mFAILURE!\e[0m"
    false
fi
