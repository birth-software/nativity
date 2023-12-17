#!/usr/bin/env bash

echo -e "\e[90mCompiling Nativity with Zig...\e[0m"
nativity_use_llvm=true
zig build -Duse_llvm=$nativity_use_llvm
failed_test_count=0
passed_test_count=0
test_directory_name=test
standalone_test_directory=$test_directory_name/standalone
standalone_test_directory_files=$standalone_test_directory/*
integral_test_directory=$test_directory_name/integral
integral_test_directory_files=$integral_test_directory/*
standalone_test_count=$(ls 2>/dev/null -Ubad1 -- $standalone_test_directory/* | wc -l)
integral_test_count=$(ls 2>/dev/null -Ubad1 -- $integral_test_directory/* | wc -l)
total_test_count=$(($standalone_test_count + $integral_test_count))

ran_test_count=0
test_i=1
passed_compilation_count=0
failed_compilation_count=0
failed_compilations=()
failed_tests=()
my_current_directory=$(pwd)
nat_compiler=$my_current_directory/zig-out/bin/nat

for standalone_test_case in $standalone_test_directory_files
do
    STANDALONE_TEST_NAME=${standalone_test_case##*/}
    $nat_compiler $standalone_test_case/main.nat

    if [[ "$?" == "0" ]]; then
        passed_compilation_count=$(($passed_compilation_count + 1))
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            nat/$STANDALONE_TEST_NAME

            if [[ "$?" == "0" ]]; then
                passed_test_count=$(($passed_test_count + 1))
                result="\e[32mPASSED\e[0m"
            else
                failed_test_count=$(($failed_test_count + 1))
                result="\e[31mFAILED\e[0m"
                failed_tests+=("$test_i. $STANDALONE_TEST_NAME")
            fi

            ran_test_count=$(($ran_test_count + 1))
        else
            result="\e[31mOS NOT SUPPORTED\e[0m"
        fi
    else
        failed_compilation_count=$(($failed_compilation_count + 1))
        result="\e[31mCOMPILATION FAILURE\e[0m"
        failed_compilations+=("$test_i. $STANDALONE_TEST_NAME")
    fi

    echo -e "[$test_i/$total_test_count] [$result] $STANDALONE_TEST_NAME"

    test_i=$(($test_i + 1))
done

for integral_test_case in $integral_test_directory_files
do
    MY_TESTNAME=${integral_test_case##*/}
    cd test/integral/$MY_TESTNAME
    $nat_compiler

    if [[ "$?" == "0" ]]; then
        passed_compilation_count=$(($passed_compilation_count + 1))
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            nat/src

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
    cd $my_current_directory
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
