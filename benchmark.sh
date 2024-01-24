#!/bin/bash
# These are benchmarks with added blocks
# TEST_NAME="PermRead64SimpleLoop"
# ./pmbw -o "${TEST_NAME}_results_2.txt" -f ${TEST_NAME}
#
# These are benchmarks with added one more block and changed the bandwidth calc
# Also focusing only on the larger buffer sizes and one thread
TEST_NAME="PermRead64SimpleLoop"
./pmbw -o "${TEST_NAME}_results_3.txt" -f ${TEST_NAME} -s $((2**19)) -P 1
