#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

CSV_TOOL=$SCRIPT_DIR/csv_multitool.py
SYSCALL_TOOL=$SCRIPT_DIR/syscall_signature_debian.py

OUT_GEN_DIR=$SCRIPT_DIR/gen
mkdir -p $OUT_GEN_DIR

OUT_SYSCALL_NAME=$OUT_GEN_DIR/syscall_names.h
OUT_SYSCALL_NUM_PARAMS=$OUT_GEN_DIR/syscall_num_params.h

$SYSCALL_TOOL list --fmt number num_params | $CSV_TOOL toc -p /dev/stdin -c -a syscall_num_params > $OUT_SYSCALL_NUM_PARAMS
$SYSCALL_TOOL list --fmt name   number     | $CSV_TOOL toc -p /dev/stdin -c -a syscall_names      > $OUT_SYSCALL_NAME


