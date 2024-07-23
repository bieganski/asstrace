#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SYSCALL_TOOL=$SCRIPT_DIR/syscall_signature_debian.py

OUT_GEN_DIR=$SCRIPT_DIR/gen
OUT_SYSCALL_NAMES_BASENAME=syscall_names
OUT_SYSCALL_NUM_PARAMS_BASENAME=syscall_num_params

TEMP_DIR=`mktemp -d`
mkdir -p $OUT_GEN_DIR

cd $TEMP_DIR

git clone https://github.com/hrw/syscalls-table
pip install ./syscalls-table

from_debian_base=$OUT_GEN_DIR/$OUT_SYSCALL_NUM_PARAMS_BASENAME

# Generate (name,num_params) csv.
$SYSCALL_TOOL list --fmt name num_params > $from_debian_base.csv

for arch in x86_64 riscv64; do
    mkdir -p $OUT_GEN_DIR/$arch
    from_python_base=$OUT_GEN_DIR/$arch/$OUT_SYSCALL_NAMES_BASENAME

    # Generate (name,number) csv
    ./syscalls-table/bin/syscall --dump $arch | awk '{ print $1 "," $2 }' > $from_python_base.csv
done
