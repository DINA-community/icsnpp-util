#!/bin/bash

set -ex

for dir in util pres acse mms; do
    if ! [[ -d "$dir" ]]; then
        echo "directory $dir missing"
        exit 1
    fi
done

NAMES=(     "pres"                           "acse"                           "mms")
ASN_PATHS=( "util/pres.asn"                  "util/acse.asn"                  "util/mms-simple.asn")
PLUGINS=(   "zeek::plugin::pres"             "zeek::plugin::ACSE"             "zeek::plugin::MMS")
ASN_DIRS=(  "pres/plugin/src/asn1c"          "acse/plugin/src/asn1c"          "mms/plugin/src/asn1c")
PROCESS_H=( "pres/plugin/src/process.h"      "acse/plugin/src/process.h"      "mms/plugin/src/process.h")
PROCESS_CC=("pres/plugin/src/process.cc"     "acse/plugin/src/process.cc"     "mms/plugin/src/process.cc")
TYPES_ZEEK=("pres/plugin/scripts/types.zeek" "acse/plugin/scripts/types.zeek" "mms/plugin/scripts/types.zeek")

for i in "${!NAMES[@]}"; do
    name=${NAMES[$i]}
    asn=${ASN_PATHS[$i]}
    plugin=${PLUGINS[$i]}
    asn_dir=${ASN_DIRS[$i]}
    proc_h=${PROCESS_H[$i]}
    proc_cc=${PROCESS_CC[$i]}
    types_zeek=${TYPES_ZEEK[$i]}

    pushd "$asn_dir"
    asn1c -fcompound-names $(realpath "../../../../$asn")
    sed -i 's/void (\*free)(type \*);/void (*free)(void *);/' asn_SET_OF.h
    sed -i 's/_BSD_SOURCE/_DEFAULT_SOURCE/g' asn_system.h 
    mv converter-sample.c ../../../testing/Files/asn1c-test.c
    rm Makefile.am.sample
    popd

    python3 util/gen.py hpp "${name^^}" "$plugin" "$asn" | clang-format > "$proc_h"
    python3 util/gen.py cpp "${name^^}" "$plugin" "$asn" | clang-format > "$proc_cc"
    python3 util/gen.py zeek "${name^^}" "$asn" > "$types_zeek"
done
