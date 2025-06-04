#!/bin/bash

set -ex

if ! [ -d "util" -a -d "pres" -a -d "acse" -a -d "mms" ];
then
    echo "directories missing";
    exit 1;
fi;

cd pres/plugin/src/asn1c
asn1c -fcompound-names ../../../../util/pres.asn
sed -i 's/void (\*free)(type \*);/void (*free)(void *);/' asn_SET_OF.h
sed -i 's/_BSD_SOURCE/_DEFAULT_SOURCE/g' asn_system.h 
mv converter-sample.c ../../../testing/Files/asn1c-test.c
rm Makefile.am.sample
cd -

python3 util/gen.py hpp PRES zeek::plugin::pres util/pres.asn | clang-format > pres/plugin/src/process.h
python3 util/gen.py cpp PRES zeek::plugin::pres util/pres.asn | clang-format > pres/plugin/src/process.cc
python3 util/gen.py zeek PRES util/pres.asn > pres/plugin/scripts/types.zeek


cd acse/plugin/src/asn1c
asn1c -fcompound-names ../../../../util/acse.asn
sed -i 's/void (\*free)(type \*);/void (*free)(void *);/' asn_SET_OF.h
sed -i 's/_BSD_SOURCE/_DEFAULT_SOURCE/g' asn_system.h 
mv converter-sample.c ../../../testing/Files/asn1c-test.c
rm Makefile.am.sample
cd -

python3 util/gen.py hpp ACSE zeek::plugin::ACSE util/acse.asn | clang-format > acse/plugin/src/process.h
python3 util/gen.py cpp ACSE zeek::plugin::ACSE util/acse.asn | clang-format > acse/plugin/src/process.cc
python3 util/gen.py zeek ACSE util/acse.asn > acse/plugin/scripts/types.zeek

cd mms/plugin/src/asn1c
asn1c -fcompound-names ../../../../util/mms-simple.asn
sed -i 's/void (\*free)(type \*);/void (*free)(void *);/' asn_SET_OF.h
sed -i 's/_BSD_SOURCE/_DEFAULT_SOURCE/g' asn_system.h 
mv converter-sample.c ../../../testing/Files/asn1c-test.c
rm Makefile.am.sample
cd -

python3 util/gen.py hpp MMS zeek::plugin::MMS util/mms-simple.asn | clang-format > mms/plugin/src/process.h
python3 util/gen.py cpp MMS zeek::plugin::MMS util/mms-simple.asn | clang-format > mms/plugin/src/process.cc
python3 util/gen.py zeek MMS util/mms-simple.asn > mms/plugin/scripts/types.zeek
