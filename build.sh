#!/bin/bash

make clean

./autogen.sh
./configure --prefix=`pwd`/output/
make -j 3
make install

