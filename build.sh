#!/bin/bash

make clean

./autogen.sh
#./configure --prefix=`pwd`/output/
./configure
make -j 4
sudo make install

