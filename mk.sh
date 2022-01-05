#!/bin/bash


mkdir test
cd test
cmake ../
num=$(cat /proc/cpuinfo  | grep process | wc -l)
make -j${num}
cp ssl-client ../
cp ssl-server ../
cp dtls-server ../
cp dtls-client ../
cp dtls-libevent-server ../
cp dtls-libuv-server ../
cp mbed-libuv/dtls-mbed-server ../
cp mbed-libuv/dtls-mbed-client ../
cd -