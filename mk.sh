#!/bin/bash


mkdir test
cd test
cmake ../
make -j8
cp ssl-client ../
cp ssl-server ../
cp dtls-server ../
cp dtls-client ../
cp dtls-libevent-server ../
cd -