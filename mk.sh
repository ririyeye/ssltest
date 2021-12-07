#!/bin/bash


mkdir test
cd test
cmake ../
make -j8
cp ssl-client ../
cp ssl-server ../
cd -