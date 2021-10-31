#!/bin/bash

mkdir cmake-build-debug cmake-build-release

cd cmake-build-debug
cmake -DCMAKE_BUILD_TYPE=Debug ../
make

cd ../cmake-build-release
cmake -DCMAKE_BUILD_TYPE=Release ../
make

cd ..
