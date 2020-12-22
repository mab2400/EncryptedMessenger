#!/bin/bash

make clean
make

valgrind ./getcert user pass
