#!/bin/bash

make clean
make

valgrind ./getcert localhost addleness Cardin_pwns
