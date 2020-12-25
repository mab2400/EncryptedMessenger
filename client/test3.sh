#!/bin/bash

./clean.sh

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

echo "Hi there!" > hi.txt

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed
