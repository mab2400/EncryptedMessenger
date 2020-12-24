#!/bin/bash

cd users/$1
# Writes the password into a textfile within the username directory
echo "${2}" > password.txt
