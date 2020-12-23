#!/bin/bash

cd users
echo "$3"

# If getcert, then creates the username directory inside of users
if [ "$3" = "1" ]
then 
    mkdir $1 
fi

cd $1 

# Writes the password into a textfile within the username directory
echo "${2}" > password.txt
