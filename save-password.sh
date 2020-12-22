#!/bin/bash

# Takes in username, password, is_getcert
username = $1
password = $2
is_getcert = $3

cd users

# If getcert, then creates the username directory inside of users
if [ is_getcert == 1 ]
then 
    mkdir username 
fi

cd username

# Writes the password into a textfile within the username directory
echo "${password}" > password.txt
