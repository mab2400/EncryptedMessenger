#!/bin/bash

rm -rf certs
rm -rf users

#make clean
#make

mkdir users
cd users
# TODO: make all of the user directories

input="../users.txt"
while IFS= read -r line
do 
    l=($line)
    user=${l[0]}
    mkdir $user
    cd $user
    password=${l[2]}
    echo $password > password.txt
    cd ..
done < "$input"

cd ..

#./gen-ca-certs.sh
#./gen-server-cert.sh
#valgrind ./server
