#!/bin/bash

rm -rf certs
rm -rf users

make clean
make

mkdir users
cd users

input="../users.txt"
while IFS= read -r line
do 
    l=($line)
    user=${l[0]}
    mkdir $user
    cd $user
    passhash=${l[1]}
    password=${l[2]}
    echo $passhash > password.txt
    mkdir pending
    cd ..
done < "$input"

cd ..

./gen-ca-certs.sh
./gen-server-cert.sh
valgrind ./server
