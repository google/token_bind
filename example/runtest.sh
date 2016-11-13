#!/bin/bash
echo "removing old key_vault and cookie_jar"
rm -f ./key_vault ./cookie_jar
./server &
serverPID=$!
echo "Started server"
./client get https://localhost:40000
echo "************************This should have redirected us to /login"
./client get https://localhost:40000/login
echo "************************This should have shown us the login form"
./client post https://localhost:40000/login "user=john&pw=password"
echo "************************This should have submitted our login form and redirected us to /user, while setting a bound auth cookie"
./client get https://localhost:40000/user
echo "************************This should have shown us the user page"
kill $serverPID
if [ "`grep auth cookie_jar`" == "" ]; then
    echo "TEST FAILED"
else
    echo "TEST PASSED"
fi
