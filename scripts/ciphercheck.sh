#!/bin/bash

rm ./testfile 2> /dev/null

passmanager -a entry -p password -f ./testfile -x 123

cat /usr/local/share/doc/passmanager/working-ciphers | sed "s/Cipher: //g" | sed "s/des-ede3-cfb1//g"| grep -ve "[[:upper:]]" | while read cipher ;
do
	passmanager -H list | sed "s/Digest: //g" | grep -ve "[[:upper:]]" | while read digest
	do
		passmanager -U -c $cipher -H $digest -f ./testfile -x 123 && passmanager -r allpasses -f ./testfile -x 123 ;
		if [ $? != 0 ] ; then
			echo "Failure!"
			rm ./testfile
			passmanager -a entry -p password -f ./testfile -x 123
			echo $cipher >> ./badciphers
		fi
	done
done
