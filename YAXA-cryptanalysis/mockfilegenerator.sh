#!/bin/bash

#This script will create a 140MB file that mimmicks the plain-text of a password database file
#It can be used by yaxafile utility to test password database sizes that would otherwise be impractical to test
#140 MB was chosen because it is the least amount of data need to run dieharder's NIST STS implementation without file rewinds

mockFile="$1"
i=0 ; while [ $i -le $(($2*1024)) ] ; do
word="$(shuf -n 1 /usr/share/dict/words | tr [:upper:] [:lower:] | sed s/\'//g).com"
wordLength="$(echo $word | wc -c)"
pass="$(./mkpasswd -L 8)"
passLength="$(echo $pass | wc -c)"
	echo -n "$word" >> "$mockFile"
	dd if=/dev/urandom bs=1 count=$((512 - $wordLength)) of=./randombytes status=none
	cat ./randombytes >> "$mockFile"
	echo -n "$pass" >> "$mockFile"
	dd if=/dev/urandom bs=1 count=$((512 - $passLength)) of=./randombytes status=none
	cat ./randombytes >> "$mockFile"
	let i=i+1
done
