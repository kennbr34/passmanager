#!/bin/bash

dd if=/dev/urandom of=urandombytes bs=1M count=$1
./freqan ./urandombytes | sort
./freqan ./mockfile.enc | sort
dieharder -d 102 -g 201 -f ./urandombytes
dieharder -d 102 -g 201 -f ./mockfile.enc
