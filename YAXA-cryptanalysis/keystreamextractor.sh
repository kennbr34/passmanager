#!/bin/bash

rm ./mockfile
./mockfilegenerator.sh ./mockfile $1
./yaxafileutil -e ./mockfile ./mockfile.enc
./stripsalt ./mockfile.enc ./mockfile.enc.unsalted 24
./pxorc ./mockfile ./mockfile.enc.unsalted > ./mockfile.keystream
./pxorc ./mockfile.enc.unsalted ./mockfile.keystream > ./mockfile.denc.fromunsalted
md5sum -b ./mockfile ./mockfile.denc.fromunsalted
