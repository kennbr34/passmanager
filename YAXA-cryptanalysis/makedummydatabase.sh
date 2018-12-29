#!/bin/bash

rm ./mockfile
./mockfilegenerator.sh ./mockfile $1
./yaxafileutil -e ./mockfile ./mockfile.enc pass
