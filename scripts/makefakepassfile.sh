

#!/bin/bash

i=0 ; while [ $i -le 5 ] ; do passmanager -a "name$i : $(shuf -n 1 /usr/share/dict/words | sed s/\'//g)" -p gen -f ./examplepasswords1.dat -x password -i 1; let i=i+1; done
i=0 ; while [ $i -le 5 ] ; do passmanager -a "$(shuf -n 1 /usr/share/dict/words | tr [:upper:] [:lower:] | sed s/\'//g).com : $(shuf -n 1 /usr/share/dict/words | tr [:upper:] [:lower:] | sed s/\'//g)" -p "$(if [ $(echo $RANDOM | cut -b 1) -ge 5 ] ; then echo gen ; else echo genalpha ; fi)" -f ./examplepasswords1.dat -x password -i 1; let i=i+1; done
