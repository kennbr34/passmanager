dd if=/dev/zero of=./zerofile bs=1M count=3
./yaxafileutil -e ./zerofile ./zerofile.keystream pass
./stripsalt ./zerofile.keystream ./zerofile.keystream.stripped 24
dd if=/dev/urandom of=./randomfile bs=1M count=3
./freqan ./randomfile >> keystreamtesting$1.log
./freqan ./zerofile.keystream.stripped | sort >> keystreamtesting$1.log
dieharder -d 102 -g 201 -f ./randomfile  >> keystreamtesting$1.log
dieharder -d 102 -g 201 -f ./zerofile.keystream.stripped >> keystreamtesting$1.log
