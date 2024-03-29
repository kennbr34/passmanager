#!/bin/bash

echo "Make a fake password file... (Press enter)"
read
echo ./makefakepassfile.sh
./makefakepassfile.sh
echo -e "\nRead the password file just created... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nUpdate all passwords in the database... (Press enter)"
read
echo passmanager -u allpasses -p gen -f ./examplepasswords1.dat -x password
passmanager -u allpasses -p gen -f ./examplepasswords1.dat -x password
echo -e "\nDisplay updated passwords... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nDelete all password entries beignning with 'name'... (Press enter)"
read
echo passmanager -d name -f ./examplepasswords1.dat -x password
passmanager -d name -f ./examplepasswords1.dat -x password
echo -e "\nDisplay changes made... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nNow try changing the password. You will be prompted for the current and new password... (Press enter)"
read
echo passmanager -U -f ./examplepasswords1.dat
passmanager -U -f ./examplepasswords1.dat
echo -e "\nNow read the database with the password you just changed to... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat
passmanager -r allpasses -f ./examplepasswords1.dat
echo -e "\nNow try changing the encryption to blowfish in OFB mode and the scrypt N factor to 16384... (Press enter)"
read
echo passmanager -U -c bf-ofb -w 16384,8,1 -f ./examplepasswords1.dat
passmanager -U -c bf-ofb -w 16384,8,1 -f ./examplepasswords1.dat
echo -e "\nRead the password database to confirm change... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat
passmanager -r allpasses -f ./examplepasswords1.dat
echo -e "\nNow view database information... (Press enter)"
read
echo passmanager -I -f ./examplepasswords1.dat
passmanager -I -f ./examplepasswords1.dat
echo -e "\nNow change the password back to 'password', the encryption back to AES in CTR mode, and scrypt N factor back to 1024 when prompted... (Press enter)"
read
echo passmanager -U -c aes-256-ctr -w 1024,8,1 -P -f ./examplepasswords1.dat
passmanager -U -c aes-256-ctr -w 1024,8,1 -P -f ./examplepasswords1.dat
echo -e "\nNow view database information again... (Press enter)"
read
echo passmanager -I -f ./examplepasswords1.dat
passmanager -I -f ./examplepasswords1.dat
echo -e "\nNow read the database to confirm... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nNow add a new entry 'name' to the database with a random password and send the password to the clipboard, and clear the clipboard after 5 seconds... (Press enter)"
read
echo passmanager -a name -p gen -f ./examplepasswords1.dat -x password -C -t 5s
passmanager -a name -p gen -f ./examplepasswords1.dat -x password -C -t 5s
echo -e "\nGo ahead and middle-click your mouse, and the password will be displayed.  Wait 5 seconds and try it again, and it should be cleared..."
read
echo -e "Now read that pass from the database and send it to the clipboard... (Press enter)"
read
echo passmanager -r name -f ./examplepasswords1.dat -x password -C -t 5s
passmanager -r name -f ./examplepasswords1.dat -x password -C -t 5s
echo -e "\nCheck it is read and erased with middle-click..."
read
echo -e "Now let's display it... (Press enter)"
read
echo passmanager -r name -f ./examplepasswords1.dat -x password
passmanager -r name -f ./examplepasswords1.dat -x password
echo -e "\nNotice that when updating passwords, if a password is alphanumeric, it is kept alphanumeric"
echo -e "Display the password database... (Press enter)"
read
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nNow update them all... (Press enter)"
read
passmanager -u allpasses -p gen -f ./examplepasswords1.dat -x password
echo -e "\nDiplay them, and notice how passwords with no symbols before still have no symbols now... (Press enter)"
read
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nUpdate the entry 'name' to have a alphanumeric password... (Press enter)"
read
echo passmanager -u name -p genalpha -f ./examplepasswords1.dat -x password
passmanager -u name -p genalpha -f ./examplepasswords1.dat -x password
echo -e "\nDisplay the new pass... (Press enter)"
read
echo passmanager -r name -f ./examplepasswords1.dat -x password
passmanager -r name -f ./examplepasswords1.dat -x password
echo -e "\nOf course things might not always go right. Lets try with the wrong password... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password1
passmanager -r allpasses -f ./examplepasswords1.dat -x password1
echo passmanager -u allpasses -p gen -f ./examplepasswords1.dat -x password1
passmanager -u allpasses -p gen -f ./examplepasswords1.dat -x password1
echo passmanager -d name -f ./examplepasswords1.dat -x password1
passmanager -d name -f ./examplepasswords1.dat -x password1
echo passmanager -U -c bf-ofb -f ./examplepasswords1.dat -x password1
passmanager -U -c bf-ofb -f ./examplepasswords1.dat -x password1
echo -e "\nNow let's imagine the database has been corrupted for some reason... (Press enter)"
read
echo ./ciphertextmodification.sh ./examplepasswords1.dat ./examplepasswords1.dat.forged
./ciphertextmodification.sh ./examplepasswords1.dat ./examplepasswords1.dat.forged
echo -e "\nNow try to read the database.. (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat.forged -x password
passmanager -r allpasses -f ./examplepasswords1.dat.forged -x password
echo -e "\nNow what if we modified the ciphertext and forged the checksum to match it... (Press enter)"
read
echo ./ciphertextforgery.sh ./examplepasswords1.dat ./examplepasswords1.dat.forged
./ciphertextforgery.sh ./examplepasswords1.dat ./examplepasswords1.dat.forged
echo -e "\nNow try to read the database... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat.forged -x password
passmanager -r allpasses -f ./examplepasswords1.dat.forged -x password
echo -e "\nThese are all the program's basic functions and operations.\n"
