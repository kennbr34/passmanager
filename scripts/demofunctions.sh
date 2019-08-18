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
echo -e "\nNow try changing the password. You will be prompted for the current and new password"
echo passmanager -U -f ./examplepasswords1.dat
passmanager -U -f ./examplepasswords1.dat
echo -e "\nNow read the database with the password you just changed to"
echo passmanager -r allpasses -f ./examplepasswords1.dat
passmanager -r allpasses -f ./examplepasswords1.dat
echo -e "\nNow try changing the encryption to bf-ofb:bf-ofb and whirlpool:sha512"
echo passmanager -U -c bf-ofb -H whirlpool -f ./examplepasswords1.dat
passmanager -U -c bf-ofb -H whirlpool -f ./examplepasswords1.dat
echo -e "\nRead the password database to confirm change... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat
passmanager -r allpasses -f ./examplepasswords1.dat
echo -e "\nNow change the password back to 'password' when prompted"
echo passmanager -U -c aes-256-ctr -H sha512 -P -f ./examplepasswords1.dat
passmanager -U -c aes-256-ctr -H sha512 -P -f ./examplepasswords1.dat
echo -e "\nNow read the database to confirm... (Press enter)"
read
echo passmanager -r allpasses -f ./examplepasswords1.dat -x password
passmanager -r allpasses -f ./examplepasswords1.dat -x password
echo -e "\nNow add a new entry 'name' to the database with a random password and send the password to the clipboard, and clear the clipboard after 5 seconds... (Press enter)"
read
echo passmanager -a name -p gen -f ./examplepasswords1.dat -x password -C -s 5
passmanager -a name -p gen -f ./examplepasswords1.dat -x password -C -s 5
echo -e "\nGo ahead and middle-click your mouse, and the password will be displayed.  Wait 5 seconds and try it again, and it should be cleared..."
read
echo -e "Now read that pass from the database and send it to the clipboard... (Press enter)"
read
echo passmanager -r name -f ./examplepasswords1.dat -x password -C -s 5
passmanager -r name -f ./examplepasswords1.dat -x password -C -s 5
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
echo -e "\nNow imagine you started to update the database encryption, but didn't like the options you entered press Ctrl=C when prompted for the password... (Press enter)"
read
echo passmanager -U -c foocipher-f ./examplepasswords1.dat
passmanager -U -c foocipher -f ./examplepasswords1.dat
