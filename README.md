# PURPOSE

This program has been a project of mine for quite a while. There's a billion password managers out there, a ton of cipher algorithms, but I just wanted to take a crack at writing code for one of my own just for practice. It also gave me the opportunity to study more about cryptography, and learn how to design and describe a cipher in proper terms. I also made sure it used cascaded encryption so that I did not have to rely on the strength of my own cipher design.

Packaging it as I have was mostly used for the experience of learning how to use autotools, and to practice thoroughly documenting a piece of software throughout development. Mostly the intent in sharing it would be to learn from others about what mistakes I've made and what I could do better. I have little illusion that there is practical reason for anyone to adopt this password manager over much more tried and true options, and I don't ecourage it. I use it myself simply because its my own creation, and for that reason I've endured to make it as securely functioning as I can as if it were to be used/developed by others.

One major coding challenge for me has been to design the program to work solely in memory, instead of temporary files. I used that shortcoming as rationale to leave my steam cipher in the program (to encrypt the temp files), so I would also have an excuse for describing and specifying it. Ultimately, aside from the learning opportunity that provided, a long-term goal may be to remove the stream cipher from the program and have it operate solely in memory, and with only provenly strong encryption algorithms.

However, since the program uses cascaded encryption (cascaded stream ciphers) to further encrypt my stream cipher using OpenSSL's crypto libraries, the program is in a mature enough point of development that it is fully functioning and secure enough for actual use. It seemed like a reasonable starting point to let other eyes see it.

# DESCRIPTION
passmanager is an ultra simple, but very secure password management program written in C and making use of OpenSSL's Libcrypto API libraries. The passwords can be written, read, updated or deleted from an encrypted database file.

New passwords can be randomly generated when creating or updating account credentials. Passwords can be matched by entry name, and printed/updated/deleted in bulk or individually. All password entries in the database can be updated at once with ease. If the user updated/deleted a password they didn't intend to, the program lists which entries were matched and edited, and provides an automatically produced backup file to restore from. The database password and encryption method can be changed at any time.

The program pays special attention to minimize the amount user passwords are displayed on screen or stored in memory, and allows them to be sent directly to the clipboard (via xclip). Allowing the passwords to be sent directly to the clipboard means adding, updating or retrieving a password can be done without it ever being visible on the screen. Even if a user must display an entry's password to verify it, only that pass can be printed, in order to prevent the entire database being displayed on screen. Authenticated encryption protects the database against both data corruption and tampering.

Account credentials are stored with cascading encryption. First the YAXA stream cipher is used, and then the YAXA data is further encrypted using OpenSSL's EVP routines. Using OpenSSL's EVP functions also enables the use of any encryption and digest algorithm supported by the EVP interface. For example, encryption can be done with blowfish, and the KDF can use the whirlpool digest algorithm. The default algorithm to use is 256-bit AES in CTR mode.

User input is stored in 512 byte buffers padded by cryptographically strong pseudorandom data: One for an entry's name, and the other for that entry's password. This allows very large passwords, as well as long and flexible entry names, which can be comprised of service names and account names, and are best delimited with a colon. The program will print out each buffer delimited as a colon as well, in a list of "entry name : entry pass" format. The format of "entry name" is up to the user.

For example, here the user manually delimits the service and the account name

service : account : password 

foobar : foo : passfoo 

gmail : account@gmail.com : (*&*UJD83dh

But any of these are also possible

just a user account : password 

foo - bar : foobar : foobar 

555 867 5309 : (*&*UJD83dh

With this format and the modes provided, the user can easily and securely manage the contents of the database.


# DEPENDENCIES

OpenSSL developement files

xclip (optional, for clipboard functions)

# INSTALL

This archive is an automake package with full documentation, example files and a cipher checking script.

To install, run these commands from the current working directory:

$ ./configure

$ make

$ make install

# COMPILATION

If you don't want to install the automake package contents, and want to compile the binary alone, just link with lcrypto

gcc passmanager.c -o passmanager -lcrypto

# DOCUMENTATION

Full and thorugh documentation is given via manual file in man/passmanager.1 or by running 'man passmanger' after installation.

# SCRIPTS AND EXAMPLES

A cript to check that all OpenSSL ciphers functino correctly is available at /usr/local/bin/ciphercheck.sh after installation.

An example password database, encrypted with the password 'password' is available at /usr/local/share/doc/passmanager/examplepasswords1.dat.

