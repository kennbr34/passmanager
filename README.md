This program has been a project of mine for quite a while.  There's a billion password managers out there, a ton of cipher algorithms,
but I just wanted to take a crack at writing code for one of my own just for practice.

Packaging it as I have was mostly used for the experience of learning how to use autotools, and to practice thoroughly documenting
a piece of software throughout development. Mostly the intent in sharing it would be to learn from others about what mistakes I've 
made and what I could do better.  I have little illusion that there is practical reason for anyone to adopt this password manager
over much more tried and true options, and I don't ecourage it.  I use it myself simply because its my own creation, and for
that reason I've endured to make it as securely functioning as I can as if it were to be used/developed by others.

One major coding challenge for me has been to design the program to work solely in memory, instead of temporary files. I used 
that shortcoming as rationale to leave my steam cipher in the program (to encrypt the temp files), so I would also have an excuse 
for describing and specifying it. Once I was satisfied with that, I removed my custom crypto from the program, and relied on 
OpenSSL's libraries instead.

DEPENDENCIES

OpenSSL (1.0.1.g or higher) developement files

xclip (optional, for clipboard functions)

INSTALL

This archive is an automake package with full documentation, example files and a cipher checking script.

To install, run these commands from the current working directory:

$ ./configure

$ make

$ make install

COMPILATION

If you don't want to install the automake package contents, and want to compile the binary alone, just link with lcrypto

gcc passmanager.c -o passmanager -lcrypto

DOCUMENTATION

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

SCRIPTS AND EXAMPLES

A cript to check that all OpenSSL ciphers functino correctly is available at /usr/local/bin/ciphercheck.sh after installation.

An example password database, encrypted with the password 'password' is available at /usr/local/share/doc/passmanager/examplepasswords1.dat.
