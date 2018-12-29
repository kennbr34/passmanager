This program has been a project of mine for quite a while.  There's a billion password managers out there, a ton of cipher algorithms,
but I just wanted to take a crack at writing code for one of my own just for practice.  It also gave me the opportunity to study
more about cryptography, and learn how to design and describe a cipher in proper terms.  I also made sure it used cascaded encryption
so that I did not have to rely on the strength of my own cipher design.

Packaging it as I have was mostly used for the experience of learning how to use autotools, and to practice thoroughly documenting
a piece of software throughout development. Mostly the intent in sharing it would be to learn from others about what mistakes I've 
made and what I could do better.  I have little illusion that there is practical reason for anyone to adopt this password manager
over much more tried and true options, and I don't ecourage it.  I use it myself simply because its my own creation, and for
that reason I've endured to make it as securely functioning as I can as if it were to be used/developed by others.

One major coding challenge for me has been to design the program to work solely in memory, instead of temporary files. I used 
that shortcoming as rationale to leave my steam cipher in the program (to encrypt the temp files), so I would also have an excuse 
for describing and specifying it.  Ultimately, aside from the learning opportunity that provided, a long-term goal may be to remove 
the stream cipher from the program and have it operate solely in memory, and with only provenly strong encryption algorithms.

However, since the program uses cascaded encryption (cascaded stream ciphers) to further encrypt my stream cipher using 
OpenSSL's crypto libraries, the program is in a mature enough point of development that it is fully functioning and secure
enough for actual use. It seemed like a reasonable starting point to let other eyes see it.

DEPENDENCIES

OpenSSL developement files
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

Full and thorugh documentation is given via manual file in man/passmanager.1 or by running 'man passmanger' after installation.

SCRIPTS AND EXAMPLES

A cript to check that all OpenSSL ciphers functino correctly is available at /usr/local/bin/ciphercheck.sh after installation.

An example password database, encrypted with the password 'password' is available at /usr/local/share/doc/passmanager/examplepasswords1.dat.
