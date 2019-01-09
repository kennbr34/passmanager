This program has been a project of mine for quite a while.  There's a billion password managers out there, a ton of cipher algorithms,
but I just wanted to take a crack at writing code for one of my own just for practice.

Packaging it as I have was mostly used for the experience of learning how to use autotools, and to practice thoroughly documenting
a piece of software throughout development. Mostly the intent in sharing it would be to learn from others about what mistakes I've 
made and what I could do better.  

I have little illusion that there is practical reason for anyone to adopt this password manager
over much more tried and true options, and I don't ecourage it.  I use it myself simply because its my own creation, and for
that reason I've tried to make it as securely functioning and user friendly as I can, as if it were to be used/developed by others.

# DEPENDENCIES

OpenSSL development files (1.0.1.g or higher)

xclip (optional for clipboard functions)

# INSTALL

This archive is an automake package.

To install, run these commands from the current working directory:

$ ./configure

$ make

\# make install

# COMPILATION

If you don't want to install the automake package contents, and want to compile the binary alone, just link with lcrypto

gcc passmanager.c -o passmanager -lcrypto

Special Note: I would advise against using optimization, because the functions which are used to clear memory of sensitive data may be optimized out.

# DOCUMENTATION

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

There is also an accompanying manual file at 'man/passmanager.1' or installed to the system after 'make install'

# SCRIPTS AND EXAMPLES

A script to demonstrate and test the progarm is available at 'scripts/demofunctions.sh'. It will create an fake database file, encrypting it with the password 'password' and save it to 'scripts/examplepasswords1.dat'  It can be ran after 'make'

# DEVELOPMENT GOALS

* Create a branch using GCM:

A lot of the authentication with HMAC can be done with much more streamlined operations if OpenSSL's GCM implementation is used.  AES-GCM is the fist standardized NIST Authenticated Encryption algorithm and likely to see more development via the OpenSSL team and would greatly simplify the program.
