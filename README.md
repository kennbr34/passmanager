This program has been a project of mine for quite a while.  There's a billion password managers out there, a ton of cipher algorithms,
but I just wanted to take a crack at writing code for one of my own just for practice.

Packaging it as I have was mostly used for the experience of learning how to use autotools, and to practice thoroughly documenting
a piece of software throughout development. Mostly the intent in sharing it would be to learn from others about what mistakes I've 
made and what I could do better.  I have little illusion that there is practical reason for anyone to adopt this password manager
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

Special Note: I would advice against using optimization, because the functions which are used to clear memory of sensitive data may be optimized out.

# DOCUMENTATION

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

There is also an accompanying manual file at 'man/passmanager.1' or installed to the system after 'make install'

# SCRIPTS AND EXAMPLES

A script to demonstrate and test the progarm is available at 'scripts/demofunctions.sh'. It will create an fake database file, encrypting it with the password 'password' and save it to 'scripts/examplepasswords1.dat'  It can be ran after 'make'

# TODO

* Get gcm/ccm modes working:

A lot of the authentication with HMAC can be done with much more streamlined operations if OpenSSL's GCM implementation is used.

* Perform authentication on both algorithms in cascade, instead of just the 1st:

A blog post by Matthew Green suggests that using authentication on the 1st algorithm alone makes it possible for the 2nd algorithm's cipher-text to be "beiningly malleable". He suggests that most changes to cipher-text should be detected, but that padding used in modes like CBC could be changed.
https://blog.cryptographyengineering.com/2012/02/02/multiple-encryption/

* Cleanup source

A lot of artifacts of the original design have carried over, like using fopen and chmod instead of just one open call.  Otherwise, there's probably more comments than need to be there, and they haven't been kept as updated as the surrounding source. I should also find a cleaner way to access buffers and variables from one function's scope to another besides declaring them globablly; for some reason nobody likes reading that.  Honestly, there's probably a lot more "WTFs" per minute than I am aware of.
