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

# DEPENDENCIES

OpenSSL (1.0.1.g or higher) developement files

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

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

# SCRIPTS AND EXAMPLES

A cript to check that all OpenSSL ciphers functino correctly is available at /usr/local/bin/ciphercheck.sh after installation.

An example password database, encrypted with the password 'password' is available at /usr/local/share/doc/passmanager/examplepasswords1.dat.

# TODO

* MAC nonce along with hmac key for MAC-and-encrypt:

Some literature suggests that best practice is to authenticate things like nonces and salts along with the plain-text.

* Stop gcc optimizing away memset:

Sensitive information like plain-text buffers and user-inputted information was thought to be cleared out of memory by memset.

Because gcc will optimize memset lines away, this is not the case, and a new way to sanitize the memory that held this sensitive
information is needed.

* Change '-c' option to take two cipher names delimited with a colon so both algoritms in the cascade can be selected:

Right now camellia-256-ofb is the default 1st algorithm in the cascade, and only the 2nd algorithm can be selected by the user.

Allowing the cryptoHeader to have two OpenSSL algorithm names delimited by a colon would easily allow both ciphers to be selected
while still requiring only the option '-c'.  Example, Camellia-256-OFB cascaded into AES-256-CTR would 
be camellia-256-ofb:digest:aes-256-ctr:digest in the cryptoHeader.

* Get gcm/ccm modes working:

A lot of the authentication with HMAC can be done with much more streamlined operations if OpenSSL's GCM implementation is used.


* Modify openEnvelope/sealEnvelope to perform HMAC on EVP1 cipher-text in MAC-then-encrypt style:

A blog post by Matthew Green suggests that best practice for cascaded/combined encryption with authentication is to use
authentication on both ciphers, and not just one.
https://blog.cryptographyengineering.com/2012/02/02/multiple-encryption/

