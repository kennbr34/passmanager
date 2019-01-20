This password manager has been my project to learn to code with. I tried to make the interface as simple as possible, and focused more on security and simplicity. The end result is a password manager that modifies and displays an encrypted password database as if it were parsing a simple text file, with a couple bells and whistles like a password generator and automated clipboard loading/clearing. 

The bulk of the program is under the hood, because ir pays special attention to security. Care is taken to not display more passwords on screen at one time than needed (if not able to to use clipboard) and sensitive information is cleared from memory. Cascaded and authenticated encryption is used through OpenSSL libraries. with the default configuration encrypting  first into Camellia-256-OFB, and then encrypting that ciper-text with AES-256-CTR.

Thorough documentation on design and use was also added via manual file, in addition to a webpage clone of said manual file. The source itself is thoroughly commented, and autotools was used to handle installation of this documentation, compiling and installing the binary, and providing a demo script showing off the program's use and features.

# PLATFORMS

~The program utilizes OpenSSL and libcap and should work on any Linux.~

The BSD port of this program does not employ any memory locking, core dump prevention, or ptrace protection like the Linux version does, so it only needs OpenSSL.

Confirmed Operational On:

GhostBSD 18.02

Semi-Operational On:

OpenBSD 6.4 (Updating database encryption or password does not work)

# DEPENDENCIES

OpenSSL development files (1.0.1.g or higher)

xclip (optional for clipboard functions)

# INSTALL

This archive is an automake package.

To install, run these commands from the current working directory:

$ ./configure\
$ make\
\# make install

# COMPILATION

If you don't want to install the automake package contents, and want to compile the binary alone, just link with lcrypto

gcc passmanager.c -o passmanager -lcrypto -lcap

Special Note: I would advise against using optimization, because the functions which are used to clear memory of sensitive data may be optimized out.

# DOCUMENTATION

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

There is also an accompanying manual file at 'man/passmanager.1' or installed to the system after 'make install'

# SCRIPTS AND EXAMPLES

A script to demonstrate and test the progarm is available at 'scripts/demofunctions.sh'. It will create an fake database file, encrypting it with the password 'password' and save it to 'scripts/examplepasswords1.dat'  It can be ran after 'make'
