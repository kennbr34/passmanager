This password manager has been my project of mine to learn to program with, evolving its design over time. I tried to make the interface as simple as possible, and focused more on security and simplicity. The end result is a password manager that modifies and displays an encrypted password database as if it were parsing a simple text file, with a couple bells and whistles like a password generator and automated clipboard loading/clearing. Authenticated encryption is done through OpenSSL libraries, with the default configuration encrypting with AES-256-CTR and using scrypt for key derivation.

Thorough documentation on design and use was also added via manual file, in addition to a webpage clone of said manual file. The source itself is thoroughly commented, and autotools was used to handle installation of this documentation, compiling and installing the binary, and providing a demo script showing off the program's use and features.

# PLATFORMS

The program utilizes OpenSSL and X11 (optional) and should work on any Linux or BSD with those installed

Confirmed Operational On:

* Debian Buster/testing
* Ubuntu (16.04 and 18.04)
* Antegros 18.12
* Manjaro 18.0
* Sabayon 18.05
* Slackware 14.2
* OpenBSD 6.5
* FreeBSD 12
* NetBSD 7

# DEPENDENCIES

OpenSSL development files (1.1.1 or higher)

(Optional)

X11 development files

...or

xsel (to pipe password to)

# INSTALL

This archive is an automake package.

To install, run these commands from the current working directory:

'make install' must be ran as root to install the binary with SUID permission and to install the man file

$ ./configure

$ make

\# make install

If you would rather use xsel for clipboard functions (or to disable them all together if xsel is not installed)...

$ ./configure --disable-x11

$ make

\# make install

# COMPILATION

If you don't want to install the automake package contents, and want to compile the binary alone:

gcc passmanager.c -o passmanager -lcrypto -lX11 -D HAVE_LIBX11

...or if you want to use xsel for clipboard functions, or disable clipboard functions all together...

gcc passmanager.c -o passmanager -lcrypto

Special Note: I would advise against using optimization, because the functions which are used to clear memory of sensitive data may be optimized out.

# DOCUMENTATION

Full and thorugh documentation can be found here:

https://kennbr34.github.io/

There is also an accompanying manual file at 'man/passmanager.1' or installed to the system after 'make install'

# SCRIPTS AND EXAMPLES

A script to demonstrate and test the progarm is available at 'scripts/demofunctions.sh'. It will create a fake database file, encrypting it with the password 'password' and save it to 'scripts/examplepasswords1.dat'  It can be ran after 'make'
(Note: This script will likely not work correclty on any BSD distritbution)
