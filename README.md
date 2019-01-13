This password manager has been my project to learn to code with. I tried to make the interface as simple as possible, and focused more on security and simplicity. The end result is a password manager that modifies and displays an encrypted password database as if it were parsing a simple text file, with a couple bells and whistles like a password generator and automated clipboard loading/clearing. 

The bulk of the program is under the hood, because ir pays special attention to security. Care is taken to not display more passwords on screen at one time than needed (if not able to to use clipboard) and sensitive information is cleared from memory. Cascaded and authenticated encryption is used through OpenSSL libraries. with the default configuration encrypting  first into Camellia-256-OFB, and then encrypting that ciper-text with AES-256-CTR.

Thorough documentation on design and use was also added via manual file, in addition to a webpage clone of said manual file. The source itself is thoroughly commented, and autotools was used to handle installation of this documentation, compiling and installing the binary, and providing a demo script showing off the program's use and features.

# PLATFORMS

The program utilizes OpenSSL and POSIX compliant functions, so it should work on most unix-like systems

Confirmed Operational On:

Debian Buster/testing

Ubuntu (16.04 and 18.04)

Antegros 18.12

Manjaro 18.0

Sabayon 18.05

Slackware 14.2

openSUSE Leap 15.0

GhostBSD 18.10

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

* Use GCM:

A lot of the authentication with HMAC can be done with much more streamlined operations if OpenSSL's GCM implementation is used.  AES-GCM is the fist standardized NIST Authenticated Encryption algorithm and likely to see more development via the OpenSSL team and would greatly simplify the program.

* Use single encryption with AES:

The cascaded encryption is novel, but mostly a left-over from the original design of the program. Now it just adds unneeded complication.  There's also really not much of a point in being able to select different cipher algorithms.

* Use PBKDF2 or scrypt

The EVP_BytesToKey function from OpenSSL is not reccomended for use over PBKDF2, but handles generating properly sized keys and IVs based on the EVP cipher specified.  It would be best to figure out a way to use PBKDF2, or better yet, scrypt.
