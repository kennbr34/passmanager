/* printsyntax.c - prints progra command syntax */

/* Copyright 2020 Kenneth Brown */

/* Licensed under the Apache License, Version 2.0 (the "License"); */
/* you may not use this file except in compliance with the License. */
/* You may obtain a copy of the License at */

/*     http://www.apache.org/licenses/LICENSE-2.0 */

/* Unless required by applicable law or agreed to in writing, software */
/* distributed under the License is distributed on an "AS IS" BASIS, */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and */
/* limitations under the License. */

/*

  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/

#include "headers.h"

int printSyntax(char *arg)
{
    fprintf(stderr, "\
\nReccomend Syntax: \
\n\n%s passmanager  [-E] -a entry name | -r entry name | -d entry name | -u entry name | -U  [-n new name ] [-p new entry password] [-l random password length] [-c cipher] [-w N,r,p ] [ -P ] [-x database password] [ -o | -C ] [ -O ] [ -s selection ] [ -t seconds or miliseconds ] -f database file\
\nOptions: \
\n-n new name - entry name up to 511 characters (can contain white space or special characters) \
\n-p new entry password - entry password up to 511 characters (don't call to be prompted instead) ('gen' will generate a random password, 'genalpha' will generate a random password with no symbols)\
\n-l random password length - makes 'gen' or 'genalpha' generate a password random password length digits long (defaults to 16 without this option) \
\n-c cipher - Specify 'list' for a list of methods available to OpenSSL. Default: aes-256-ctr. \
\n-w N,r,p - Specify scrypt work factors N,r,p (Must be comma separted with no spaces, and N must be a power of 2). Default: 1048576,8,1\
\n-P - In Update entry or Update database mode (-u and -U respectively) this option enables updating the entry password or database password via prompt instead of as command line argument \
\n-o - send entry password directly to standard output. (Mutually exclusive with -C) \
\n-C - send entry password directly to clipboard. Clipboard is cleared automatically after pasting, or in 30 seconds. \
\n-t 'n'ms or 'n's - clear password from clipboard in the specified amount of miliseconds or seconds instead of default 30 seconds. \
\n-O - implies '-t 55ms' to allow only one pasting of pssword before its cleared \
\n-s selection - use either the 'primary' or 'clipboard' X selection. (Defaults to 'primary')\
\n-x database password - To supply database password as command-line argument (not reccomended) \
\n-I - print database information \
\n-f - database file ( must be specified ) \
\n-h - Quick usage help \
\nEach functioning mode has a subset of applicable options \
\n-a - Add mode \
\n     \t-p 'password'\
\n     \t-l 'password length'\
\n     \t-x 'database password'\
\n     \t-c 'cipher' - Initializes a password database with encryption of 'cipher' \
\n     \t-w 'N,r,p' - Specify scrypt work factors. \
\n     \t-C send new entry's password to clipboard (useful if randomly generated)\
\n     \t-o send new entry's password to standard output (useful if randomly generated)\
\n     \t-t 'n'ms or 'n's - clear password from clipboard in the specified amount of miliseconds or seconds instead of default 30 seconds.\
\n     \t-O implies '-t 55ms' to allow only one pasting of pssword before its cleared \
\n     \t-s 'selection' - use either the 'primary' or 'clipboard' X selection. (Defaults to 'primary')\
\n-r - Read mode \
\n     \t-x 'database password'\
\n     \t-C  send a specified entry's password directly to clipboard \
\n     \t-o  send a specified entry's password directly to standard output \
\n     \t-t 'n'ms or 'n's - clear password from clipboard in the specified amount of miliseconds or seconds instead of default 30 seconds.\
\n     \t-O implies '-t 55ms' to allow only one pasting of pssword before its cleared \
\n     \t-s 'selection' - use either the 'primary' or 'clipboard' X selection.(Defaults to 'primary')\
\n     \t-E - match entry using exended regular expressions instead of basic regular expressions\
\n-d - Delete mode \
\n     \t-x 'database password'\
\n     \t-E - match entry using exended regular expressions instead of basic regular expressions\
\n-u - Update entry mode \
\n     \t-P  updates entry name and password, getting password via user input instead of -p\
\n     \t-p 'password' - update the entry's password to 'password' \
\n     \t-l 'password length'\
\n     \t-n 'entry' - update the entry's name to 'entry'. Without this its assumed you're only changing entry's password. \
\n     \t-x 'database password'\
\n     \t-C send entry's new password directly to clipboard\
\n     \t-o send entry's new password directly to standard output\
\n     \t-t 'n'ms or 'n's - clear password from clipboard in the specified amount of miliseconds or seconds instead of default 30 seconds.\
\n     \t-O implies '-t 55ms' to allow only one pasting of pssword before its cleared \
\n     \t-s 'selection' - use either the 'primary' or 'clipboard' X selection. (Defaults to 'primary')\
\n     \t-E - match entry using exended regular expressions instead of basic regular expressions\
\n-U - Update database mode \
\n     \t-P  updates database password. Read via prompt. Cannot be supplied via commandline. \
\n     \t-x 'database password' (the current database password to decrypt/with) \
\n     \t-c 'cipher' - Update encryption algorithm  \
\n     \t-H 'digest' - Update digest used for algorithms' KDFs \
\n     \t-w 'N,r,p' - Specify scrypt work factors. \
\nVersion 4.0.3\
\n\
",
            arg);
    fprintf(stderr, "\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    fprintf(stderr, "Using OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));
    return 1;
}
