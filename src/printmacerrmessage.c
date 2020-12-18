/* printmacerrmessage.c - prints various authentication error messages between authentication, integrity and password check */

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

int printMACErrMessage(int errMessage)
{
    if (errMessage == INTEGRITY_FAIL)
        fprintf(stderr, "Integrity Failure\
                \n\nThis means the database file has been modified or corrupted since the program last saved it.\
                \n\nThis could be because:\
                \n\t1. An attacker has attempted to modify any part of the database on disk\
                \n\t2. A data-integrity issue with your storage media has corrupted the database\
                \n\nPlease verify your system is secure, storage media is not failing, and restore from backup.\n");
    else if (errMessage == AUTHENTICATION_FAIL)
        fprintf(stderr, "Authentication Failure\
                \n\nThis means the cipher-text or associated data has been modified, possibly after being loaded into memory.\
                \n\nThis could be because:\
                \n\t1. An attacker has attempted to modify the cipher-text and/or associated data and forged the database checksum to match\
                \n\t2. Faulty memory has lead to corruption of the cipher-text and/or associated data\
                \n\nPlease verify your system is secure, system memory is not failing, and restore from backup.\n");
    else if (errMessage == PASSWORD_FAIL)
        fprintf(stderr, "Password was incorrect.\n");
    return 0;
}
