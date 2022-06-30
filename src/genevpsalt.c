/* genevpsalt.c - generates a salt for EVP algorithms to use */

/* Copyright 2022 Kenneth Brown */

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

/* Generates the salt to use with KDF */
int genEvpSalt(struct cryptoVar *cryptoStructPtr)
{

    unsigned char randomByte;
    int i = 0;

    while (i < EVP_SALT_SIZE) {
        if (!RAND_bytes(&randomByte, 1)) {
            PRINT_ERROR("Failure: CSPRNG bytes could not be made unpredictable\n");
            return 1;
        }
        cryptoStructPtr->evpSalt[i] = randomByte;
        i++;
    }

    return 0;
}
