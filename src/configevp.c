/* configevp.c - configures EVP cipher algorithm to use */

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

/* Configures which encryption algorithm from the EVP library to use */
int configEvp(struct cryptoVar *cryptoStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    /*If the user has specified a cipher to use*/
    if (conditionsStruct->userChoseCipher == true) {

        if (!EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) {
            fprintf(stderr, "Could not load cipher %s. Check that it is available with -c list\n", cryptoStructPtr->encCipherName);
            return 1;
        } else if (EVP_CIPHER_mode(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) == EVP_CIPH_GCM_MODE || EVP_CIPHER_mode(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) == EVP_CIPH_CCM_MODE) {
            fprintf(stderr, "Program does not support GCM or CCM modes.\nAlready authenticates with HMAC-SHA512\n");
            return 1;
        } else if (EVP_CIPHER_mode(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) == EVP_CIPH_WRAP_MODE) {
            fprintf(stderr, "Program does not support ciphers in wrap mode\n");
            return 1;
        }
/*Added for backward compatibility between OpenSSL 1.0 and 1.1*/
#ifdef EVP_CIPH_OCB_MODE
        else if (EVP_CIPHER_mode(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) == EVP_CIPH_OCB_MODE) {
            fprintf(stderr, "Program does not support ciphers in OCB mode\n");
            return 1;
        }
#endif
        else
            cryptoStructPtr->evpCipher = EVP_get_cipherbyname(cryptoStructPtr->encCipherName);

        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!cryptoStructPtr->evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", cryptoStructPtr->encCipherName);
            return 1;
        }

    } else { /*If not default to aes-256-ctr*/
        strcpy(cryptoStructPtr->encCipherName, "aes-256-ctr");
        cryptoStructPtr->evpCipher = EVP_get_cipherbyname(cryptoStructPtr->encCipherName);
        if (!cryptoStructPtr->evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", cryptoStructPtr->encCipherName);
            return 1;
        }
    }

    return 0;
}
