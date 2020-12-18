/* verifyciphertext.c - verify cipher-text and associated data of password database*/

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

/* Verifies cipher-text and associated data
 * Must use local versions of some of the global variables in case they are changed when database is updated
 */
int verifyCiphertext(unsigned int encryptedBufferLength, unsigned char *encryptedBufferLcl, unsigned char *HMACKeyLcl, char *encCipherNameLcl, unsigned int scryptNFactorLcl, unsigned int scryptRFactorLcl, unsigned int scryptPFactorLcl, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr)
{
    /*Generate MAC from both cipher-text and associated data*/
    unsigned int evpCipherSize = strlen(encCipherNameLcl);
    unsigned int scryptWorkFactorSize = sizeof(scryptNFactorLcl);
    unsigned int hmacBufferLength = EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 3) + encryptedBufferLength;
    unsigned int *HMACLengthPtr = NULL;

    unsigned char *hmacBuffer = calloc(sizeof(unsigned char), hmacBufferLength);
    if (hmacBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        return errno;
    }

    /*Concatenates evpSalt:evpCipher:scryptNFactorLcl:scryptRFactorLcl:scryptPFactorLcl:encryptedBufferLcl into hmacBuffer*/
    memcpy(hmacBuffer, cryptoStructPtr->evpSalt, EVP_SALT_SIZE);
    memcpy(hmacBuffer + EVP_SALT_SIZE, encCipherNameLcl, evpCipherSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize, &scryptNFactorLcl, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + scryptWorkFactorSize, &scryptRFactorLcl, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 2), &scryptPFactorLcl, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 3), encryptedBufferLcl, encryptedBufferLength);

    /*Generate a SHA512 hash from the cipher-text and associated data copied into hmacBuffer and store into MACcipherTextGenerates*/
    if (HMAC(EVP_sha512(), HMACKeyLcl, EVP_MAX_KEY_LENGTH, hmacBuffer, hmacBufferLength, authStructPtr->MACcipherTextGenerates, HMACLengthPtr) == NULL) {
        PRINT_ERROR("verifyCipherText HMAC failure");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    OPENSSL_cleanse(hmacBuffer, sizeof(char) * (hmacBufferLength));
    free(hmacBuffer);
    hmacBuffer = NULL;

    if (constTimeMemCmp(authStructPtr->MACcipherTextSignedWith, authStructPtr->MACcipherTextGenerates, SHA512_DIGEST_LENGTH) != 0)
        return 1;
    else
        return 0;
}
