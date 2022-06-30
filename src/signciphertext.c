/* signciphertext.c - sign cipher-text and associated data of password database*/

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

/* Signs cipher-text and associated data
 * Must have its own copy of encryptedBuffer besides the global version so that different buffers can be passed to the funciton
 * Such as: in addEntry() versus deleteEntry() or updateEntry()
 */
int signCiphertext(unsigned int encryptedBufferLength, unsigned char *encryptedBufferLcl, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr)
{
    /*Generate MAC from both cipher-text and associated data*/
    unsigned int evpCipherSize = strlen(cryptoStructPtr->encCipherName);
    unsigned int scryptWorkFactorSize = sizeof(cryptoStructPtr->scryptNFactor);
    unsigned int hmacBufferLength = EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 3) + encryptedBufferLength;
    unsigned int *HMACLengthPtr = NULL;

    unsigned char *hmacBuffer = calloc(sizeof(unsigned char), hmacBufferLength);
    if (hmacBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        return 1;
    }

    /*Concatenates evpSalt:evpCipher:scryptNFactorLcl:scryptRFactorLcl:scryptPFactorLcl:encryptedBufferLcl into hmacBuffer*/
    memcpy(hmacBuffer, cryptoStructPtr->evpSalt, EVP_SALT_SIZE);
    memcpy(hmacBuffer + EVP_SALT_SIZE, cryptoStructPtr->encCipherName, evpCipherSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize, &cryptoStructPtr->scryptNFactor, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + scryptWorkFactorSize, &cryptoStructPtr->scryptRFactor, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 2), &cryptoStructPtr->scryptPFactor, scryptWorkFactorSize);
    memcpy(hmacBuffer + EVP_SALT_SIZE + evpCipherSize + (scryptWorkFactorSize * 3), encryptedBufferLcl, encryptedBufferLength);

    /*Generate MAC from the cipher-text and associated data copied into hmacBuffer and store into MACcipherTextGenerates*/
    if (HMAC(EVP_sha512(), authStructPtr->HMACKey, EVP_MAX_KEY_LENGTH, hmacBuffer, hmacBufferLength, authStructPtr->MACcipherTextGenerates, HMACLengthPtr) == NULL) {
        PRINT_ERROR("signCipherText HMAC failure");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    OPENSSL_cleanse(hmacBuffer, sizeof(char) * (hmacBufferLength));
    free(hmacBuffer);
    hmacBuffer = NULL;

    return 0;
}
