/* cleanupbuffers.c - cleans up buffers */

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

void cleanUpBuffers(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *buffer)
{
    /*OPENSSL_cleanse won't be optimized away by the compiler*/

    OPENSSL_cleanse(buffer->entryPass, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->entryPass);
    OPENSSL_cleanse(buffer->entryName, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->entryName);
    OPENSSL_cleanse(buffer->entryNameToFind, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->entryNameToFind);
    OPENSSL_cleanse(buffer->entryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->entryPassToVerify);
    OPENSSL_cleanse(buffer->newEntry, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->newEntry);
    OPENSSL_cleanse(buffer->newEntryPass, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->newEntryPass);
    OPENSSL_cleanse(buffer->newEntryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);
    free(buffer->newEntryPassToVerify);
    OPENSSL_cleanse(cryptoStructPtr->dbPass, sizeof(unsigned char) * strlen(cryptoStructPtr->dbPass));
    free(cryptoStructPtr->dbPass);
    OPENSSL_cleanse(cryptoStructPtr->dbPassOld, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    free(cryptoStructPtr->dbPassOld);
    OPENSSL_cleanse(cryptoStructPtr->dbPassToVerify, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    free(cryptoStructPtr->dbPassToVerify);
    OPENSSL_cleanse(cryptoStructPtr->masterKey, sizeof(unsigned char) * (EVP_MAX_KEY_LENGTH * 2));
    free(cryptoStructPtr->masterKey);
    OPENSSL_cleanse(cryptoStructPtr->evpKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(cryptoStructPtr->evpKey);
    OPENSSL_cleanse(cryptoStructPtr->evpKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(cryptoStructPtr->evpKeyOld);
    OPENSSL_cleanse(authStructPtr->HMACKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(authStructPtr->HMACKey);
    OPENSSL_cleanse(authStructPtr->HMACKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(authStructPtr->HMACKeyOld);

    /*Don't need to run OPENSSL_cleanse on these since they will be public anyway*/
    free(cryptoStructPtr->evpSalt);
    free(cryptoStructPtr->encryptedBuffer);
}
