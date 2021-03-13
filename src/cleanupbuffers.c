/* cleanupbuffers.c - cleans up buffers */

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

void cleanUpBuffers()
{
    /*OPENSSL_cleanse won't be optimized away by the compiler*/

    OPENSSL_cleanse(globalBufferPtr.entryPass, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.entryPass);
    OPENSSL_cleanse(globalBufferPtr.entryName, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.entryName);
    OPENSSL_cleanse(globalBufferPtr.entryNameToFind, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.entryNameToFind);
    OPENSSL_cleanse(globalBufferPtr.entryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.entryPassToVerify);
    OPENSSL_cleanse(globalBufferPtr.newEntry, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.newEntry);
    OPENSSL_cleanse(globalBufferPtr.newEntryPass, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.newEntryPass);
    OPENSSL_cleanse(globalBufferPtr.newEntryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.newEntryPassToVerify);
    OPENSSL_cleanse(globalBufferPtr.dbPass, sizeof(unsigned char) * strlen(globalBufferPtr.dbPass));
    free(globalBufferPtr.dbPass);
    OPENSSL_cleanse(globalBufferPtr.dbPassOld, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.dbPassOld);
    OPENSSL_cleanse(globalBufferPtr.dbPassToVerify, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    free(globalBufferPtr.dbPassToVerify);
    OPENSSL_cleanse(globalBufferPtr.masterKey, sizeof(unsigned char) * (EVP_MAX_KEY_LENGTH * 2));
    free(globalBufferPtr.masterKey);
    OPENSSL_cleanse(globalBufferPtr.evpKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(globalBufferPtr.evpKey);
    OPENSSL_cleanse(globalBufferPtr.evpKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(globalBufferPtr.evpKeyOld);
    OPENSSL_cleanse(globalBufferPtr.HMACKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(globalBufferPtr.HMACKey);
    OPENSSL_cleanse(globalBufferPtr.HMACKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    free(globalBufferPtr.HMACKeyOld);

    /*Don't need to run OPENSSL_cleanse on these since they will be public anyway*/
    free(globalBufferPtr.evpSalt);
    free(globalBufferPtr.encryptedBuffer);
}
