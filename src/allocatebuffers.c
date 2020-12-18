/* allocatebuffers.c - allocates buffers */

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

/* Buffers are allocated and filled with CSPRNG data so that they can be cleansed later
 * and so that buffers are not padded with zeroes that would constitute known-plain-text
 */
void allocateBuffers(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *buffer)
{
    buffer->entryPass = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->entryPass == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->entryPass, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->entryPassToVerify = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->entryPassToVerify == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->entryPassToVerify, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->entryName = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->entryName == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->entryName, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->entryNameToFind = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->entryNameToFind == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->entryNameToFind, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->newEntry = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->newEntry == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->newEntry, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->newEntryPass = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->newEntryPass == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->newEntryPass, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    buffer->newEntryPassToVerify = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (buffer->newEntryPassToVerify == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)buffer->newEntryPassToVerify, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->dbPass = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if (cryptoStructPtr->dbPass == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)cryptoStructPtr->dbPass, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->dbPassToVerify = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if (cryptoStructPtr->dbPassToVerify == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)cryptoStructPtr->dbPassToVerify, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->dbPassOld = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if (cryptoStructPtr->dbPassOld == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes((unsigned char *)cryptoStructPtr->dbPassOld, UI_BUFFERS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->evpSalt = calloc(sizeof(unsigned char), EVP_SALT_SIZE);
    if (cryptoStructPtr->evpSalt == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->masterKey = calloc(sizeof(unsigned char), (EVP_MAX_KEY_LENGTH * 2));
    if (cryptoStructPtr->masterKey == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->evpKey = calloc(sizeof(unsigned char), EVP_MAX_KEY_LENGTH);
    if (cryptoStructPtr->evpKey == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    cryptoStructPtr->evpKeyOld = calloc(sizeof(unsigned char), EVP_MAX_KEY_LENGTH);
    if (cryptoStructPtr->evpKeyOld == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    authStructPtr->HMACKey = calloc(sizeof(unsigned char), EVP_MAX_KEY_LENGTH);
    if (authStructPtr->HMACKey == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    authStructPtr->HMACKeyOld = calloc(sizeof(unsigned char), EVP_MAX_KEY_LENGTH);
    if (authStructPtr->HMACKeyOld == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
}
