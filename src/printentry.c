/* printentry.c - print password entries */

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

int printEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int i = 0;
    int entriesMatched = 0;

    int evpOutputLength = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    long fileSize = cryptoStructPtr->evpDataSize;

    unsigned char *entryNameBuffer = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (entryNameBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }
    unsigned char *passWordBuffer = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if (passWordBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }
    unsigned char *decryptedBuffer = calloc(sizeof(char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if (decryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Verify cipher-text loaded into cryptoSetingsPtr->encryptedBuffer by openDatabase*/
    if (verifyCiphertext(fileSize, cryptoStructPtr->encryptedBuffer, authStructPtr->HMACKey, cryptoStructPtr->encCipherName, cryptoStructPtr->scryptNFactor, cryptoStructPtr->scryptRFactor, cryptoStructPtr->scryptPFactor, cryptoStructPtr, authStructPtr) != 0) {
        printMACErrMessage(AUTHENTICATION_FAIL);
        goto cleanup;
    }

    /*Begin decryption*/
    EVP_DecryptInit(ctx, cryptoStructPtr->evpCipher, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

    /*Decrypt cryptoStructPtr->encryptedBuffer and store into decryptedBuffer*/
    if (evpDecrypt(ctx, fileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, decryptedBuffer) != 0) {
        PRINT_ERROR("evpDecrypt failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }

    /*Clean up EVP cipher context*/
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Loop to process the entries*/
    for (i = 0; i < evpOutputLength; i += (UI_BUFFERS_SIZE * 2)) {

        /*Copy the decrypted information into entryNameBuffer and passWordBuffer*/
        memcpy(entryNameBuffer, decryptedBuffer + i, UI_BUFFERS_SIZE);
        memcpy(passWordBuffer, decryptedBuffer + i + UI_BUFFERS_SIZE, UI_BUFFERS_SIZE);

        if (searchString != NULL) {

            int regexCflags = 0;

            if (conditionsStruct->useExtendedRegex == true)
                regexCflags = REG_EXTENDED;

            int regexResult = regExComp(searchString, (char *)entryNameBuffer, regexCflags);
            if (regexResult == -1) {
                PRINT_ERROR("Problem with regex\n");
                OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
                OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * (UI_BUFFERS_SIZE / 2));
                OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * (UI_BUFFERS_SIZE / 2));
                goto cleanup;
            }

            if (regexResult == 0) {
                entriesMatched++;

                /*Pipe password to standard output if specified*/
                if (conditionsStruct->pipePasswordToStdout == true) {
                    fprintf(stderr, "Matched \"%s\" to \"%s\"\n", searchString, entryNameBuffer);
                    fprintf(stderr, "Piping password to standard output\n");
                    fprintf(stdout, "%s", (char *)passWordBuffer);
                    if (entriesMatched == 1 && conditionsStruct->pipePasswordToStdout) {
                        OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpOutputLength + EVP_MAX_BLOCK_LENGTH);
                        OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);

                        free(entryNameBuffer);
                        entryNameBuffer = NULL;
                        free(decryptedBuffer);
                        decryptedBuffer = NULL;
                        free(ctx);
                        ctx = NULL;
                        free(passWordBuffer);
                        passWordBuffer = NULL;
                        break;
                    }
                }

                /*Send password to clipboard if specified*/
                if (conditionsStruct->sendToClipboard == true) {
                    fprintf(stderr, "Matched \"%s\" to \"%s\"\n", searchString, entryNameBuffer);
                    if (entriesMatched == 1 && conditionsStruct->sendToClipboard == true) {
                        OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpOutputLength + EVP_MAX_BLOCK_LENGTH);

                        free(entryNameBuffer);
                        entryNameBuffer = NULL;
                        free(decryptedBuffer);
                        decryptedBuffer = NULL;
                        free(ctx);
                        ctx = NULL;
                        if (sendToClipboard((char *)passWordBuffer, miscStructPtr, conditionsStruct) == 0) {
                            if (strcmp(searchString, textBuffersStructPtr->entryName) == 0) {
                                printClipboardMessage(1, miscStructPtr, conditionsStruct);
                            } else {
                                printClipboardMessage(0, miscStructPtr, conditionsStruct);
                            }
                        }
                        OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                        free(passWordBuffer);
                        passWordBuffer = NULL;
                        break;
                    }
                }

                if (conditionsStruct->pipePasswordToStdout == false && conditionsStruct->sendToClipboard == false) {
                    fprintf(stdout, "%s : %s\n", entryNameBuffer, passWordBuffer);
                }
            }
        } else /*If an entry name wasn't specified, print them all*/
            fprintf(stdout, "%s : %s\n", entryNameBuffer, passWordBuffer);
    }

    if (entriesMatched == 0 && searchString != NULL) {
        fprintf(stderr, "Nothing matched \"%s\"\n", searchString);
    }

    /*If sending password to clipboard was not specified cleanup and free buffers here instead of above*/
    if (conditionsStruct->sendToClipboard == false && conditionsStruct->pipePasswordToStdout == false) {
        OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
        OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpOutputLength + EVP_MAX_BLOCK_LENGTH);

        free(entryNameBuffer);
        entryNameBuffer = NULL;
        free(passWordBuffer);
        passWordBuffer = NULL;
        free(decryptedBuffer);
        decryptedBuffer = NULL;
        free(ctx);
        ctx = NULL;
    }

    return 0;

cleanup:
    free(entryNameBuffer);
    entryNameBuffer = NULL;
    free(passWordBuffer);
    passWordBuffer = NULL;
    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(ctx);
    ctx = NULL;
    return 1;
}
