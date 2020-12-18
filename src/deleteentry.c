/* deleteentry.c - delete password entries */

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

int deleteEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int i = 0, ii = 0;
    int entriesMatched = 0;

    long fileSize = cryptoStructPtr->evpDataSize, oldFileSize, newFileSize;

    int evpOutputLength;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    unsigned char *fileBuffer = NULL;
    unsigned char *fileBufferOld = NULL;

    unsigned char *entryNameBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if (entryNameBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }
    unsigned char *passWordBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if (passWordBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    unsigned char *decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
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
        PRINT_ERROR("evpDecrypt failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    /*Mark old filesize by assgning to evpOutputLength*/
    /*This is needed in case a block cipher was used and fileSize may not reflect actual size of decrypted database*/
    oldFileSize = evpOutputLength;

    /*Allocate a buffer to store changes to now decryped information into*/
    /*This buffer will be reallocated later if a match is found*/
    fileBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if (fileBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Loop to process the entries*/
    for (i = 0; i < oldFileSize; i += (UI_BUFFERS_SIZE * 2)) {

        /*Copy UI_BUFFERS_SIZE chunks into respective entry and password buffers*/
        memcpy(entryNameBuffer, decryptedBuffer + i, UI_BUFFERS_SIZE);
        memcpy(passWordBuffer, decryptedBuffer + i + UI_BUFFERS_SIZE, UI_BUFFERS_SIZE);

        int regexCflags = 0;

        if (conditionsStruct->useExtendedRegex == true)
            regexCflags = REG_EXTENDED;

        int regexResult = regExComp(searchString, (char *)entryNameBuffer, regexCflags);
        if (regexResult == -1) {
            PRINT_ERROR("Problem with regex\n");
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
            OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * (UI_BUFFERS_SIZE / 2));
            OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * (UI_BUFFERS_SIZE / 2));
            OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
            goto cleanup;
        }

        if (regexResult == 0) {
            if (i == (oldFileSize - (UI_BUFFERS_SIZE * 2))) /*If i is positioned at start of the last entry*/
            {
                /*Re-size the buffer to reflect deleted passwords*/
                /*Not using realloc() because it will leak and prevent wiping sensitive information*/
                fileBufferOld = calloc(sizeof(unsigned char), oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                if (fileBufferOld == NULL) {
                    PRINT_SYS_ERROR(errno);
                    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
                    OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                    OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    goto cleanup;
                }
                memcpy(fileBufferOld, fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                free(fileBuffer);

                fileBuffer = calloc(sizeof(unsigned char), oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                if (fileBuffer == NULL) {
                    PRINT_SYS_ERROR(errno);
                    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
                    OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                    OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
                    OPENSSL_cleanse(fileBufferOld, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    goto cleanup;
                }
                memcpy(fileBuffer, fileBufferOld, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                OPENSSL_cleanse(fileBufferOld, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                free(fileBufferOld);
                fileBufferOld = NULL;
            }
            fprintf(stderr, "Matched \"%s\" to \"%s\" (Deleting)...\n", searchString, entryNameBuffer);
            entriesMatched++;
        } else { /*Write back the original entry and pass if nothing matched searchString*/
            memcpy(fileBuffer + ii, entryNameBuffer, UI_BUFFERS_SIZE);
            memcpy(fileBuffer + ii + UI_BUFFERS_SIZE, passWordBuffer, UI_BUFFERS_SIZE);

            ii += UI_BUFFERS_SIZE * 2;
        }
    }

    /*If an entry was matched, modify newFileSize according to the amount of entries matched*/
    if (entriesMatched >= 1)
        newFileSize = oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched);
    else
        newFileSize = oldFileSize;

    /*Clear out sensitive information ASAP*/
    OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize);

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    /*No need to run OPENSSL_cleanse since it is already encrypted*/
    free(cryptoStructPtr->encryptedBuffer);
    cryptoStructPtr->encryptedBuffer = calloc(sizeof(unsigned char), (newFileSize + EVP_MAX_BLOCK_LENGTH));
    if (cryptoStructPtr->encryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * newFileSize);
        goto cleanup;
    }

    /*Make sure to point globalBufferPtr.encryptedBuffer to new location so it can be freed on program exit*/
    globalBufferPtr.encryptedBuffer = cryptoStructPtr->encryptedBuffer;

    /*Creating a new databse with new salt, so also need new HMAC and EVP key derived from that salt*/
    if (genEvpSalt(cryptoStructPtr) != 0) {
        PRINT_ERROR("Could not update salt");
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * newFileSize);
        goto cleanup;
    }
    if (deriveKeys(cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not create new HMAC key");
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * newFileSize);
        goto cleanup;
    }

    /*Begin encryption of new database*/
    EVP_EncryptInit_ex(ctx, cryptoStructPtr->evpCipher, NULL, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

    if (evpEncrypt(ctx, newFileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, fileBuffer) != 0) {
        PRINT_ERROR("evpEncrypt failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        goto cleanup;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    /*Clear out sensitive information in fileBuffer ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * newFileSize);

    /*Assign size of evpOutputLength as the new file size*/
    /*This is needed in case a block cipher is used and new size may not simply be UI_BUFFERS_SIZE * 2*/
    newFileSize = evpOutputLength;
    cryptoStructPtr->evpDataSize = newFileSize;

    /*Create MAC of cipher-text and associated data to sign with*/
    if (signCiphertext(newFileSize, cryptoStructPtr->encryptedBuffer, cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not sign ciphertext\n");
        goto cleanup;
    }

    /*Check if any entries were deleted and inform user accordingly*/
    if (entriesMatched < 1) {
        fprintf(stderr, "Nothing matched that exactly.\n");
    } else {
        fprintf(stderr, "If you deleted more than you intended to, restore from %s%s\n", dbStructPtr->dbFileName, dbStructPtr->backupFileExt);
    }

    free(entryNameBuffer);
    entryNameBuffer = NULL;
    free(passWordBuffer);
    passWordBuffer = NULL;
    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(fileBuffer);
    fileBuffer = NULL;
    free(ctx);
    ctx = NULL;

    return 0;

cleanup:
    free(entryNameBuffer);
    entryNameBuffer = NULL;
    free(passWordBuffer);
    passWordBuffer = NULL;
    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(fileBuffer);
    fileBuffer = NULL;
    free(ctx);
    ctx = NULL;
    return 1;
}
