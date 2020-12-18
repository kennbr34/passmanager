/* addentry.c - add password entry */

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

int addEntry(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    long fileSize = cryptoStructPtr->evpDataSize, newFileSize, oldFileSize;

    int evpOutputLength;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*entryPass and entryName are both copied into newEntryBuffer, which is then encrypted*/
    unsigned char *newEntryBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE * 2);
    if (newEntryBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }
    unsigned char *decryptedBuffer = calloc(sizeof(unsigned char), fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
    if (decryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Copy textBuffersStructPtr->entryName and textBuffersStructPtr-entryPass newEntryBuffer*/
    memcpy(newEntryBuffer, textBuffersStructPtr->entryName, UI_BUFFERS_SIZE);
    memcpy(newEntryBuffer + UI_BUFFERS_SIZE, textBuffersStructPtr->entryPass, UI_BUFFERS_SIZE);

    /*If this is not the first entry being added, then must decrypt current database before adding entry to it*/
    if (conditionsStruct->databaseBeingInitalized == false) {

        /*Verify cipher-text loaded into cryptoSetingsPtr->encryptedBuffer by openDatabase*/
        if (verifyCiphertext(fileSize, cryptoStructPtr->encryptedBuffer, authStructPtr->HMACKey, cryptoStructPtr->encCipherName, cryptoStructPtr->scryptNFactor, cryptoStructPtr->scryptRFactor, cryptoStructPtr->scryptPFactor, cryptoStructPtr, authStructPtr) != 0) {
            printMACErrMessage(AUTHENTICATION_FAIL);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }

        /*Begin decryption*/
        EVP_DecryptInit(ctx, cryptoStructPtr->evpCipher, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

        if (evpDecrypt(ctx, fileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, decryptedBuffer) != 0) {
            PRINT_ERROR("evpDecrypt failed");
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }

        EVP_CIPHER_CTX_cleanup(ctx);
    }

    /*Otherwise if it is the first entry being added, add it from cryptoStruct->dbInitBuffer*/
    if (conditionsStruct->databaseBeingInitalized == true) {
        /*Begin encryption of new database*/
        EVP_EncryptInit_ex(ctx, cryptoStructPtr->evpCipher, NULL, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

        if (evpEncrypt(ctx, UI_BUFFERS_SIZE * 2, &evpOutputLength, cryptoStructPtr->dbInitBuffer, newEntryBuffer) != 0) {
            PRINT_ERROR("evpEncrypt failed");
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }

        EVP_CIPHER_CTX_cleanup(ctx);

        /*Clear out sensitive information in newEntryBuffer ASAP*/
        OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);

        /*Create MAC of cipher-text and associated data to sign with*/
        if (signCiphertext(evpOutputLength, cryptoStructPtr->dbInitBuffer, cryptoStructPtr, authStructPtr) != 0) {
            PRINT_ERROR("Could not sign ciphertext\n");
            goto cleanup;
        }

        cryptoStructPtr->evpDataSize = evpOutputLength;

    } else { /*If not the first password entry in database, add it to the current database in cryptoStruct->encryptedBuffer*/

        /*Creating a new databse with new salt, so also need new HMAC and EVP key derived from that salt*/
        if (genEvpSalt(cryptoStructPtr) != 0) {
            PRINT_ERROR("Could not update salt");
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }
        if (deriveKeys(cryptoStructPtr, authStructPtr) != 0) {
            PRINT_ERROR("Could not create new HMAC key");
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }

        /*Begin encryption of new database*/
        EVP_EncryptInit_ex(ctx, cryptoStructPtr->evpCipher, NULL, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

        /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
        /*No need to run OPENSSL_cleanse since it is already encrypted*/
        free(cryptoStructPtr->encryptedBuffer);
        cryptoStructPtr->encryptedBuffer = calloc(sizeof(unsigned char), evpOutputLength + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
        if (cryptoStructPtr->encryptedBuffer == NULL) {
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
            OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            goto cleanup;
        }

        /*Make sure to point globalBufferPtr.encryptedBuffer to new location so it can be freed on program exit*/
        globalBufferPtr.encryptedBuffer = cryptoStructPtr->encryptedBuffer;

        memcpy(decryptedBuffer + evpOutputLength, newEntryBuffer, UI_BUFFERS_SIZE * 2);

        OPENSSL_cleanse(newEntryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);

        oldFileSize = evpOutputLength;

        if (evpEncrypt(ctx, evpOutputLength + (UI_BUFFERS_SIZE * 2), &evpOutputLength, cryptoStructPtr->encryptedBuffer, decryptedBuffer) != 0) {
            PRINT_ERROR("evpEncrypt falied");
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
            goto cleanup;
        }

        EVP_CIPHER_CTX_cleanup(ctx);

        /*Assign size of evpOutputLength as the new file size*/
        /*This is needed in case a block cipher is used and new size may not simply be UI_BUFFERS_SIZE * 2*/
        newFileSize = evpOutputLength;

        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);

        /*Create MAC of cipher-text and associated data to sign with*/
        if (signCiphertext(newFileSize, cryptoStructPtr->encryptedBuffer, cryptoStructPtr, authStructPtr) != 0) {
            PRINT_ERROR("Could not sign ciphertext\n");
            goto cleanup;
        }

        cryptoStructPtr->evpDataSize = newFileSize;
    }

    fprintf(stderr, "Added \"%s\" to database.\n", textBuffersStructPtr->entryName);

    /*Pipe new password to standard output if specified*/
    if (conditionsStruct->pipePasswordToStdout == true) {
        fprintf(stderr, "Piping new password to standard output\n");
        fprintf(stdout, "%s", textBuffersStructPtr->entryPass);
    }

    /*If specified to send password to clipboard, clean up buffers and do so, if not just clean up buffers*/
    if (conditionsStruct->sendToClipboard == true) {

        free(newEntryBuffer);
        newEntryBuffer = NULL;
        free(decryptedBuffer);
        decryptedBuffer = NULL;
        free(ctx);
        ctx = NULL;
        if (sendToClipboard(textBuffersStructPtr->entryPass, miscStructPtr, conditionsStruct) == 0) {
            printClipboardMessage(0, miscStructPtr, conditionsStruct);
        }
    } else {

        free(newEntryBuffer);
        newEntryBuffer = NULL;
        free(decryptedBuffer);
        decryptedBuffer = NULL;
        free(ctx);
        ctx = NULL;
    }

    return 0;

cleanup:
    free(newEntryBuffer);
    newEntryBuffer = NULL;
    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(ctx);
    ctx = NULL;
    return 1;
}
