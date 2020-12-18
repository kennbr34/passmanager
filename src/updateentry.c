/* updateentry.c - update password entries */

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

int updateEntry(char *searchString, struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct textBuf *textBuffersStructPtr, struct dbVar *dbStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int i = 0, ii = 0;
    int entriesMatched = 0;
    int passLength = 0;

    long fileSize = cryptoStructPtr->evpDataSize, oldFileSize, newFileSize;

    int evpOutputLength = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    int numberOfSymbols = 0;

    unsigned char *fileBuffer = NULL;

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

    /*Clean up EVP cipher context*/
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Mark old filesize by assgning to evpOutputLength*/
    /*This is needed in case a block cipher was used and fileSize may not reflect actual size of decrypted database*/
    oldFileSize = evpOutputLength;

    /*Allocate a buffer to store changes to now decryped information into*/
    fileBuffer = calloc(sizeof(unsigned char), fileSize);
    if (fileBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
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
            OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);
            goto cleanup;
        }

        if (regexResult == 0 || conditionsStruct->updateAllPasses == true) {

            entriesMatched++;

            if (!(((conditionsStruct->sendToClipboard == true || conditionsStruct->pipePasswordToStdout == true) && entriesMatched > 1) || (conditionsStruct->updateAllPasses == true && (conditionsStruct->sendToClipboard == true || conditionsStruct->pipePasswordToStdout == true) && entriesMatched > 1))) {

                /*Update content in entryNameBuffer before encrypting back*/
                if (conditionsStruct->entryGiven == true) {
                    memcpy(entryNameBuffer, textBuffersStructPtr->newEntry, UI_BUFFERS_SIZE);
                }

                /*This will preserve the alphanumeric nature of a password if it has no symbols*/
                if (conditionsStruct->updateAllPasses == true) {
                    passLength = strlen((char *)passWordBuffer);
                    for (ii = 0; ii < passLength; ii++) {
                        if (isupper(passWordBuffer[ii]) == 0 && islower(passWordBuffer[ii]) == 0 && isdigit(passWordBuffer[ii]) == 0)
                            numberOfSymbols++;
                    }

                    if (numberOfSymbols == 0) {
                        conditionsStruct->generateEntryPassAlpha = true;
                        conditionsStruct->generateEntryPass = false;
                    } else {
                        conditionsStruct->generateEntryPassAlpha = false;
                        conditionsStruct->generateEntryPass = true;
                    }
                    numberOfSymbols = 0;
                }

                /*Generate random passwords if gen was given, and for all if allpasses was given*/
                /*If allpasses was given, they will be random regardless if gen is not set.*/
                if (conditionsStruct->updatingEntryPass == true && (conditionsStruct->generateEntryPass == true || conditionsStruct->updateAllPasses == true)) {

                    /*This will generate a new pass for each entry during a bulk update*/
                    genPassWord(miscStructPtr, textBuffersStructPtr, conditionsStruct);
                    /*Have to copy over entryPass to textBuffersStructPtr->newEntryPass since genPassWord() operates on entryPass buffer*/
                    snprintf(textBuffersStructPtr->newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStructPtr->entryPass);
                    memcpy(passWordBuffer, textBuffersStructPtr->newEntryPass, UI_BUFFERS_SIZE);

                    /*Do the same as above but if an alphanumeric pass was specified*/
                } else if (conditionsStruct->updatingEntryPass == true && (conditionsStruct->generateEntryPassAlpha == true || conditionsStruct->updateAllPasses == true)) {
                    genPassWord(miscStructPtr, textBuffersStructPtr, conditionsStruct);
                    snprintf(textBuffersStructPtr->newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStructPtr->entryPass);
                    memcpy(passWordBuffer, textBuffersStructPtr->newEntryPass, UI_BUFFERS_SIZE);
                }

                if (conditionsStruct->updatingEntryPass == true) {
                    memcpy(passWordBuffer, textBuffersStructPtr->newEntryPass, UI_BUFFERS_SIZE);
                }

                /*Copy the entryNameBuffer and passWordBuffer out to fileBuffer*/
                memcpy(fileBuffer + i, entryNameBuffer, UI_BUFFERS_SIZE);
                memcpy(fileBuffer + i + UI_BUFFERS_SIZE, passWordBuffer, UI_BUFFERS_SIZE);

                if (conditionsStruct->entryGiven == true)
                    fprintf(stderr, "Updating \"%s\" to \"%s\" ...\n", searchString, entryNameBuffer);
                else
                    fprintf(stderr, "Matched \"%s\" to \"%s\" (Updating...)\n", searchString, entryNameBuffer);
            } else { /*Write back the original entry and pass if if alraeady matched one entry and sendToClipboard or pipePasswordToStdout is true*/
                memcpy(fileBuffer + i, entryNameBuffer, UI_BUFFERS_SIZE);
                memcpy(fileBuffer + i + UI_BUFFERS_SIZE, passWordBuffer, UI_BUFFERS_SIZE);
            }

        } else { /*Write back the original entry and pass if nothing matched searchString*/
            memcpy(fileBuffer + i, entryNameBuffer, UI_BUFFERS_SIZE);
            memcpy(fileBuffer + i + UI_BUFFERS_SIZE, passWordBuffer, UI_BUFFERS_SIZE);
        }
    }

    /*Clear out sensitive buffers ASAP*/
    OPENSSL_cleanse(entryNameBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(passWordBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize + EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(passWordBuffer, sizeof(char) * UI_BUFFERS_SIZE);

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    /*No need to run OPENSSL_cleanse since it is already encrypted*/
    free(cryptoStructPtr->encryptedBuffer);

    /*Allocate new buffer for encrypted information*/
    cryptoStructPtr->encryptedBuffer = calloc(sizeof(unsigned char), oldFileSize + EVP_MAX_BLOCK_LENGTH);
    if (cryptoStructPtr->encryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);
        goto cleanup;
    }

    /*Make sure to point globalBufferPtr.encryptedBuffer to new location so it can be freed on program exit*/
    globalBufferPtr.encryptedBuffer = cryptoStructPtr->encryptedBuffer;

    /*Creating a new databse with new salt, so also need new HMAC and EVP key derived from that salt*/
    if (genEvpSalt(cryptoStructPtr) != 0) {
        PRINT_ERROR("Could not update salt");
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);
        goto cleanup;
    }
    if (deriveKeys(cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not create new HMAC key");
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);
        goto cleanup;
    }

    /*Begin encryption of new database*/
    EVP_EncryptInit_ex(ctx, cryptoStructPtr->evpCipher, NULL, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

    if (evpEncrypt(ctx, oldFileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, fileBuffer) != 0) {
        PRINT_ERROR("evpEncrypt failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);
        goto cleanup;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    /*Assign size of evpOutputLength as the new file size*/
    /*This is needed in case a block cipher is used and new size may not simply be UI_BUFFERS_SIZE * 2*/
    newFileSize = evpOutputLength;
    cryptoStructPtr->evpDataSize = newFileSize;

    /*Sanitize fileBuffer of sensitive information ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);

    /*Create MAC of cipher-text and associated data to sign with*/
    if (signCiphertext(newFileSize, cryptoStructPtr->encryptedBuffer, cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not sign ciphertext\n");
        goto cleanup;
    }

    /*Check if any entries were updated and inform user accordingly*/
    if (entriesMatched < 1) {
        fprintf(stderr, "Nothing matched the entry specified, nothing was updated.\n");
    } else {
        fprintf(stderr, "If you updated more than you intended to, restore from %s%s\n", dbStructPtr->dbFileName, dbStructPtr->backupFileExt);
    }

    /*Pipe new password to standard output if specified*/
    if (conditionsStruct->pipePasswordToStdout == true && entriesMatched >= 1) {
        fprintf(stderr, "Piping new password to standard output\n");
        fprintf(stdout, "%s", textBuffersStructPtr->newEntryPass);
    }

    /*If specified to send password to clipboard, clean up buffers and do so, if not just clean up buffers*/
    if (conditionsStruct->sendToClipboard == true && conditionsStruct->pipePasswordToStdout == false) {
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
        if (sendToClipboard(textBuffersStructPtr->newEntryPass, miscStructPtr, conditionsStruct) == 0) {
            if (entriesMatched > 1)
                printClipboardMessage(entriesMatched, miscStructPtr, conditionsStruct);
            else
                printClipboardMessage(1, miscStructPtr, conditionsStruct);
        }
    } else {

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
    }

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
