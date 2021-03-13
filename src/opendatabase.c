/* opendatabase.c - open a password database */

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

/* The composition of the password database on file will be as so:
 * salt|cipher name|scrypt settings|cipher text|keyed-hash of password|MAC of cipher and AD|checksum of everything prior
 * 
 * The checksum only exists to ensure integrity of the file on disk.
 * The MAC will authentiate the cipher-text as well as associated data
 * The keyed-hash of the password is used to notify the user if they entered the wrong password
 * 
 * The opendDatabase() funciton below will read this information into buffers as needed
 */

/* Opens the password databse file and loads the salt, 
 * crypto settings, KDF settings, keyed hash of password, MAC
 * checksum signature of the database, etc. (Actual order varies)
 */
int openDatabase(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    unsigned char *verificationBuffer = NULL;
    int MACSize = SHA512_DIGEST_LENGTH;
    int fileSize = returnFileSize(dbStructPtr->dbFileName);
    cryptoStructPtr->evpDataSize = fileSize - (EVP_SALT_SIZE + CRYPTO_HEADER_SIZE + (MACSize * 3));
    unsigned int *HMACLengthPtr = NULL;

    FILE *dbFile = NULL;

    dbFile = fopen(dbStructPtr->dbFileName, "rb");
    if (dbFile == NULL) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        goto cleanup;
    }

    /*fread overwrites any randomly generated salt with the one read from file*/
    if (freadWErrCheck(cryptoStructPtr->evpSalt, sizeof(char), EVP_SALT_SIZE, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    /*Read the cipher information in*/
    if (freadWErrCheck(cryptoStructPtr->cryptoHeader, sizeof(char), CRYPTO_HEADER_SIZE, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    /*Read scrypt work factors from end of cryptoHeader*/
    memcpy(&cryptoStructPtr->scryptNFactor, cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1), sizeof(int));
    memcpy(&cryptoStructPtr->scryptRFactor, cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1) + sizeof(int) + sizeof(int), sizeof(int));
    memcpy(&cryptoStructPtr->scryptPFactor, cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1) + sizeof(int) + sizeof(int) + sizeof(int), sizeof(int));

    if (conditionsStruct->printingDbInfo == false) {
        if (deriveKeys(cryptoStructPtr, authStructPtr) != 0) {
            PRINT_ERROR("Could not create master key");
            goto cleanup;
        }
    }

    /*Copy all of the file minus the checksum but including the salt and cryptoHeader and keyed-hash/MAC into a buffer for verification*/
    verificationBuffer = calloc(fileSize - MACSize, sizeof(unsigned char));
    if (verificationBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Reset to beginning since reading in the salt and cryptoHeader have advanced the file position*/
    if (fseek(dbFile, 0L, SEEK_SET) != 0) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    if (freadWErrCheck(verificationBuffer, sizeof(unsigned char), fileSize - MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    /*Set the file position to the beginning of the first SHA512 hash and read the rest*/
    if (fseek(dbFile, fileSize - (MACSize * 3), SEEK_SET) != 0) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    if (freadWErrCheck(authStructPtr->KeyedHashdBPassSignedWith, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    if (freadWErrCheck(authStructPtr->MACcipherTextSignedWith, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    if (freadWErrCheck(authStructPtr->CheckSumDbFileSignedWith, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        goto cleanup;
    }

    /*If not just printing database info, check the database for integrity and and if correct password was issued*/
    if (conditionsStruct->printingDbInfo == false) {

        /*Verify integrity of database*/
        if (SHA512(verificationBuffer, fileSize - MACSize, authStructPtr->CheckSumDbFileGenerates) == NULL) {
            PRINT_ERROR("SHA512 failed");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        if (constTimeMemCmp(authStructPtr->CheckSumDbFileSignedWith, authStructPtr->CheckSumDbFileGenerates, MACSize) != 0) {
            printMACErrMessage(INTEGRITY_FAIL);

            goto cleanup;
        }

        /*Verify dbPass*/
        if (HMAC(EVP_sha512(), authStructPtr->HMACKey, EVP_MAX_KEY_LENGTH, (const unsigned char *)cryptoStructPtr->dbPass, strlen(cryptoStructPtr->dbPass), authStructPtr->KeyedHashdBPassGenerates, HMACLengthPtr) == NULL) {
            PRINT_ERROR("HMAC falied");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        if (constTimeMemCmp(authStructPtr->KeyedHashdBPassSignedWith, authStructPtr->KeyedHashdBPassGenerates, MACSize) != 0) {
            printMACErrMessage(PASSWORD_FAIL);

            goto cleanup;
        }
    }

    /*Create a backup after verification of MAC so that user can recover database if something went wrong in the last modification*/
    if (backupDatabase(dbStructPtr, miscStructPtr, conditionsStruct) != 0) {
        goto cleanup;
    }

    /*Copy verificationBuffer to encryptedBuffer without the header information or MACs*/
    cryptoStructPtr->encryptedBuffer = calloc(sizeof(char), cryptoStructPtr->evpDataSize);
    if (cryptoStructPtr->encryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Must point globalBufferPtr.encryptedBuffer to the new location allocated by calloc*/
    /*Otherwise cleanUpBuffers will not be able to free it at exit*/
    globalBufferPtr.encryptedBuffer = cryptoStructPtr->encryptedBuffer;

    memcpy(cryptoStructPtr->encryptedBuffer, verificationBuffer + EVP_SALT_SIZE + CRYPTO_HEADER_SIZE, cryptoStructPtr->evpDataSize);

    if (fclose(dbFile) == EOF) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        goto cleanup;
    }

    free(verificationBuffer);
    verificationBuffer = NULL;

    /*Load cipher name from header*/
    snprintf(cryptoStructPtr->encCipherName, NAME_MAX, "%s", cryptoStructPtr->cryptoHeader);

    /*Check the string read is a valid name*/
    cryptoStructPtr->evpCipher = EVP_get_cipherbyname(cryptoStructPtr->encCipherName);
    if (!cryptoStructPtr->evpCipher) {
        fprintf(stderr, "Could not load cipher %s. Is it installed? Use -c list to list available ciphers\n", cryptoStructPtr->encCipherName);
        goto cleanup;
    }

    return 0;

cleanup:
    if (dbFile != NULL)
        fclose(dbFile);
    free(verificationBuffer);
    verificationBuffer = NULL;
    free(cryptoStructPtr->encryptedBuffer);
    cryptoStructPtr->encryptedBuffer = NULL;
    exit(EXIT_FAILURE);
}
