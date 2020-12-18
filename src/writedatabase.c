/* writedatabase.c - write a password database */

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
 * The writeDatabase() funciton below will write this information from buffers to file as needed
 */

/* Writes the corresponding password database with salt, crypto settings,
 * cipher-text, keyed-hash of password, MAC and checksum of database.
 */
int writeDatabase(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr, struct dbVar *dbStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    unsigned int *HMACLengthPtr = NULL;

    unsigned char *cryptoHeaderPadding = calloc(sizeof(unsigned char), CRYPTO_HEADER_SIZE);
    if (cryptoHeaderPadding == NULL) {
        PRINT_SYS_ERROR(errno);
        return errno;
    }
    unsigned char *fileBuffer = NULL;
    int MACSize = SHA512_DIGEST_LENGTH;
    int fileSize = cryptoStructPtr->evpDataSize;

    /*Fills cryptoHeaderPadding with CRSPNG data*/
    if (!RAND_bytes(cryptoHeaderPadding, CRYPTO_HEADER_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    /*Copies that CRSPNG padding to cryptoStructPtr->cryptoHeader*/
    memcpy(cryptoStructPtr->cryptoHeader, cryptoHeaderPadding, sizeof(char) * CRYPTO_HEADER_SIZE);
    free(cryptoHeaderPadding);
    cryptoHeaderPadding = NULL;

    FILE *dbFile = NULL;

    dbFile = fopen(dbStructPtr->dbFileName, "wb");
    if (dbFile == NULL) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }

    /*Write encCipherName to the CSPRNG padded buffer*/
    if (snprintf(cryptoStructPtr->cryptoHeader, CRYPTO_HEADER_SIZE, "%s", cryptoStructPtr->encCipherName) < 0) {
        PRINT_ERROR("snprintf failed");
        exit(EXIT_FAILURE);
    }

    /*Append scrypt work factors to the CSPRNG padded buffer*/
    memcpy(cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1), &cryptoStructPtr->scryptNFactor, sizeof(cryptoStructPtr->scryptNFactor));
    memcpy(cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1) + sizeof(cryptoStructPtr->scryptNFactor) + sizeof(cryptoStructPtr->scryptRFactor), &cryptoStructPtr->scryptRFactor, sizeof(cryptoStructPtr->scryptRFactor));
    memcpy(cryptoStructPtr->cryptoHeader + (strlen(cryptoStructPtr->cryptoHeader) + 1) + sizeof(cryptoStructPtr->scryptNFactor) + sizeof(cryptoStructPtr->scryptRFactor) + sizeof(cryptoStructPtr->scryptPFactor), &cryptoStructPtr->scryptPFactor, sizeof(cryptoStructPtr->scryptPFactor));

    /*Now begin composing the database*/

    /*Write evpSalt*/
    if (fwriteWErrCheck(cryptoStructPtr->evpSalt, sizeof(unsigned char), EVP_SALT_SIZE, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    /*Write the cryptoHeader*/
    if (fwriteWErrCheck(cryptoStructPtr->cryptoHeader, sizeof(unsigned char), CRYPTO_HEADER_SIZE, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    /*If this is the first entry to the database it will be contained in dbInitBuffer instead*/
    if (conditionsStruct->databaseBeingInitalized == true) {
        if (fwriteWErrCheck(cryptoStructPtr->dbInitBuffer, sizeof(char), fileSize, dbFile, miscStructPtr) != 0) {
            PRINT_SYS_ERROR(miscStructPtr->returnVal);
            exit(EXIT_FAILURE);
        }
    } else {
        if (fwriteWErrCheck(cryptoStructPtr->encryptedBuffer, sizeof(char), fileSize, dbFile, miscStructPtr) != 0) {
            PRINT_SYS_ERROR(miscStructPtr->returnVal);
            exit(EXIT_FAILURE);
        }
    }

    /*Generate keyed hash of database password*/
    if (HMAC(EVP_sha512(), authStructPtr->HMACKey, EVP_MAX_KEY_LENGTH, (const unsigned char *)cryptoStructPtr->dbPass, strlen(cryptoStructPtr->dbPass), authStructPtr->KeyedHashdBPassGenerates, HMACLengthPtr) == NULL) {
        PRINT_ERROR("HMAC falied");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*Write keyed hash of database password and MAC of cipher-text/associated data then close file*/
    if (fwriteWErrCheck(authStructPtr->KeyedHashdBPassGenerates, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    if (fwriteWErrCheck(authStructPtr->MACcipherTextGenerates, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    if (fclose(dbFile) == EOF) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }

    /*Load the database as written so far into a buffer to generate a checksum*/
    dbFile = fopen(dbStructPtr->dbFileName, "rb");
    if (dbFile == NULL) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }
    chmod(dbStructPtr->dbFileName, S_IRUSR | S_IWUSR);

    fileBuffer = calloc(returnFileSize(dbStructPtr->dbFileName), sizeof(unsigned char));
    if (fileBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }

    if (freadWErrCheck(fileBuffer, sizeof(unsigned char), returnFileSize(dbStructPtr->dbFileName), dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    if (SHA512(fileBuffer, returnFileSize(dbStructPtr->dbFileName), authStructPtr->CheckSumDbFileGenerates) == NULL) {
        PRINT_ERROR("HMAC falied");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    free(fileBuffer);
    fileBuffer = NULL;

    if (fclose(dbFile) == EOF) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }

    /*Append the database checksum*/
    dbFile = fopen(dbStructPtr->dbFileName, "ab");
    if (dbFile == NULL) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }
    chmod(dbStructPtr->dbFileName, S_IRUSR | S_IWUSR);

    if (fwriteWErrCheck(authStructPtr->CheckSumDbFileGenerates, sizeof(unsigned char), MACSize, dbFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        exit(EXIT_FAILURE);
    }

    if (fclose(dbFile) == EOF) {
        PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
        exit(EXIT_FAILURE);
    }

    return 0;
}
