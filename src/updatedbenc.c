/* updatedbenc.c - updates cryptographic or master password for password database */

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

int updateDbEnc(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr)
{
    int evpOutputLength = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    long fileSize = cryptoStructPtr->evpDataSize, oldFileSize, newFileSize;

    unsigned char *decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if (decryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        goto cleanup;
    }

    /*Verify cipher-text loaded into cryptoSetingsPtr->encryptedBuffer by openDatabase*/
    if (verifyCiphertext(fileSize, cryptoStructPtr->encryptedBuffer, authStructPtr->HMACKeyOld, cryptoStructPtr->encCipherNameOld, cryptoStructPtr->scryptNFactorOld, cryptoStructPtr->scryptRFactorOld, cryptoStructPtr->scryptPFactorOld, cryptoStructPtr, authStructPtr) != 0) {
        printMACErrMessage(AUTHENTICATION_FAIL);
        goto cleanup;
    }

    /*Begin decryption*/
    EVP_DecryptInit(ctx, cryptoStructPtr->evpCipherOld, cryptoStructPtr->evpKeyOld, cryptoStructPtr->evpSalt);

    /*Decrypt cryptoStructPtr->encryptedBuffer and store into decryptedBuffer*/
    if (evpDecrypt(ctx, fileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, decryptedBuffer) != 0) {
        PRINT_ERROR("evpDecrypt");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }

    /*Clean up EVP cipher context*/
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Mark old filesize by assgning to evpOutputLength*/
    /*This is needed in case a block cipher was used and fileSize may not reflect actual size of decrypted database*/
    oldFileSize = evpOutputLength;

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    /*No need to run OPENSSL_cleanse since it is already encrypted*/
    free(cryptoStructPtr->encryptedBuffer);

    /*Allocate new buffer for encrypted information*/
    cryptoStructPtr->encryptedBuffer = calloc(sizeof(unsigned char), oldFileSize + EVP_MAX_BLOCK_LENGTH);
    if (cryptoStructPtr->encryptedBuffer == NULL) {
        PRINT_SYS_ERROR(errno);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }

    /*Creating a new databse with new salt, so also need new HMAC and EVP key derived from that salt*/
    if (genEvpSalt(cryptoStructPtr) != 0) {
        PRINT_ERROR("Could not update salt");
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }
    if (deriveKeys(cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not create new HMAC key");
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        goto cleanup;
    }

    /*Begin encryption of new database*/
    EVP_EncryptInit_ex(ctx, cryptoStructPtr->evpCipher, NULL, cryptoStructPtr->evpKey, cryptoStructPtr->evpSalt);

    if (evpEncrypt(ctx, oldFileSize, &evpOutputLength, cryptoStructPtr->encryptedBuffer, decryptedBuffer) != 0) {
        PRINT_ERROR("evpEncrypt failed");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize);
        goto cleanup;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    /*Assign size of evpOutputLength as the new file size*/
    /*This is needed in case a block cipher is used and new size may not simply be UI_BUFFERS_SIZE * 2*/
    newFileSize = evpOutputLength;
    cryptoStructPtr->evpDataSize = newFileSize;

    /*Clear sensitive data from decryptedBuffer ASAP*/
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize);

    /*Create MAC of cipher-text and associated data to sign with*/
    if (signCiphertext(newFileSize, cryptoStructPtr->encryptedBuffer, cryptoStructPtr, authStructPtr) != 0) {
        PRINT_ERROR("Could not sign ciphertext\n");
        goto cleanup;
    }

    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(ctx);
    ctx = NULL;

    return 0;

cleanup:
    free(decryptedBuffer);
    decryptedBuffer = NULL;
    free(ctx);
    ctx = NULL;
    return 1;
}
