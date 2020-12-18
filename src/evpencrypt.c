/* evpencrypt.c - function for encrypting via EVP library */

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

/* OpenSSl's evp encryption routines.
 * This will handle multiple different ciphers in different operational modes
 * I.e. CBC, CTR, OFB, etc.
 * Must use local versions of global buffers so that old and new buffers can be used on database update
 */

/*Named encryptedBufferLcl and decryptedBufferLcl to not be confused with the global encrypedBuffer*/
int evpEncrypt(EVP_CIPHER_CTX *ctx, int evpInputLength, int *evpOutputLength, unsigned char *encryptedBufferLcl, unsigned char *decryptedBufferLcl)
{
    /*This will hold the updated length after EVP_EncryptFinal_ex*/
    int evpLengthUpdate = 0;

    if (!EVP_EncryptUpdate(ctx, encryptedBufferLcl, evpOutputLength, decryptedBufferLcl, evpInputLength)) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBufferLcl, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);

        return 1;
    }

    /*This will do the last bit of encryption for block ciphers*/
    /*For stream ciphers it will not do anything*/
    if (!EVP_EncryptFinal_ex(ctx, encryptedBufferLcl + *evpOutputLength, &evpLengthUpdate)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBufferLcl, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);

        return 1;
    }

    /*evpLengthUpdate will contain the added padding information from any block cipher operation to evpOutputLength*/
    /*For stream ciphers it will not add anything*/
    *evpOutputLength += evpLengthUpdate;

    return 0;
}
