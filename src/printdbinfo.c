/* printdbinfo.c - prints information about password database file */

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

/*Prints general information about the password database*/
void printDbInfo(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr)
{
    fprintf(stdout, "Number of entries in database: %i\n", cryptoStructPtr->evpDataSize / (UI_BUFFERS_SIZE * 2));
    fprintf(stdout, "scrypt configuration:\n");
    fprintf(stdout, "\tSalt:");
    for (int i = 0; i < EVP_SALT_SIZE; i++) {
        fprintf(stdout, "%02x", cryptoStructPtr->evpSalt[i] & 0xff);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "\tN factor: %i\n", cryptoStructPtr->scryptNFactor);
    fprintf(stdout, "\tr factor: %i\n", cryptoStructPtr->scryptRFactor);
    fprintf(stdout, "\tp factor: %i\n", cryptoStructPtr->scryptPFactor);
    fprintf(stdout, "Encryption configuration: %s \n\tAlgorithm: ", cryptoStructPtr->encCipherName);
    if (strncmp(cryptoStructPtr->encCipherName, "aes", 3) == 0)
        fprintf(stdout, "AES\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "bf", 2) == 0 || strcmp(cryptoStructPtr->encCipherName, "blowfish") == 0)
        fprintf(stdout, "Blowfish\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "rc2", 3) == 0)
        fprintf(stdout, "RC2\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "rc4", 3) == 0)
        fprintf(stdout, "RC4\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "sm4", 3) == 0)
        fprintf(stdout, "SM4\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "des", 3) == 0)
        fprintf(stdout, "DES\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "cast", 4) == 0)
        fprintf(stdout, "CAST\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "aria", 4) == 0)
        fprintf(stdout, "Aria\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "camellia", 8) == 0)
        fprintf(stdout, "Camellia\n");
    else if (strncmp(cryptoStructPtr->encCipherName, "chacha20", 8) == 0)
        fprintf(stdout, "Cha-Cha20\n");
    switch (EVP_CIPHER_mode(EVP_get_cipherbyname(cryptoStructPtr->encCipherName))) {
    case EVP_CIPH_CBC_MODE:
        fprintf(stdout, "\tMode: Cipher Block Chaining\n");
        break;
    case EVP_CIPH_ECB_MODE:
        fprintf(stdout, "\tMode: Electronic Code Book\n");
        break;
    case EVP_CIPH_CTR_MODE:
        fprintf(stdout, "\tMode: Counter\n");
        break;
    case EVP_CIPH_OFB_MODE:
        fprintf(stdout, "\tMode: Output Feedback\n");
        break;
    case EVP_CIPH_CFB_MODE:
        fprintf(stdout, "\tMode: Cipher Feedback\n");
        break;
    case EVP_CIPH_STREAM_CIPHER:
        fprintf(stdout, "\tMode: Sream\n");
        break;
    default:
        fprintf(stdout, "\tMode: Unkonwn\n");
        break;
    }
    fprintf(stdout, "\tBlock Size: %i bits\n", EVP_CIPHER_block_size(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) * 8);
    fprintf(stdout, "\tKey Size: %i bits\n", EVP_CIPHER_key_length(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) * 8);
    fprintf(stdout, "\tIV Size: %i bits\n", EVP_CIPHER_iv_length(EVP_get_cipherbyname(cryptoStructPtr->encCipherName)) * 8);
    fprintf(stdout, "Ciphertext+Associated Data MAC:\n\t");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        fprintf(stdout, "%02x", authStructPtr->MACcipherTextSignedWith[i] & 0xff);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "Database Password Keyed Hash:\n\t");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        fprintf(stdout, "%02x", authStructPtr->KeyedHashdBPassSignedWith[i] & 0xff);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "Database Checksum:\n\t");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        fprintf(stdout, "%02x", authStructPtr->CheckSumDbFileSignedWith[i] & 0xff);
    }
    fprintf(stdout, "\n");
}
