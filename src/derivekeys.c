/* derivekeys.c - derives master key and splits it up for HMAC and encryption algorithm */

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

/* Uses scrypt to generate a large key and then splits it in half
 * First half is used as the encryption key
 * Second half is used as the authentication key
 */
int deriveKeys(struct cryptoVar *cryptoStructPtr, struct authVar *authStructPtr)
{

    /*Use scrypt to derive a master key*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = EVP_MAX_KEY_LENGTH * 2;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, cryptoStructPtr->dbPass, strlen(cryptoStructPtr->dbPass)) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, cryptoStructPtr->evpSalt, EVP_SALT_SIZE) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, cryptoStructPtr->scryptNFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, cryptoStructPtr->scryptRFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, cryptoStructPtr->scryptPFactor) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    if (EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, checkFreeMem()) <= 0)
        return 1;
        
    if (checkNeededMem(cryptoStructPtr) != 0)
        return 1;
    
    if (EVP_PKEY_derive(pctx, cryptoStructPtr->masterKey, &outlen) <= 0) {
        PRINT_ERROR("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_PKEY_CTX_free(pctx);

    /*Copy halves of cryptoStructPtr->masterKey into cryptoStructPtr->evpKey and authStructPtr->HMACKey respectively*/
    memcpy(cryptoStructPtr->evpKey, cryptoStructPtr->masterKey, EVP_MAX_KEY_LENGTH);
    memcpy(authStructPtr->HMACKey, cryptoStructPtr->masterKey + EVP_MAX_KEY_LENGTH, EVP_MAX_KEY_LENGTH);

    return 0;
}
