/* macros.h - macros */

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

/*These are defined as macros so that they can print the line, function and filename of the error when expanded*/
#define PRINT_SYS_ERROR(errCode) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, strerror(errCode)); \
    }

#define PRINT_FILE_ERROR(fileName, errCode) \
    { \
        fprintf(stderr, "%s: %s (Line: %i)\n", fileName, strerror(errCode), __LINE__); \
    }

#define PRINT_ERROR(errMsg) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, errMsg); \
    }

/*General macros*/
#define UI_BUFFERS_SIZE 512

#define CRYPTO_HEADER_SIZE UI_BUFFERS_SIZE

#define EVP_SALT_SIZE 32

#define DEFAULT_GENPASS_LENGTH 16

/*Default scrypt parameters*/
#define DEFAULT_SCRYPT_N 1048576

#define DEFAULT_SCRYPT_R 8

#define DEFAULT_SCRYPT_P 1

/*Define integer values for MAC error messages*/
#define INTEGRITY_FAIL 0
#define AUTHENTICATION_FAIL 1
#define PASSWORD_FAIL 2
