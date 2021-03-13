/* globals.h - global variables */

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

/*Global buffer pointers needed to be able to sanitize and free sensitive buffers in cleanUpBuffers registered with atexit*/
struct bufferPointers {
    char *entryPass;
    char *entryName;
    char *entryNameToFind;
    char *entryPassToVerify;
    char *newEntry;
    char *newEntryPass;
    char *newEntryPassToVerify;
    char *dbPass;
    char *dbPassOld;
    char *dbPassToVerify;
    unsigned char *masterKey;
    unsigned char *evpKey;
    unsigned char *evpKeyOld;
    unsigned char *HMACKey;
    unsigned char *HMACKeyOld;
    unsigned char *evpSalt;
    unsigned char *encryptedBuffer;
};

struct bufferPointers globalBufferPtr;

/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
/*Need to be global to register signalHandler() with sigaction*/
struct termios termiosOld, termiosNew;
