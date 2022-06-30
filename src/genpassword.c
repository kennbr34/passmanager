/* genpassword.c - generates a random password */

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

/*Uses OpenSSL to generate a password with either all printable characters or only alphanumeric*/
int genPassWord(struct miscVar *miscStructPtr, struct textBuf *buffer, struct conditionBoolsStruct *conditionsStruct)
{
    if (conditionsStruct->genPassLengthGiven == false)
        miscStructPtr->genPassLength = DEFAULT_GENPASS_LENGTH;

    unsigned char randomByte = 0;
    char *tempPassString = calloc(sizeof(char), miscStructPtr->genPassLength + 1);
    int i = 0;

    while (i < miscStructPtr->genPassLength) {
        /*Gets a random byte from OpenSSL CSPRNG*/
        if (!RAND_bytes(&randomByte, 1)) {
            fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
            return 1;
        }

        if (conditionsStruct->generateEntryPass == true) {
            /*Tests that byte to be printable and not blank*/
            /*If it is it fills the temporary pass string buffer with that byte*/
            if ((isalnum(randomByte) != 0 || ispunct(randomByte) != 0) && isblank(randomByte) == 0) {
                tempPassString[i] = randomByte;
                i++;
            }
        }

        if (conditionsStruct->generateEntryPassAlpha == true) {
            if ((isupper(randomByte) != 0 || islower(randomByte) != 0 || isdigit(randomByte) != 0) && isblank(randomByte) == 0) {
                tempPassString[i] = randomByte;
                i++;
            }
        }
    }

    snprintf(buffer->entryPass, UI_BUFFERS_SIZE, "%s", tempPassString);
    OPENSSL_cleanse(tempPassString, sizeof(char) * (miscStructPtr->genPassLength + 1));
    free(tempPassString);
    tempPassString = NULL;
    
    return 0;
}
