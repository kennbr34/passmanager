/* misc.c - miscellaneous helper functions */

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

/*A wrapper to run fread with error checking*/
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct miscVar *miscStructPtr)
{
    /* 
	 * From glibc manual: On  success,  fread()  and fwrite() return the number of items read or written.  
	 * This number equals the number of bytes transferred only when size is 1.  
	 * If an error occurs, or the end of the file is reached, the return value is a short item count (or zero).
	 * 
	 * The number of items read/written will always equal nmemb / size 
	 * unless EOF was reached before that, or if some other error occured 
	 */
    if (fread(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            miscStructPtr->returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            miscStructPtr->returnVal = errno;
            return errno;
        }
    }

    return 0;
}

/*A wrapper to run fwrite with error checking*/
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct miscVar *miscStructPtr)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            miscStructPtr->returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            miscStructPtr->returnVal = errno;
            return errno;
        }
    }

    return 0;
}

/*This will run memcpy() in constant time*/
int constTimeMemCmp(const void *in_a, const void *in_b, size_t len)
{
    /*This is CRYPTO_memcmp from cryptlib.c in OpenSSL 1.1.*/
    /*Added here for backward-compatability to OpenSSL 1.0.1*/
    size_t i = 0;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

/*Returns TRUE if xsel binary is found in $PATH*/
bool xselIsInstalled(void)
{
    char *pathBuffer = NULL;
    char pathString[NAME_MAX] = {0}, pathToCheck[NAME_MAX] = {0};
    char *token = NULL;
    struct stat sb;

    pathBuffer = (char *)getenv("PATH");

    snprintf(pathString, NAME_MAX, "%s", pathBuffer);

    token = strtok(pathString, ":");
    if (token == NULL) {
        fprintf(stderr, "Could not parse $PATH\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        snprintf(pathToCheck, NAME_MAX, "%s/xsel", token);

        /* Use stat to check if the binary exists and is executable by current user*/
        if (stat(pathToCheck, &sb) == 0 && sb.st_mode & S_IXUSR) {
            return true;
        } else {
            token = strtok(NULL, ":");
            if (token == NULL)
                break;
            continue;
        }
    }

    return false;
}

/*Returns FALSE if the file exists*/
bool fileNonExistant(const char *filename)
{
    struct stat st;
    int result = stat(filename, &st);
    return result;
}

/*Returns filesize of file named by in filename*/
int returnFileSize(const char *filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

/*Lists available encryption algorithms in OpenSSL's EVP library*/
void encListCallback(const OBJ_NAME *obj, void *arg)
{
    /*I don't want to use -Wno-unused-parameter to suppress compiler warnings*/
    /*So this does nothing with it to make gcc think it did something*/
    arg = arg;

    fprintf(stderr, "Cipher: %s\n", obj->name);
}

/*Handles interrupt signal*/
void signalHandler(int signum)
{
    fprintf(stderr, "\nCaught signal %d\n\nCleaning up buffers...\n", signum);

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);

    /*Terminate program with exit() so that atexit() runs cleanUpBuffers()*/
    exit(signum);
}

int regExComp(char *regexPattern, char *stringToCompare, int cflags)
{
    int returnValue;

    regex_t regex;
    char regexErrMsg[100];

    /*Compile regular expression and return -1 if failure*/
    returnValue = regcomp(&regex, regexPattern, cflags);
    if (returnValue != 0) {
        regerror(returnValue, &regex, regexErrMsg, sizeof(regexErrMsg));
        /*Print error that occured*/
        fprintf(stderr, "Regex compilation failed: %s\n", regexErrMsg);
        regfree(&regex);
        return -1;
    }

    /*Compare regular expression with string, return 0 if match found, REG_NOMATCH if not, and something else if an error*/
    returnValue = regexec(&regex, stringToCompare, 0, NULL, 0);
    if (returnValue == 0) {
        regfree(&regex);
        return 0;
    } else if (returnValue == REG_NOMATCH) {
        regfree(&regex);
        return 1;
    } else {
        regerror(returnValue, &regex, regexErrMsg, sizeof(regexErrMsg));
        /*Print error that occured*/
        fprintf(stderr, "Regex match failed: %s\n", regexErrMsg);
        regfree(&regex);
        return -1;
    }
}
