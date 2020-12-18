/* parseoptions.c - parse command line options */

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

void parseOptions(int argc, char *argv[], struct cryptoVar *cryptoStructPtr, struct dbVar *dbStructPtr, struct textBuf *textBuffersStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int opt = 0;
    int errflg = 0;

    int i = 0;

    char optionsString[] = "s:w:t:l:f:u:n:d:a:r:p:x:c:hUPCIOEo";

    /*Process through arguments*/
    while ((opt = getopt(argc, argv, optionsString)) != -1) {
        switch (opt) {
        case 'h':
            printSyntax("passmanager");
            for (i = 1; i < argc; i++)
                OPENSSL_cleanse(argv[i], strlen(argv[i]));
            exit(EXIT_SUCCESS);
            break;
        case 'o':
            conditionsStruct->pipePasswordToStdout = true;
            conditionsStruct->sendToClipboard = false;
            break;
        case 'E':
            conditionsStruct->useExtendedRegex = true;
            break;
        case 'O':
            miscStructPtr->clipboardClearTimeMiliSeconds = 55;
            conditionsStruct->allowOnePasting = true;
            break;
        case 's':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -s requires an argument\n");
                errflg++;
            }
            if (strcmp("primary", optarg) == 0)
                conditionsStruct->selectionIsPrimary = true;
            else if (strcmp("clipboard", optarg) == 0) {
                conditionsStruct->selectionIsClipboard = true;
            }
            conditionsStruct->selectionGiven = true;
            break;
        case 't':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -t requires an argument\n");
                errflg++;
            }
            for (unsigned int i = 0; i < strlen(optarg); i++) {
                if (isdigit(optarg[i]))
                    break;
                fprintf(stderr, "Time specified needs a number\n");
                errflg++;
                break;
            }
            if (optarg[strlen(optarg) - 1] == 's' && optarg[strlen(optarg) - 2] == 'm') {
                optarg[strlen(optarg) - 2] = '\0';
                miscStructPtr->clipboardClearTimeMiliSeconds = atoi(optarg);
            } else if (optarg[strlen(optarg) - 1] == 's' && optarg[strlen(optarg) - 2] != 'm') {
                optarg[strlen(optarg) - 1] = '\0';
                miscStructPtr->clipboardClearTimeMiliSeconds = atoi(optarg) * 1000;
            } else if (isdigit(optarg[strlen(optarg) - 1])) {
                miscStructPtr->clipboardClearTimeMiliSeconds = atoi(optarg) * 1000;
            } else if (isalpha(optarg[strlen(optarg) - 1])) {
                fprintf(stderr, "Only 's' for seconds or 'ms' for miliseconds can be specified. Defaulting to seconds.\n");
                miscStructPtr->clipboardClearTimeMiliSeconds = atoi(optarg) * 1000;
            } else {
                fprintf(stderr, "Don't understand time format.\n");
                errflg++;
                break;
            }
            conditionsStruct->userChoseClipboardClearTime = true;
            break;
        case 'w':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -w requires an argument\n");
                errflg++;
                break;
            }

            /*First parse the N factor*/
            char *token = strtok(optarg, ",");
            if (token == NULL) {
                fprintf(stderr, "Could not parse scrypt work factors\n");
                errflg++;
                break;
            }

            /*Test if N factor is power of 2*/

            cryptoStructPtr->scryptNFactor = atoi(token);
            cryptoStructPtr->scryptNFactorStore = cryptoStructPtr->scryptNFactor;

            int testNumber = cryptoStructPtr->scryptNFactor;
            while (testNumber > 1) {
                if (testNumber % 2 != 0) {
                    /*Bitwise operation to round cryptoStructPtr->scryptNFactor up to the nearest power of 2*/
                    cryptoStructPtr->scryptNFactor--;
                    cryptoStructPtr->scryptNFactor |= cryptoStructPtr->scryptNFactor >> 1;
                    cryptoStructPtr->scryptNFactor |= cryptoStructPtr->scryptNFactor >> 2;
                    cryptoStructPtr->scryptNFactor |= cryptoStructPtr->scryptNFactor >> 4;
                    cryptoStructPtr->scryptNFactor |= cryptoStructPtr->scryptNFactor >> 8;
                    cryptoStructPtr->scryptNFactor |= cryptoStructPtr->scryptNFactor >> 16;
                    cryptoStructPtr->scryptNFactor++;
                    cryptoStructPtr->scryptNFactorStore = cryptoStructPtr->scryptNFactor;
                    fprintf(stderr, "scrypt's N factor must be a power of 2. Rounding it up to %i\n", cryptoStructPtr->scryptNFactor);
                    break;
                }
                testNumber /= 2;
            }

            /*Second parse the R factor*/
            token = strtok(NULL, ",");
            if (token == NULL) {
                fprintf(stderr, "Could not parse scrypt work factors\n");
                errflg++;
                break;
            }
            cryptoStructPtr->scryptRFactor = atoi(token);
            cryptoStructPtr->scryptRFactorStore = cryptoStructPtr->scryptRFactor;

            /*Third parse the P factor*/
            token = strtok(NULL, ",");
            if (token == NULL) {
                fprintf(stderr, "Could not parse scrypt work factors\n");
                errflg++;
                break;
            }
            cryptoStructPtr->scryptPFactor = atoi(token);
            cryptoStructPtr->scryptPFactorStore = cryptoStructPtr->scryptPFactor;

            conditionsStruct->userChoseScryptWorkFactors = true;
            break;
        case 'l':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -l requires an argument\n");
                errflg++;
                break;
            }
            miscStructPtr->genPassLength = atoi(optarg);
            if ((UI_BUFFERS_SIZE - 1) < miscStructPtr->genPassLength) {
                miscStructPtr->genPassLength = (UI_BUFFERS_SIZE - 1);
            }
            conditionsStruct->genPassLengthGiven = true;
            break;
        case 'U':
            conditionsStruct->updatingDbEnc = true;
            conditionsStruct->fileNeeded = true;
            break;
        case 'C':
#ifndef HAVE_LIBX11
            if (xselIsInstalled() == true)
                conditionsStruct->sendToClipboard = true;
            else {
                fprintf(stderr, "Program wasn't compiled with X11 headers and no executable xsel binary found. Will now quit to prevent password from being printed to screen.\n");
                /*Sanitize argv and argc of any sensitive information*/
                errflg++;
                break;
            }
#endif
#ifdef HAVE_LIBX11
            conditionsStruct->sendToClipboard = true;
#endif
			conditionsStruct->pipePasswordToStdout = false;
            break;
        case 'I':
            conditionsStruct->printingDbInfo = true;
            conditionsStruct->fileNeeded = true;
            break;
        case 'P':
            conditionsStruct->updatingEntryPass = true;
            break;
        case 'a':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -a requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->addingPass = true;
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\nentry name too long\n");
                errflg++;
                break;
            }
            snprintf(textBuffersStructPtr->entryName, UI_BUFFERS_SIZE, "%s", optarg);
            conditionsStruct->entryGiven = true;
            conditionsStruct->fileNeeded = true;
            break;
        case 'r':
            conditionsStruct->readingPass = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -r requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->searchForEntry = true;
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\nentry name too long\n");
                errflg++;
                break;
            }
            if (strcmp(optarg, "allpasses") == 0)
                conditionsStruct->printAllPasses = true;
            snprintf(textBuffersStructPtr->entryName, UI_BUFFERS_SIZE, "%s", optarg);
            conditionsStruct->entryGiven = true;
            conditionsStruct->fileNeeded = true;
            break;
        case 'd':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -d requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->deletingPass = true;
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\nentry name too long\n");
                errflg++;
                break;
            }
            snprintf(textBuffersStructPtr->entryName, UI_BUFFERS_SIZE, "%s", optarg);
            conditionsStruct->entryGiven = true;
            conditionsStruct->searchForEntry = true;
            conditionsStruct->fileNeeded = true;
            break;
        case 'c':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -c requires an argument\n");
                errflg++;
                break;
            }
            if (strcmp(optarg, "list") == 0) {
                /*Print a list of available ciphers*/
                OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encListCallback, NULL);
                for (i = 1; i < argc; i++)
                    OPENSSL_cleanse(argv[i], strlen(argv[i]));
                exit(EXIT_SUCCESS);
            }

            snprintf(cryptoStructPtr->encCipherName, NAME_MAX, "%s", optarg);
            snprintf(cryptoStructPtr->encCipherNameFromCmdLine, NAME_MAX, "%s", cryptoStructPtr->encCipherName);

            conditionsStruct->userChoseCipher = true;
            break;
        case 'f':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -f requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->fileGiven = true;
            snprintf(dbStructPtr->dbFileName, NAME_MAX, "%s", optarg);
            break;
        case 'n':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -n requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->searchForEntry = true;
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\nentry name too long\n");
                errflg++;
                break;
            }
            snprintf(textBuffersStructPtr->entryName, UI_BUFFERS_SIZE, "%s", optarg);
            conditionsStruct->entryGiven = true;
            break;
        case 'u':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -u requires an argument\n");
                errflg++;
                break;
            } else
                conditionsStruct->updatingEntry = true;
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\nentry name too long\n");
                errflg++;
                break;
            }
            if (strcmp(optarg, "allpasses") == 0)
                conditionsStruct->updateAllPasses = true;
            snprintf(textBuffersStructPtr->entryNameToFind, UI_BUFFERS_SIZE, "%s", optarg);
            conditionsStruct->fileNeeded = true;
            break;
        case 'p':
            conditionsStruct->entryPassGivenasArg = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -p requires an argument\n");
                errflg++;
                break;
            }
            if (strlen(optarg) > (UI_BUFFERS_SIZE - 1)) {
                fprintf(stderr, "\npassword too long\n");
                errflg++;
                break;
            }
            if (strcmp(optarg, "gen") == 0)
                conditionsStruct->generateEntryPass = true;
            if (strcmp(optarg, "genalpha") == 0)
                conditionsStruct->generateEntryPassAlpha = true;
            snprintf(textBuffersStructPtr->entryPass, UI_BUFFERS_SIZE, "%s", optarg);
            break;
        case 'x':
            conditionsStruct->dbPassGivenasArg = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -x requires an argument\n");
                errflg++;
                break;
            }
            snprintf(cryptoStructPtr->dbPass, UI_BUFFERS_SIZE, "%s", optarg);
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an argument\n", optopt);
            errflg++;
            break;
        case '?':
            errflg++;
            break;
        }
    }

    /*Sanitize argv and argc of any sensitive information*/
    for (i = 1; i < argc; i++)
        OPENSSL_cleanse(argv[i], strlen(argv[i]));

    /*If the user didn't specify a file with -f, and one was needed, set error flag on*/
    if (conditionsStruct->fileGiven == false && conditionsStruct->fileNeeded == true) {
        fprintf(stderr, "Must specify a database file with -f\n");
        errflg++;
    }

    /*Finally test for errflag and halt program if on*/
    if (errflg) {
        fprintf(stderr, "Use -h to print help\n");
        exit(EXIT_FAILURE);
    }
}
