/* main.c - password manager using OpenSSL crypto libraries */

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

int main(int argc, char *argv[])
{

    /*Print help if no arguments given*/
    if (argc == 1) {
        printSyntax(argv[0]);
        return 1;
    }

    /*Define structs and initialize to zero*/
    struct conditionBoolsStruct conditionsStruct = {0};
    struct cryptoVar cryptoStruct = {0};
    struct authVar authStruct = {0};
    struct dbVar dbStruct = {0};
    struct textBuf textBuffersStruct = {0};
    struct miscVar miscStruct = {0};

    /*Initialize scrypt factors*/
    cryptoStruct.scryptNFactor = DEFAULT_SCRYPT_N;
    cryptoStruct.scryptRFactor = DEFAULT_SCRYPT_R;
    cryptoStruct.scryptPFactor = DEFAULT_SCRYPT_P;

    /*Initialize backup file extention*/
    strcpy(dbStruct.backupFileExt, ".autobak");

    /*Initialize clipboard clear time*/
    miscStruct.clipboardClearTimeMiliSeconds = 30000;

    lockMemory();

    disablePtrace();

    allocateBuffers(&cryptoStruct, &authStruct, &textBuffersStruct);

    /*Point global buffers to sensitive bufers that need to be cleared in cleanUpBuffers*/
    globalBufferPtr.entryPass = textBuffersStruct.entryPass;
    globalBufferPtr.entryName = textBuffersStruct.entryName;
    globalBufferPtr.entryNameToFind = textBuffersStruct.entryNameToFind;
    globalBufferPtr.entryPassToVerify = textBuffersStruct.entryPassToVerify;
    globalBufferPtr.newEntry = textBuffersStruct.newEntry;
    globalBufferPtr.newEntryPass = textBuffersStruct.newEntryPass;
    globalBufferPtr.newEntryPassToVerify = textBuffersStruct.newEntryPassToVerify;
    globalBufferPtr.dbPass = cryptoStruct.dbPass;
    globalBufferPtr.dbPassOld = cryptoStruct.dbPassOld;
    globalBufferPtr.dbPassToVerify = cryptoStruct.dbPassToVerify;
    globalBufferPtr.masterKey = cryptoStruct.masterKey;
    globalBufferPtr.evpKey = cryptoStruct.evpKey;
    globalBufferPtr.evpKeyOld = cryptoStruct.evpKeyOld;
    globalBufferPtr.HMACKey = authStruct.HMACKey;
    globalBufferPtr.HMACKeyOld = authStruct.HMACKeyOld;
    globalBufferPtr.evpSalt = cryptoStruct.evpSalt;
    globalBufferPtr.encryptedBuffer = cryptoStruct.encryptedBuffer;

    atexit(cleanUpBuffers);

    signal(SIGINT, signalHandler);

    FILE *dbFile = NULL;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdListCallback() and encListCallback() functions to work*/
    OpenSSL_add_all_algorithms();

    parseOptions(argc, argv, &cryptoStruct, &dbStruct, &textBuffersStruct, &miscStruct, &conditionsStruct);

    /*Test if database is being initialized and if not if it is readable*/
    if (fileNonExistant(dbStruct.dbFileName) == true) {
        conditionsStruct.databaseBeingInitalized = true;
    } else {
        dbFile = fopen(dbStruct.dbFileName, "rb");
        if (dbFile == NULL) {
            PRINT_FILE_ERROR(dbStruct.dbFileName, errno);
            exit(EXIT_FAILURE);
        }
        if (fclose(dbFile) == EOF) {
            PRINT_FILE_ERROR(dbStruct.dbFileName, errno);
            exit(EXIT_FAILURE);
        }
    }

    if (conditionsStruct.printingDbInfo == true) { /*Just print the database information*/
        if (conditionsStruct.databaseBeingInitalized == false) {
            openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);
        } else {
            fprintf(stderr, "Database file not initialized\n");
            exit(EXIT_FAILURE);
        }

        printDbInfo(&cryptoStruct, &authStruct);

        return EXIT_SUCCESS;
    } else if (conditionsStruct.addingPass == true) /*This mode will add an entry*/
    {

        /*If generating a random password was specified on command line*/
        if (strcmp(textBuffersStruct.entryPass, "gen") == 0) {
            conditionsStruct.generateEntryPass = true;
            if (conditionsStruct.genPassLengthGiven == true)
                genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
            else
                genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
        } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
            conditionsStruct.generateEntryPassAlpha = true;
            if (conditionsStruct.genPassLengthGiven == true)
                genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
            else
                genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
        } else if (conditionsStruct.entryPassGivenasArg == false) {
            /*Prompt for entry password*/
            getPass("Enter entry password to be saved: ", textBuffersStruct.entryPass);

            /*If user entered gen or genalpha at prompt*/
            if (strcmp(textBuffersStruct.entryPass, "gen") == 0) {
                conditionsStruct.generateEntryPass = true;
                fprintf(stderr, "\nGenerating a random password\n");
                if (conditionsStruct.genPassLengthGiven == true)
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                else
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
            } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
                conditionsStruct.generateEntryPassAlpha = true;
                fprintf(stderr, "\nGenerating a random password\n");
                if (conditionsStruct.genPassLengthGiven == true)
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                else
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
            } else {
                /*Verify user gentered password if not gen or genalpha*/
                getPass("Verify password:", textBuffersStruct.entryPassToVerify);
                if (strcmp(textBuffersStruct.entryPass, textBuffersStruct.entryPassToVerify) != 0) {
                    fprintf(stderr, "\nPasswords do not match.  Nothing done.\n\n");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /*Prompt for database password if not supplied as argument*/
        if (conditionsStruct.dbPassGivenasArg == false) {
            getPass("Enter database password to encode with: ", cryptoStruct.dbPass);

            /*Verify the database password if the database is being intialized*/
            if (conditionsStruct.databaseBeingInitalized == true) {
                getPass("Verify password:", cryptoStruct.dbPassToVerify);
                if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                    fprintf(stderr, "\nPasswords do not match.  Nothing done.\n\n");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /*Note this will be needed before openDatabase() is called in all modes except Read*/
        configEvp(&cryptoStruct, &conditionsStruct);

        /*If password database has been initialized openDatabase on it*/
        if (conditionsStruct.databaseBeingInitalized == false) {
            openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);
        } else { /*Otherwise key material must be created now*/
            if (genEvpSalt(&cryptoStruct) != 0) {
                PRINT_ERROR("Could not create salt");
                exit(EXIT_FAILURE);
            }
            if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                PRINT_ERROR("Could not create master key");
                exit(EXIT_FAILURE);
            }
        }

        /*Adds the new enry and sends it to encryptedBuffer*/
        if (addEntry(&cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct) == 0) {
            writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);
        }

    } else if (conditionsStruct.readingPass == true) /*This will read a password or passwords*/
    {

        if (conditionsStruct.dbPassGivenasArg == false) {
            getPass("Enter database password: ", cryptoStruct.dbPass);
        }

        /*Note no configEvp() needed before openDatabase() in Read mode*/
        openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);

        if (conditionsStruct.searchForEntry == true && strcmp(textBuffersStruct.entryName, "allpasses") != 0) /*Print entry or entries that match searchString*/
        {
            printEntry(textBuffersStruct.entryName, &cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct); /*Decrypt and print pass specified by textBuffersStruct.entryName*/
        } else if (conditionsStruct.searchForEntry == true && conditionsStruct.printAllPasses == true)
            printEntry(NULL, &cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct); /*Decrypt and print all passess*/

    } else if (conditionsStruct.deletingPass == true) /*Delete a specified entry*/
    {
        if (conditionsStruct.dbPassGivenasArg == false) {
            getPass("Enter database password: ", cryptoStruct.dbPass);
        }

        /*Must specify an entry to delete*/
        if (conditionsStruct.entryGiven == false) /*Fail if no entry specified*/
        {
            fprintf(stderr, "\nNo entry name was specified\n");
            exit(EXIT_FAILURE);
        }

        configEvp(&cryptoStruct, &conditionsStruct);

        openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);

        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified into encryptedBuffer*/
        if (deleteEntry(textBuffersStruct.entryName, &cryptoStruct, &authStruct, &dbStruct, &conditionsStruct) == 0)
            writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);

    } else if (conditionsStruct.updatingEntry == true) /*Update an entry or entries*/
    {

        if (conditionsStruct.dbPassGivenasArg == false) {
            getPass("Enter database password: ", cryptoStruct.dbPass);
        }

        /*Get new entry name*/
        if (conditionsStruct.entryGiven == true) {
            snprintf(textBuffersStruct.newEntry, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryName);
        } else {
            /*If no new entry name was specified then just update the password*/
            snprintf(textBuffersStruct.newEntry, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryNameToFind);
            conditionsStruct.updatingEntryPass = true;
        }

        /*If entry password to update to was supplied by command line argument*/
        if (conditionsStruct.entryPassGivenasArg == true)
            conditionsStruct.updatingEntryPass = true;

        /*Get new pass*/
        if (conditionsStruct.updatingEntryPass) {
            /*If textBuffersStruct.entryPass supplied by command line, and generated randomly if it is 'gen'*/
            if (strcmp(textBuffersStruct.entryPass, "gen") == 0) {
                if (conditionsStruct.genPassLengthGiven == true) {
                    conditionsStruct.generateEntryPass = true;
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                    /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                } else {
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                }
            } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
                conditionsStruct.generateEntryPassAlpha = true;
                if (conditionsStruct.genPassLengthGiven == true) {
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                    /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                } else {
                    genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                }
            } else if (conditionsStruct.entryPassGivenasArg == false) {
                getPass("Enter entry password to be saved: ", textBuffersStruct.newEntryPass);

                /*If password retrieved by prompt was gen/genalpha generate a random password*/
                if (strcmp(textBuffersStruct.newEntryPass, "gen") == 0) {
                    conditionsStruct.generateEntryPass = true;
                    fprintf(stderr, "\nGenerating a random password\n");
                    if (conditionsStruct.genPassLengthGiven == true) {
                        genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                        /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                        snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                    } else {
                        genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                        snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                    }
                } else if (strcmp(textBuffersStruct.newEntryPass, "genalpha") == 0) {
                    conditionsStruct.generateEntryPassAlpha = true;
                    fprintf(stderr, "\nGenerating a random password\n");
                    if (conditionsStruct.genPassLengthGiven == true) {
                        genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                        /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                        snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                    } else {
                        genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct);
                        snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                    }
                } else {
                    /*If retrieved password was not gen/genalpha verify it was not mistyped*/
                    getPass("Veryify password:", textBuffersStruct.newEntryPassToVerify);
                    if (strcmp(textBuffersStruct.newEntryPass, textBuffersStruct.newEntryPassToVerify) != 0) {
                        fprintf(stderr, "\nPasswords do not match.  Nothing done.\n\n");
                        return 1;
                    }
                }
            } else if (conditionsStruct.entryPassGivenasArg == true) /*This condition is true if the user DID supply a password but it isn't 'gen'*/
            {
                snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
            }
        }

        configEvp(&cryptoStruct, &conditionsStruct);

        openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);

        /*Works like deleteEntry() but instead of excluding matched entry, modfies its buffer values and then writes it to encryptedBuffer*/
        if (updateEntry(textBuffersStruct.entryNameToFind, &cryptoStruct, &authStruct, &textBuffersStruct, &dbStruct, &miscStruct, &conditionsStruct) == 0) {
            writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);
        }
    } else if (conditionsStruct.updatingDbEnc == true) { /*Updates the database password, cipher algorithm, or scrypt configuration of the database*/

        if (conditionsStruct.dbPassGivenasArg == false) {
            getPass("Enter current database password: ", cryptoStruct.dbPass);
        }

        openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);

        /*Must store old key data before new key material is generated*/
        snprintf(cryptoStruct.dbPassOld, UI_BUFFERS_SIZE, "%s", cryptoStruct.dbPass);
        memcpy(authStruct.HMACKeyOld, authStruct.HMACKey, sizeof(char) * EVP_MAX_KEY_LENGTH);
        memcpy(cryptoStruct.evpKeyOld, cryptoStruct.evpKey, sizeof(char) * EVP_MAX_KEY_LENGTH);
        cryptoStruct.evpCipherOld = cryptoStruct.evpCipher;
        strcpy(cryptoStruct.encCipherNameOld, cryptoStruct.encCipherName);
        cryptoStruct.scryptNFactorOld = cryptoStruct.scryptNFactor;
        cryptoStruct.scryptRFactorOld = cryptoStruct.scryptRFactor;
        cryptoStruct.scryptPFactorOld = cryptoStruct.scryptPFactor;

        /*If -w was given along with nothing else*/
        if (conditionsStruct.userChoseScryptWorkFactors == true && (conditionsStruct.updatingEntryPass == false && conditionsStruct.userChoseCipher == false)) {
            cryptoStruct.scryptNFactor = cryptoStruct.scryptNFactorStore;
            cryptoStruct.scryptRFactor = cryptoStruct.scryptRFactorStore;
            cryptoStruct.scryptPFactor = cryptoStruct.scryptPFactorStore;
            fprintf(stderr, "Scrypt work factors changed to N=%i,r=%i,p=%i\n", cryptoStruct.scryptNFactor, cryptoStruct.scryptRFactor, cryptoStruct.scryptPFactor);
        }
        /*If -U was given but not -c*/
        else if (conditionsStruct.updatingDbEnc == true && (conditionsStruct.userChoseCipher == false)) {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", cryptoStruct.dbPass);

            getPass("Verify password:", cryptoStruct.dbPassToVerify);
            if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                fprintf(stderr, "Passwords don't match, not changing.\n");
                exit(EXIT_FAILURE);
            } else {
                fprintf(stderr, "Changed password.\n");
                if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                    PRINT_ERROR("Could not derive HMAC key");
                    exit(EXIT_FAILURE);
                }
            }

            /*Change cipher if specified*/
            if (conditionsStruct.userChoseCipher == true) {
                snprintf(cryptoStruct.encCipherName, NAME_MAX, "%s", cryptoStruct.encCipherNameFromCmdLine);
                fprintf(stderr, "Changing cipher to %s\n", cryptoStruct.encCipherNameFromCmdLine);
            }
        }
        /*-U was given but not -P and -c*/
        else if (conditionsStruct.updatingDbEnc == true && conditionsStruct.updatingEntryPass == false) {
            if (conditionsStruct.userChoseCipher == true) {
                snprintf(cryptoStruct.encCipherName, NAME_MAX, "%s", cryptoStruct.encCipherNameFromCmdLine);
                fprintf(stderr, "Changing cipher to %s\n", cryptoStruct.encCipherNameFromCmdLine);
            }
        }
        /*If -P is given along with -c*/
        else {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", cryptoStruct.dbPass);

            getPass("Verify password:", cryptoStruct.dbPassToVerify);
            if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                fprintf(stderr, "Passwords don't match, not changing.\n");
                exit(EXIT_FAILURE);
            } else {
                fprintf(stderr, "Changed password.\n");
                if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                    PRINT_ERROR("Could not derive HMAC key");
                    exit(EXIT_FAILURE);
                }
            }

            /*Change cipher algorithm*/
            if (conditionsStruct.userChoseCipher == true) {
                snprintf(cryptoStruct.encCipherName, NAME_MAX, "%s", cryptoStruct.encCipherNameFromCmdLine);
                fprintf(stderr, "Changing cipher to %s\n", cryptoStruct.encCipherNameFromCmdLine);
            }
        }

        /*Change scrypt configuration*/
        if (conditionsStruct.userChoseScryptWorkFactors == true && (conditionsStruct.updatingEntryPass == true || conditionsStruct.userChoseCipher == true)) {
            cryptoStruct.scryptNFactor = cryptoStruct.scryptNFactorStore;
            cryptoStruct.scryptRFactor = cryptoStruct.scryptRFactorStore;
            cryptoStruct.scryptPFactor = cryptoStruct.scryptPFactorStore;
            fprintf(stderr, "Scrypt work factors changed to N=%i,r=%i,p=%i\n", cryptoStruct.scryptNFactor, cryptoStruct.scryptRFactor, cryptoStruct.scryptPFactor);
        }

        /*This will change to the cipher just specified*/
        configEvp(&cryptoStruct, &conditionsStruct);

        /*The updatingDbEnc function decrypts with the old key and cipher settings, re-encrypts with new key and/or cipher settings then writes to encryptedBuffer*/
        if (updateDbEnc(&cryptoStruct, &authStruct) == 0) {
            writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct);
        }

    } else { /*If the user didn't specify an operation mode, and didn't use '-c list'*/
        fprintf(stderr, "Must use -a,-r,-d,-u or -U\nUse -h t print help\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
