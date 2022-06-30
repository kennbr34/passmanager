/* main.c - password manager using OpenSSL crypto libraries */

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

    FILE *dbFile = NULL;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdListCallback() and encListCallback() functions to work*/
    OpenSSL_add_all_algorithms();

    if( parseOptions(argc, argv, &cryptoStruct, &dbStruct, &textBuffersStruct, &miscStruct, &conditionsStruct) != 0 ) {
        goto error;
    }

    /*Test if database is being initialized and if not if it is readable*/
    if (fileNonExistant(dbStruct.dbFileName) == true) {
        conditionsStruct.databaseBeingInitalized = true;
    } else {
        dbFile = fopen(dbStruct.dbFileName, "rb");
        if (dbFile == NULL) {
            PRINT_FILE_ERROR(dbStruct.dbFileName, errno);
            goto error;
        }
        if (fclose(dbFile) == EOF) {
            PRINT_FILE_ERROR(dbStruct.dbFileName, errno);
            goto error;
        }
    }

    if (conditionsStruct.printingDbInfo == true) { /*Just print the database information*/
        if (conditionsStruct.databaseBeingInitalized == false) {
            if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else {
            fprintf(stderr, "Database file not initialized\n");
            goto error;
        }

        printDbInfo(&cryptoStruct, &authStruct);

        goto error;
    } else if (conditionsStruct.addingPass == true) /*This mode will add an entry*/
    {

        /*If generating a random password was specified on command line*/
        if (strcmp(textBuffersStruct.entryPass, "gen") == 0) {
            conditionsStruct.generateEntryPass = true;
            if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
            conditionsStruct.generateEntryPassAlpha = true;
            if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else if (conditionsStruct.entryPassGivenasArg == false) {
            /*Prompt for entry password*/
            if (getPass("Enter entry password to be saved: ", textBuffersStruct.entryPass) != 0) {
                goto error;
            }

            /*If user entered gen or genalpha at prompt*/
            if (strcmp(textBuffersStruct.entryPass, "gen") == 0) {
                conditionsStruct.generateEntryPass = true;
                fprintf(stderr, "\nGenerating a random password\n");
                if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                    goto error;
                }
            } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
                conditionsStruct.generateEntryPassAlpha = true;
                fprintf(stderr, "\nGenerating a random password\n");
                if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                    goto error;
                }
            } else {
                /*Verify user gentered password if not gen or genalpha*/
                if (getPass("Verify password:", textBuffersStruct.entryPassToVerify) != 0) {
                    goto error;
                }
                if (strcmp(textBuffersStruct.entryPass, textBuffersStruct.entryPassToVerify) != 0) {
                    fprintf(stderr, "\nPasswords do not match.  Nothing done.\n\n");
                    goto error;
                }
            }
        }

        /*Prompt for database password if not supplied as argument*/
        if (conditionsStruct.dbPassGivenasArg == false) {
            if (getPass("Enter database password to encode with: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }

            /*Verify the database password if the database is being intialized*/
            if (conditionsStruct.databaseBeingInitalized == true) {
                if (getPass("Verify password:", cryptoStruct.dbPassToVerify) != 0) {
                    goto error;
                }
                if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                    fprintf(stderr, "\nPasswords do not match.  Nothing done.\n\n");
                    goto error;
                }
            }
        }

        /*Note this will be needed before openDatabase() is called in all modes except Read*/
        if (configEvp(&cryptoStruct, &conditionsStruct) != 0) { 
            goto error;
        }

        /*If password database has been initialized openDatabase on it*/
        if (conditionsStruct.databaseBeingInitalized == false) {
            if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else { /*Otherwise key material must be created now*/
            if (genEvpSalt(&cryptoStruct) != 0) {
                PRINT_ERROR("Could not create salt");
                goto error;
            }
            if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                PRINT_ERROR("Could not create master key");
                goto error;
            }
        }

        /*Adds the new enry and sends it to encryptedBuffer*/
        if (addEntry(&cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct) == 0) {
            if (writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else {
            goto error;
        }

    } else if (conditionsStruct.readingPass == true) /*This will read a password or passwords*/
    {

        if (conditionsStruct.dbPassGivenasArg == false) {
            if (getPass("Enter database password: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }
        }

        /*Note no configEvp() needed before openDatabase() in Read mode*/
        if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
            goto error;
        }

        if (conditionsStruct.searchForEntry == true && strcmp(textBuffersStruct.entryName, "allpasses") != 0) /*Print entry or entries that match searchString*/
        {
            printEntry(textBuffersStruct.entryName, &cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct); /*Decrypt and print pass specified by textBuffersStruct.entryName*/
        } else if (conditionsStruct.searchForEntry == true && conditionsStruct.printAllPasses == true)
            printEntry(NULL, &cryptoStruct, &authStruct, &textBuffersStruct, &miscStruct, &conditionsStruct); /*Decrypt and print all passess*/

    } else if (conditionsStruct.deletingPass == true) /*Delete a specified entry*/
    {
        if (conditionsStruct.dbPassGivenasArg == false) {
            if (getPass("Enter database password: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }
        }

        /*Must specify an entry to delete*/
        if (conditionsStruct.entryGiven == false) /*Fail if no entry specified*/
        {
            fprintf(stderr, "\nNo entry name was specified\n");
            goto error;
        }

        if (configEvp(&cryptoStruct, &conditionsStruct) != 0) { 
            goto error;
        }

        if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
            goto error;
        }

        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified into encryptedBuffer*/
        if (deleteEntry(textBuffersStruct.entryName, &cryptoStruct, &authStruct, &dbStruct, &conditionsStruct) == 0) {
            if (writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else {
            goto error;
        }

    } else if (conditionsStruct.updatingEntry == true) /*Update an entry or entries*/
    {

        if (conditionsStruct.dbPassGivenasArg == false) {
            if (getPass("Enter database password: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }
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
                conditionsStruct.generateEntryPass = true;
                if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                    goto error;
                }
                /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
            } else if (strcmp(textBuffersStruct.entryPass, "genalpha") == 0) {
                conditionsStruct.generateEntryPassAlpha = true;
                if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                    goto error;
                }
                /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
            } else if (conditionsStruct.entryPassGivenasArg == false) {
                if (getPass("Enter entry password to be saved: ", textBuffersStruct.newEntryPass) != 0) {
                    goto error;
                }

                /*If password retrieved by prompt was gen/genalpha generate a random password*/
                if (strcmp(textBuffersStruct.newEntryPass, "gen") == 0) {
                    conditionsStruct.generateEntryPass = true;
                    fprintf(stderr, "\nGenerating a random password\n");
                    if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                        goto error;
                    }
                    /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                } else if (strcmp(textBuffersStruct.newEntryPass, "genalpha") == 0) {
                    conditionsStruct.generateEntryPassAlpha = true;
                    fprintf(stderr, "\nGenerating a random password\n");
                    if (genPassWord(&miscStruct, &textBuffersStruct, &conditionsStruct) != 0) {
                        goto error;
                    }
                    /*Have to copy over textBuffersStruct.entryPass to textBuffersStruct.newEntryPass since genPassWord() operates on textBuffersStruct.entryPass buffer*/
                    snprintf(textBuffersStruct.newEntryPass, UI_BUFFERS_SIZE, "%s", textBuffersStruct.entryPass);
                } else {
                    /*If retrieved password was not gen/genalpha verify it was not mistyped*/
                    if (getPass("Veryify password:", textBuffersStruct.newEntryPassToVerify) != 0) {
                        goto error;
                    }
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

        if (configEvp(&cryptoStruct, &conditionsStruct) != 0) {
            goto error;
        }

        if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
            goto error;
        }

        /*Works like deleteEntry() but instead of excluding matched entry, modfies its buffer values and then writes it to encryptedBuffer*/
        if (updateEntry(textBuffersStruct.entryNameToFind, &cryptoStruct, &authStruct, &textBuffersStruct, &dbStruct, &miscStruct, &conditionsStruct) == 0) {
            if (writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else {
            goto error;
        }
    } else if (conditionsStruct.updatingDbEnc == true) { /*Updates the database password, cipher algorithm, or scrypt configuration of the database*/

        if (conditionsStruct.dbPassGivenasArg == false) {
            if (getPass("Enter current database password: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }
        }

        if (openDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
            goto error;
        }

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
            if (getPass("Enter new database password: ", cryptoStruct.dbPass) != 0) {
                goto error;
            }

            if (getPass("Verify password:", cryptoStruct.dbPassToVerify) != 0) {
                goto error;
            }
            if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                fprintf(stderr, "Passwords don't match, not changing.\n");
                goto error;
            } else {
                fprintf(stderr, "Changed password.\n");
                if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                    PRINT_ERROR("Could not derive HMAC key");
                    goto error;
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
            if (getPass("Enter new database password: ", cryptoStruct.dbPass) != 0 ) {
                goto error;
            }

            if (getPass("Verify password:", cryptoStruct.dbPassToVerify) != 0) {
                goto error;
            }
            if (strcmp(cryptoStruct.dbPass, cryptoStruct.dbPassToVerify) != 0) {
                fprintf(stderr, "Passwords don't match, not changing.\n");
                goto error;
            } else {
                fprintf(stderr, "Changed password.\n");
                if (deriveKeys(&cryptoStruct, &authStruct) != 0) {
                    PRINT_ERROR("Could not derive HMAC key");
                    goto error;
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
        if (configEvp(&cryptoStruct, &conditionsStruct) != 0) { 
            goto error;
        }

        /*The updatingDbEnc function decrypts with the old key and cipher settings, re-encrypts with new key and/or cipher settings then writes to encryptedBuffer*/
        if (updateDbEnc(&cryptoStruct, &authStruct) == 0) {
            if (writeDatabase(&cryptoStruct, &authStruct, &dbStruct, &miscStruct, &conditionsStruct) != 0) {
                goto error;
            }
        } else {
            goto error;
        }

    } else { /*If the user didn't specify an operation mode, and didn't use '-c list'*/
        fprintf(stderr, "Must use -a,-r,-d,-u or -U\nUse -h t print help\n");
        goto error;
    }
    
    cleanUpBuffers(&cryptoStruct, &authStruct, &textBuffersStruct);
    return EXIT_SUCCESS;
    
    error:
    
    cleanUpBuffers(&cryptoStruct, &authStruct, &textBuffersStruct);
    return EXIT_FAILURE;
    
    
}
