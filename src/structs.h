/* structs.h - structures */

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

/*Boolean conditions to test for true or false for control flow*/
struct conditionBoolsStruct {
    bool addingPass;
    bool readingPass;
    bool deletingPass;
    bool entryPassGivenasArg;
    bool dbPassGivenasArg;
    bool fileGiven;
    bool fileNeeded;
    bool entryGiven;
    bool updatingEntry;
    bool updatingEntryPass;
    bool updatingDbEnc;
    bool searchForEntry;
    bool userChoseCipher;
    bool genPassLengthGiven;
    bool sendToClipboard;
    bool userChoseClipboardClearTime;
    bool userChoseScryptWorkFactors;
    bool databaseBeingInitalized;
    bool generateEntryPass;
    bool generateEntryPassAlpha;
    bool printAllPasses;
    bool updateAllPasses;
    bool printingDbInfo;
    bool selectionIsPrimary;
    bool selectionIsClipboard;
    bool selectionGiven;
    bool allowOnePasting;
    bool useExtendedRegex;
    bool pipePasswordToStdout;
};

struct cryptoVar {
    /*Master key to be split among HMACKey evpKey*/
    unsigned char *masterKey;

    /*Holds cipher identificaiton integer for OpenSSL EVP library to know what algorithm to use*/
    const EVP_CIPHER *evpCipher;

    /*Holds old cipher identificaiton integer when database encryption is being updated*/
    const EVP_CIPHER *evpCipherOld;

    /*Key to be given to the EVP lib functions for chosen cipher algorithm to use*/
    unsigned char *evpKey;

    /*Old key to give to EVP lib functions when database encryption is being updated*/
    unsigned char *evpKeyOld;

    /*Master password to derive keys from for database encryption*/
    char *dbPass;

    /*Password that user entered to verify against to ensure no typos were made*/
    char *dbPassToVerify;

    /*Old master password when database password is being changed*/
    char *dbPassOld;

    /*Text-based name of the cipher algorithm for use, that will later be converted to numeric ID by EVP lib functions*/
    char encCipherName[NAME_MAX];

    /*Salt to use with key derivation*/
    unsigned char *evpSalt;

    /*Old cipher name for when database encryption is beind updated*/
    char encCipherNameOld[NAME_MAX];

    /*Cipher name given by user on command line*/
    char encCipherNameFromCmdLine[NAME_MAX];

    /*Scrypt parameters to use*/
    int scryptNFactor, scryptRFactor, scryptPFactor;

    /*Store scrypt parameters given to be assigned back later*/
    int scryptNFactorStore, scryptRFactorStore, scryptPFactorStore;

    /*Old scrypt parameters to use when database encryption or master password is changed*/
    int scryptNFactorOld, scryptRFactorOld, scryptPFactorOld;

    /*Header containing salt, cipher name and scrypt parameters*/
    char cryptoHeader[CRYPTO_HEADER_SIZE];

    /*Buffer that will hold encrypted data of database after opening or before writing*/
    unsigned char *encryptedBuffer;

    /*Buffer which will hold the first entry that initializes the database*/
    unsigned char dbInitBuffer[(UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH];

    /*Size of the cipher-text to be sent to EVP functions*/
    int evpDataSize;
};

struct authVar {
    /*Key to use for HMAC authentication of cipher-text*/
    unsigned char *HMACKey;

    /*Old HMAC key to use when database encryption or password is updated*/
    unsigned char *HMACKeyOld;

    /*Buffers to compare for cipher-text authnetication*/
    unsigned char MACcipherTextGenerates[SHA512_DIGEST_LENGTH];
    unsigned char MACcipherTextSignedWith[SHA512_DIGEST_LENGTH];

    /*Buffers to compare for database integrity*/
    unsigned char CheckSumDbFileSignedWith[SHA512_DIGEST_LENGTH];
    unsigned char CheckSumDbFileGenerates[SHA512_DIGEST_LENGTH];

    /*Buffers to compare to check if correct password was entered*/
    unsigned char KeyedHashdBPassSignedWith[SHA512_DIGEST_LENGTH];
    unsigned char KeyedHashdBPassGenerates[SHA512_DIGEST_LENGTH];
};

struct dbVar {
    /*File name of password database*/
    char dbFileName[NAME_MAX];

/*Extention for backup file*/
#define BACKUP_FILE_EXT_LEN 9
    char backupFileExt[BACKUP_FILE_EXT_LEN];

    /*Buffer to hold backup file name plus extention*/
    char backupFileName[NAME_MAX + BACKUP_FILE_EXT_LEN];
};

struct textBuf {
    /*Buffer to hold entry password*/
    char *entryPass;

    /*Buffer to hold password user entered for verification*/
    char *entryPassToVerify;

    /*Buffer to hold entry name*/
    char *entryName;

    /*Buffer to hold entry name to search for in updateEntry or deleteEntry*/
    char *entryNameToFind;

    /*Buffer to hold new entry name*/
    char *newEntry;

    /*Buffer to hold new entry pass*/
    char *newEntryPass;

    /*Buffer to hold new entry pass for verification*/
    char *newEntryPassToVerify;

    /*Buffer to hold password with CSPRNG padding*/
    char *paddedPass;
};

struct miscVar {
    /*How long in milliseconds the password should be available for pasting*/
    int clipboardClearTimeMiliSeconds;

    /*How long a generated password should be*/
    int genPassLength;

    /*Holds the value of errno after fread/write error because it might be changed after calling perror*/
    int returnVal;
};
