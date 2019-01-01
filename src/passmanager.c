/* Copyright 2018 Kenneth Brown */

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
#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/*Define a size in bytes for the buffers. The entry name and password are handled separately so combined they will make 1024 sized buffers*/
#define BUFFER_SIZES 512

/*This is the highest number 'i' will be allowed to reach when referencing yaxaKey[i]*/
#define YAXA_KEY_LENGTH BUFFER_SIZES * 2

/*Yaxa key array must be quotient of YAXA_KEY_LENGTH / SHA512_DIGEST_LENGTH (64)*/
#define YAXA_KEYARRAY_SIZE YAXA_KEY_LENGTH / SHA512_DIGEST_LENGTH

/*This buffer holds the yaxaKey and should be YAXA_KEY_LENGTH + 1*/
#define YAXA_KEYBUF_SIZE YAXA_KEY_LENGTH + 1

/*This is the highest number 'i' will be allowed to reach when reference yaxaNonce[i]*/
#define YAXA_NONCE_LENGTH SHA512_DIGEST_LENGTH

/*This buffer holds the yaxaNonce and should be YAXA_NONCE_LENGTH + 1*/
#define YAXA_NONCEBUF_SIZE YAXA_NONCE_LENGTH + 1

/*Define sizes of salts*/
#define EVP_SALT_SIZE 16
#define YAXA_SALT_SIZE YAXA_KEYARRAY_SIZE
#define HMAC_SALT_SIZE YAXA_SALT_SIZE

/*Define block sizes for dbDecrypt and dbEncrypt to use*/
#define EVP_BLOCK_SIZE 1024

/*The default PBKDF2 and EVP_BytesToKey iteration count as per RFC 2889 reccomendation*/
/*The final iteration will differ from this depending on length of user pass and salts generated*/
#define PBKDF2_ITERATIONS 1000

/*Default size of password if generation is chosen*/
#define DEFAULT_GENPASS_LENGTH 16

/*Naming the structure 'toggle' just makes it easy to remember these are option-toggle variables*/
/*If the value is 1 the option is true/on, if not the option is false/off*/
struct toggleStruct {
    int Add; /*To add a password to a file*/
    int Read; /*To read a password to a file*/
    int Delete; /*To delete an entry from a file*/
    int entryPassArg; /*To enable passing the password from the command line*/
    int dbPassArg; /*To enable passing the yaxa password from the command line*/
    int fileGiven; /*To ensure that a file has been specified, program halts if not set to 1*/
    int entryGiven; /*To ensure that an entry has been specified*/
    int updateEntry; /*To specify updating an entry only*/
    int updateEntryPass; /*To secify updating an entry as well as a password*/
    int updateEncPass; /*Update encryption password*/
    int entrySearch; /*Use to find a specific entry instead of operating on all of them*/
    int messageDigest; /*User specified message digest algorithm*/
    int encCipher; /*User specified cipher algorithm*/
    int entryPassLengthGiven; /*Use to specify a length of generated pass*/
    int sendToClipboard; /*Toggle sending entry's password directly to clipboard*/
    int xclipClearTime; /*To use a non-default clear time for the clipboard*/
    int firstRun; /*Keep track if it's the first runw*/
    int generateEntryPass; /*Toggle to generate random entry pass*/
    int generateEntryPassAlpha; /*Toggle to generate alphanumeric pass*/
    int allPasses; /*Toggle to read or update allpasses*/
};

struct toggleStruct toggle;

/*Prototype functions*/

/*OpenSSL related functions*/
int primeSSL(); /*Loads EVP cipher and digest objects via name after user species them or parsed from file header*/
int openEnvelope(); /*Opens EVP encrypted envelope file and checks MAC attached*/
void genSalt(); /*Generates an 8byte random salt to be used by EVP*/
int dbDecrypt(FILE* in, FILE* out); /*OpenSSSL EVP decryption routine*/
int dbEncrypt(FILE* in, FILE* out); /*OpenSSL EVP encryption routine*/
int sealEnvelope(const char* tmpFileToUse); /*Writes YAXA data to EVP ecncrypted envelope and attaches MAC*/
void mdList(const OBJ_NAME* obj, void* arg); /*Sets up structure objects needed to list message digests available to OpenSSL*/
void mdLister(); /*Lists the message digests available to OpenSSL*/
void encList(const OBJ_NAME* obj, void* arg); /*Same as mdList but for encryption ciphers*/
void encLister(); /*Same as mdLIster but for encryption ciphers*/
/*YAXA functions*/
void genYaxaSalt(); /*Generates YAXA salt*/
void yaxaKDF(); /*Derive cryptographic key material needed for YAXA*/
unsigned char yaxa(unsigned char messageByte, unsigned char keyByte, unsigned char nonceByte); /*Yaxa encryption/Decryption function*/
/*Password management functions*/
int writePass(FILE* dbFile); /*Uses YAXA cipher to write passes to a file*/
int printPasses(FILE* dbFile, char* searchString); /*Uses YAXA cipher to read passes from file*/
int deletePass(FILE* dbFile, char* searchString); /*Uses YAXA cipher to delete passes from a file*/
int updateEntry(FILE* dbFile, char* searchString); /*Updates entryName or entryName AND passWord*/
int updateEncPass(FILE* dbFile); /*Update database encryption password*/
/*Password input functions*/
void genPassWord(int stringLength); /*Generates an entry password if 'gen' is specifed*/
char* getPass(const char* prompt, unsigned char * paddedPass); /*Function to retrive passwords with no echo*/
/*Setup functions*/
void allocateBuffers(); /*Allocates all the buffers used*/
int doesFileExist(const char* filename); /*Checks if the file exists using stat()*/
int returnFileSize(const char* filename); /*Returns filesize using stat()*/
char* genFileName(); /*Generates random file names for temporary files*/
/*Cleanup functions*/
void cleanUpFiles(); /*Cleans up temp files*/
void cleanUpBuffers(); /*Writes zeroes to all the buffers we used when done*/
int wipeFile(const char* filename); /*Wipes temp files used with Schneier 7-Pass method*/
/*Misc functions*/
void signalHandler(int signum); /*Signal handler for Ctrl+C*/
int sendToClipboard(); /*Sends an entry password directly to clipboard*/
int printSyntax(char* arg); /*Print program usage and help*/
int printMACErrMessage(char* backupFileName); /*Print MAC error information*/

/*OpenSSL variables*/

/*These are needed for OpenSSL key ring material*/
const EVP_CIPHER *evpCipher1, *evpCipher2; /*This holds the cipher_ctx pinter needed by EVP functions*/
unsigned char evpKey1[EVP_MAX_KEY_LENGTH],evpKey2[EVP_MAX_KEY_LENGTH]; /*buffer for key for EVP encryption will be generated by EVP_BytesToKey*/
unsigned char evpIv1[EVP_MAX_IV_LENGTH],evpIv2[EVP_MAX_IV_LENGTH]; /*buffer for evpIv2, will also be generated if needed*/
const EVP_MD *evpDigest1 = NULL, *evpDigest2 = NULL; /*store the md_ctx to tell what digest we need to use in EVP_BytesToKey*/
unsigned char* dbPass; /*Will hold the user-supplied database password*/
unsigned char* dbPassStore; /*This stores the dbPass entered by the user to verify it was not mistyped*/
unsigned char* dbPassOld; /*Store old dbPassword to check against and when changing database password*/

/*EVP cipher and MD name character arrays*/
char messageDigest[NAME_MAX]; /*Message digest name to send to EVP functions*/
char messageDigestStore[NAME_MAX]; /*Stores messageDigest given on commandline*/
char encCipher[NAME_MAX]; /*Cipher name to send to EVP functions*/
char encCipherStore[NAME_MAX]; /*Stores the encCipher given on commandline*/

/*YAXA variables*/

/*This is the last byte XOR'd to form the keystream and is sequentially incremented to form  a key counter*/
unsigned long long keyStreamGenByte = 0, keyStreamGenByteOld, keyStreamGenByteNew; 
/*Two dimensional array is needed so that PBKDF2 can produce 16 strings, 64 bytes each, concatenated to form 1024 bytes*/
unsigned char yaxaKeyArray[YAXA_KEYARRAY_SIZE][SHA512_DIGEST_LENGTH];
/*The original length of the user supplied password*/
unsigned int originalPassLength, originalPassLengthOld, originalPassLengthNew;
/*A 65 byte array to be used as a nonce in YAXA*/
unsigned char *yaxaNonce, *yaxaNonceOld, *yaxaNonceNew; /*Hold old yaxa nonce to check against when updating database*/
/*Will hold the final yaxa key derived in yaxaKDF()*/
unsigned char *yaxaKey, *yaxaKeyOld;
/*Holds 64 bytes in yaxaKeyChunk before being concatenated to form yaxaKey*/
unsigned char* yaxaKeyChunk;
/*Holds a 64 byte key derived in yaxaKDF to be used in HMAC function*/
unsigned char *hmacKey, *hmacKeyNew, *hmacKeyOld;

/*Misc crypto variables*/

/*Salts*/
unsigned char* evpSalt; /*This stores the salt to use in EVPBytestoKey for envelope encryption/decryption*/
unsigned char* yaxaSalt; /*This will store the salt to use for yaxaKDF() key deriving*/
/*Buffers and variables needed for HMAC*/
unsigned char gMac[SHA512_DIGEST_LENGTH]; /*MAC generated from plain-text, thus gMac for generatedMac*/
unsigned char fMac[SHA512_DIGEST_LENGTH]; /*MAC read from file to check against, thus fMac for fileMac*/
unsigned int* gMacLength; /*HMAC() needs an int pointer to put the length of the mac generated into*/

/*Character arrays to hold temp file random names*/
char* tmpFile1;
char* tmpFile2;
char* tmpFile3;

/*Backup and database file names*/
char dbFileName[NAME_MAX]; /*Password file name*/
char backupFileName[NAME_MAX]; /*Buffer to hold the name of backup file for passwords file which will be the same with a .sav suffix*/

/*Input buffers*/
char* entryPass; /*Entry password*/
char* entryPassStore;
char* entryName; /*Entry name*/
char* entryNameToSearch; /*Send this to updateEntry to find entires by name*/
char* newEntry; /*Use this buffer to update entry name with updateEntry*/
char* newEntryPass; /*Use this buffer to update entry passwor with updateEntry*/
char* newEntryPassStore; /*Use this buffer to update entry passwor with updateEntry*/
char* pass = NULL; /*Used in getPass() for getline()*/
char* paddedPass; /*Holds pointer to buffer for user pass from getPass()*/

/*Misc variables*/

/*The amount of seconds to wait before clearing the clipboard if we send pass to it with xclip*/
/*This will default to 30 unless the user species -s n to set it to n seconds*/
int xclipClearTime = 30;
/*How long an entry password to generate if generation is specifed*/
int entryPassLength;
/*Ignore freads return value and shut gcc up about it*/
int nullReturn;
/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
struct termios termisOld, termiosNew;

int main(int argc, char* argv[])
{
    /*Print help if no arguments given*/
    if (argc == 1) {
        printSyntax(argv[0]);
        return 1;
    }

    allocateBuffers();

    signal(SIGINT, signalHandler);

    tmpFile1 = genFileName();
    tmpFile2 = genFileName();
    tmpFile3 = genFileName();
    
    /*Debugging*/
    //printf("tmpFile1: %s\n", tmpFile1);
    //printf("tmpFile2: %s\n", tmpFile2);
    //printf("tmpFile3: %s\n", tmpFile3);

    /*These file handles refer to temporary and final files in the openEnvelope/sealEnvelope process*/
    FILE *EVPEncryptedFile, *EVPDecryptedFile, *yaxaDataFileTmp, *dbFile;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdLIster() and encLister() functions to work*/
    OpenSSL_add_all_algorithms();

    int opt; /*for getop()*/
    int errflg = 0; /*Toggle this flag on and off so we can check for errors and act accordingly*/

    int i;

    /*Process through arguments*/
    while ((opt = getopt(argc, argv, "s:l:f:u:n:d:a:r:p:x:H:c:hUPC")) != -1) {
        switch (opt) {
        case 'h': /*Help*/
            printSyntax("passmanager");
            return 1;
            break;
        case 's':
            if (optarg[0] == '-') {
                printf("Option -s requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            xclipClearTime = atoi(optarg);
            toggle.xclipClearTime = 1;
            break;
        case 'l':
            if (optarg[0] == '-') {
                printf("Option -l requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            entryPassLength = atoi(optarg);
            if (BUFFER_SIZES < entryPassLength) {
                entryPassLength = BUFFER_SIZES;
            }
            toggle.entryPassLengthGiven = 1;
            break;
        case 'U': /*Update encryption password*/
            toggle.updateEncPass = 1;
            break;
        case 'C': /*Send entry out to clipboard*/
            toggle.sendToClipboard = 1;
            break;
        case 'P': /*Update entry pasword*/
            toggle.updateEntryPass = 1;
            break;
        case 'a': /*Add password*/
            if (optarg[0] == '-') {
                printf("Option -a requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            } else
                toggle.Add = 1;
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\nentry name too long\n");
                return 1;
            }
            strcpy(entryName, optarg);
            toggle.entryGiven = 1;
            break;
        case 'r': /*Read password(s)*/
            toggle.Read = 1;
            if (optarg[0] == '-') { /*If the first character of optarg is '-' it's another option and not an argument*/
                printf("Option -r requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            } else
                toggle.entrySearch = 1;
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\nentry name too long\n");
                return 1;
            }
            if (strcmp(optarg, "allpasses") == 0)
                toggle.allPasses = 1;
            strcpy(entryName, optarg);
            toggle.entryGiven = 1;
            break;
        case 'd': /*Delete password*/
            if (optarg[0] == '-') {
                printf("Option -d requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            } else
                toggle.Delete = 1;
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\nentry name too long\n");
                return 1;
            }
            strcpy(entryName, optarg);
            toggle.entryGiven = 1;
            toggle.entrySearch = 1;
            break;
        case 'H': /*Hashing digest for EVPKeytoBytes() to use*/
            if (optarg[0] == '-') {
                printf("Option -H requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            if (strcmp(optarg, "list") == 0) {
                mdLister();
                return 0;
            }
            toggle.messageDigest = 1;
            strcpy(messageDigest, optarg);
            strcpy(messageDigestStore, optarg);
            toggle.messageDigest = 1;
            break;
        case 'c': /*Encryption cipher to use*/
            if (optarg[0] == '-') {
                printf("Option -c requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            if (strcmp(optarg, "list") == 0) {
                encLister();
                return 0;
            }
            toggle.encCipher = 1;
            strcpy(encCipher, optarg);
            strcpy(encCipherStore, optarg);
            toggle.encCipher = 1;
            break;
        case 'f': /*Specify password file*/
            if (toggle.Add == 1) {
                dbFile = fopen(optarg, "ab");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }

                /*Grab passworld database filename off the command line*/
                strcpy(dbFileName, optarg);
            }
            if (toggle.Read == 1) {
                dbFile = fopen(optarg, "rb");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }

                strcpy(dbFileName, optarg);
            }
            if (toggle.Delete == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strcpy(dbFileName, optarg);
            }
            if (toggle.updateEncPass == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strcpy(dbFileName, optarg);
            }
            if (toggle.updateEntry == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strcpy(dbFileName, optarg);
            }
            toggle.fileGiven = 1;
            break;
        case 'n': /*Specifies an entry by name*/
            if (optarg[0] == '-') { /*If the first character of optarg is '-' it's another option and not an argument*/
                printf("Option -n requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            } else
                toggle.entrySearch = 1;
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\nentry name too long\n");
                return 1;
            }
            strcpy(entryName, optarg);
            toggle.entryGiven = 1;
            break;
        case 'u': /*Specifies an entry by name*/
            if (optarg[0] == '-') {
                printf("Option -u requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            } else
                toggle.updateEntry = 1;
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\nentry name too long\n");
                return 1;
            }
            if (strcmp(optarg, "allpasses") == 0)
                toggle.allPasses = 1;
            strcpy(entryNameToSearch, optarg);
            break;
        case 'p': /*If passing password from command line*/
            toggle.entryPassArg = 1;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -p requires an operand\n");
                errflg++; /*Set error flag*/
            }
            if (strlen(optarg) > BUFFER_SIZES) {
                printf("\npassword too long\n");
                return 1;
            }
            if (strcmp(optarg, "gen") == 0)
                toggle.generateEntryPass = 1;
            if (strcmp(optarg, "genalpha") == 0)
                toggle.generateEntryPassAlpha = 1;
            strcpy(entryPass, optarg);
            memset(optarg, 0, strlen(optarg));
            break;
        case 'x': /*If passing yaxa password from command line*/
            toggle.dbPassArg = 1;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                errflg++; /*Set error flag*/
                printf("Option -x requires an operand\n");
            }
            strcpy(dbPass, optarg);
            memset(optarg, 0, strlen(optarg));
            break;
        case ':':
            printf("Option -%c requires an operand\n", optopt);
            errflg++; /*Set error flag*/
            break;
        case '?': /*Get opt error handling, these check that the options were entered in correct syntax but not that the options are right*/
            //u:n:p:x:f:H:c:
            if (optopt == 'f')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'u')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'n')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'd')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'a')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'p')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'x')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'H')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            printf("Unrecognized option: -%c\n", optopt);
            errflg++; /*Set error flag*/
        }
    }
    /*If the user didn't specify a file with -f set error flag on*/
    if (toggle.fileGiven != 1)
        errflg++;
    /*Finally test for errflag and halt program if on*/
    if (errflg) {
        printSyntax("passmanger"); /*Print proper usage of program*/
        return 1;
    }

    /*Sanitize argv and argc of any sensitive information*/
    for (i = 1; i < argc; i++)
        memset(argv[i], 0, strlen(argv[i]));

    /*Before anything else, back up the password database*/
    if (returnFileSize(dbFileName) != 0 && toggle.Read != 1) {
        strcpy(backupFileName, dbFileName);
        strcat(backupFileName, ".autobak");
        FILE* backUpFile = fopen(backupFileName, "w");
        if (backUpFile == NULL) {
            printf("Couldn't make a backup file. Be careful...\n");
        } else {
            FILE* copyFile = fopen(dbFileName, "r");
            char* backUpFileBuffer = malloc(sizeof(char) * returnFileSize(dbFileName));
            nullReturn = fread(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), copyFile);
				
            fwrite(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), backUpFile);
            fclose(copyFile);
            fclose(backUpFile);
            free(backUpFileBuffer);
        }
    }

    /*Now the program begins its work*/

    /*Test for toggle.Add, toggle.Read, toggle.Delete, toggle.updateEntry or toggle.UpdateEncPass*/
    if (toggle.Add == 1) /*This mode will add an entry*/
    {

        /*Check a few things before proceeding*/
        
        /*If dbFile is NULL there was a problem opening it*/
        if (dbFile == NULL) {
            perror(argv[0]); /*Print the error that occured*/
            cleanUpBuffers();
            return errno; /*Return the error's status code*/
        }

		/*If generating a random password was specified on command line*/
        if (strcmp(entryPass, "gen") == 0) {
            toggle.generateEntryPass = 1;
            if (toggle.entryPassLengthGiven == 1)
                genPassWord(entryPassLength);
            else
                genPassWord(DEFAULT_GENPASS_LENGTH);
        } else if (strcmp(entryPass, "genalpha") == 0) {
            toggle.generateEntryPassAlpha = 1;
            if (toggle.entryPassLengthGiven == 1)
                genPassWord(entryPassLength);
            else
                genPassWord(DEFAULT_GENPASS_LENGTH);
        } else if (toggle.entryPassArg != 1) {
			/*Prompt for entry password*/
            getPass("Enter entry password to be saved: ", entryPass); /*getpass() defined in getpass.h to retrieve pass without echo*/

			/*If user entered gen or genalpha at prompt*/
            if (strcmp(entryPass, "gen") == 0) {
                toggle.generateEntryPass = 1;
                printf("\nGenerating a random password\n");
                if (toggle.entryPassLengthGiven == 1)
                    genPassWord(entryPassLength);
                else
                    genPassWord(DEFAULT_GENPASS_LENGTH);
            } else if (strcmp(entryPass, "genalpha") == 0) {
                toggle.generateEntryPassAlpha = 1;
                printf("\nGenerating a random password\n");
                if (toggle.entryPassLengthGiven == 1)
                    genPassWord(entryPassLength);
                else
                    genPassWord(DEFAULT_GENPASS_LENGTH);
            } else {
				/*Verify user gentered password if not gen or genalpha*/
				getPass("Verify password:",entryPassStore);
				if (strcmp(entryPass, entryPassStore) != 0) {
					printf("\nPasswords do not match.  Nothing done.\n\n");
					cleanUpBuffers();
					return 1;
				}
            }
        }

        /*Prompt for database password if not supplied as argument*/
        if (toggle.dbPassArg != 1) {
            getPass("Enter database password to encode with: ",dbPass);

            /*If this function returns 0 then it is the first time entering the database password so input should be verified*/
            if (returnFileSize(dbFileName) == 0) {
				getPass("Verify password:",dbPassStore);
                if (strcmp(dbPass, dbPassStore) != 0) {
                    printf("\nPasswords do not match.  Nothing done.\n\n");
                    cleanUpBuffers();
                    return 1;
                }
            }
        }
        
        /*Note this will be needed before openEnvelope() is called in all modes except Read*/
        /*Do OpenSSL priming operations*/
        if (primeSSL() != 0) {
            return 1;
        }

		/*If password file exists run openEnvelope on it*/
        if (returnFileSize(dbFileName) > 0) {
            if (openEnvelope() != 0) {
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            }
            evpCipher1 = EVP_get_cipherbyname("bf-ofb");
			evpDigest1 = EVP_get_digestbyname("whirlpool");
        } else {
			/*Otherwise run these functions to initialize a database*/
			evpCipher1 = EVP_get_cipherbyname("bf-ofb");
			evpDigest1 = EVP_get_digestbyname("whirlpool");
            genYaxaSalt();
            genSalt();
            yaxaKDF();
            toggle.firstRun = 1;
        }

		/*openEnvelope will decrypt YAXA data to tempfile whose name is randomly generated and contained in buffer tmpFile2*/
        /*Open YAXA temp file*/
        yaxaDataFileTmp = fopen(tmpFile2, "a+");
        if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*writePass() appends a new entry to yaxaDataFileTmp via YAXA stream cipher*/
        int writePassResult = writePass(yaxaDataFileTmp);

		if(writePassResult == 0) {
			printf("Added \"%s\" to database.\n", entryName);

			if (toggle.sendToClipboard == 1) {
				printf("New password sent to clipboard. Paste with middle-click.\n");
				sendToClipboard(entryPass);
			}
		
			/*sealEnvelope attaches MAC and encrypts it with OpenSSL*/
			if (sealEnvelope(tmpFile2) != 0) {
				cleanUpBuffers();
				cleanUpFiles();
				return 1;
			}
		}

    } else if (toggle.Read == 1) /*Read passwords mode*/
    {

        if (toggle.dbPassArg != 1) /*If user did not specify to take pass off command line*/
        {
            getPass("Enter database password: ", dbPass);
        }

        /*For the purpose of temporary files EVPEncryptedFile refers to the password file as encrypted with OpenSSL*/
        EVPEncryptedFile = fopen(dbFileName, "rb");
        if (EVPEncryptedFile == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            return errno;
        }
        /*This file will hold the YAXA+DATA decrypted envelope*/
        EVPDecryptedFile = fopen(tmpFile1, "wb");
        if (EVPDecryptedFile == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            printf("Couldn't open file: %s", tmpFile1);
            return errno;
        }
        chmod(tmpFile1, S_IRUSR | S_IWUSR);

        /*Note no primeSSL() needed before openEnvelope() in Read mode*/
        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        /*the file whose name is pointed to by tmpFile2 now contains YAXA data with no MAC and can be passed to printPasses()*/
        yaxaDataFileTmp = fopen(tmpFile2, "rb"); /*Now open the temporary file to be read as YAXA data*/
        if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);
        
        evpCipher1 = EVP_get_cipherbyname("bf-ofb");
		evpDigest1 = EVP_get_digestbyname("whirlpool");

        if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") != 0) /*Find a specific entry to print*/
        {
            printPasses(yaxaDataFileTmp, entryName); /*Decrypt and print pass specified by entryName*/
            if (toggle.sendToClipboard == 1) {
                printf("Sent password to clipboard. Paste with middle-click.\n");
            }
        } else if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") == 0)
            printPasses(yaxaDataFileTmp, NULL); /*Decrypt and print all passess*/

        fclose(yaxaDataFileTmp);

    } else if (toggle.Delete == 1) /*Delete a specified entry*/
    {

        if (toggle.dbPassArg != 1) /*If user did not specify to take pass off command line*/
        {
            getPass("Enter database password: ", dbPass);
        }

        /*Must specify an entry to delete*/
        if (toggle.entryGiven != 1) /*Fail if no entry specified*/
        {
            fclose(dbFile);
            printf("\nNo entry name was specified\n");
            cleanUpBuffers();
            return 1;
        }

        fclose(dbFile);

        /*Do OpenSSL priming operations*/
        if (primeSSL()) {
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        /*the file whose name is pointed to by tmpFile2 now contains YAXA data with no MAC and can be passed to deletePasses()*/
        yaxaDataFileTmp = fopen(tmpFile2, "rb+"); /*Open the temporary file*/
        if (yaxaDataFileTmp == NULL) /*Make sure file opened*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);
        
        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified to a new temporary file*/
        int deletePassResult = deletePass(yaxaDataFileTmp, entryName);
        
        fclose(yaxaDataFileTmp);

		if(deletePassResult == 0) {
			
			/*After the password entry was deleted the rest of the passwords were written to a 3rd temporary file which is encrypted by sealEnvelope*/
			if (sealEnvelope(tmpFile3) != 0) {
				cleanUpBuffers();
				cleanUpFiles();
			}
		}
    } else if (toggle.updateEntry == 1) /*Update an entry name*/
    {

        if (toggle.dbPassArg != 1) /*If user did not specify to take pass off command line*/
        {
            getPass("Enter database password: ", dbPass);
        }

        /*Get new entry*/
        if (toggle.entryGiven == 1) {
            strcpy(newEntry, entryName);
        } else {
            /*If no new entry was specified then just update the password*/
            strcpy(newEntry, entryNameToSearch);
            toggle.updateEntryPass = 1;
        }

		/*If entry password to update to was supplied by command line argument*/
        if (toggle.entryPassArg == 1)
            toggle.updateEntryPass = 1;

        /*Get new pass*/
        if (toggle.updateEntryPass) {
			/*If entryPass supplied by command line, and generated randomly if it is 'gen'*/
            if (strcmp(entryPass, "gen") == 0)
            {
                if (toggle.entryPassLengthGiven == 1) {
                    toggle.generateEntryPass = 1;
                    genPassWord(entryPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strcpy(newEntryPass, entryPass);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strcpy(newEntryPass, entryPass);
                }
            } else if (strcmp(entryPass, "genalpha") == 0) {
                toggle.generateEntryPassAlpha = 1;
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strcpy(newEntryPass, entryPass);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strcpy(newEntryPass, entryPass);
                }
            } else if (toggle.entryPassArg != 1) /*entryPass was not supplied via command line*/
            {
                /*Prompt for pass via user input instead*/
                getPass("Enter entry password to be saved: ", newEntryPass);

				/*If password retrieved by prompt was gen/genalpha generate a random password*/
                if (strcmp(newEntryPass, "gen") == 0) {
                    toggle.generateEntryPass = 1;
                    printf("\nGenerating a random password\n");
                    if (toggle.entryPassLengthGiven == 1) {
                        genPassWord(entryPassLength);
                        /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                        strcpy(newEntryPass, entryPass);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strcpy(newEntryPass, entryPass);
                    }
                } else if (strcmp(newEntryPass, "genalpha") == 0) {
                    toggle.generateEntryPassAlpha = 1;
                    printf("\nGenerating a random password\n");
                    if (toggle.entryPassLengthGiven == 1) {
                        genPassWord(entryPassLength);
                        /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                        strcpy(newEntryPass, entryPass);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strcpy(newEntryPass, entryPass);
                    }
                } else {
					/*If retrieved password was not gen/genalpha verify it was not mistyped*/
					getPass("Veryify password:", newEntryPassStore);
					if(strcmp(newEntryPass, newEntryPassStore) != 0) {
						printf("\nPasswords do not match.  Nothing done.\n\n");
						cleanUpBuffers();
						return 1;
					}
                }
            } else if (toggle.entryPassArg == 1) /*This condition is true if the user DID supply a password but it isn't 'gen'*/
            {
                strcpy(newEntryPass, entryPass);
            }
        }

        fclose(dbFile);

        /*Do OpenSSL priming operations*/
        if (primeSSL() != 0) {
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

		/*the file whose name is pointed to by tmpFile2 now contains YAXA data with no MAC and can be passed to updateEntry()*/
        yaxaDataFileTmp = fopen(tmpFile2, "rb+"); /*Open the temporary file*/
        if (yaxaDataFileTmp == NULL) /*Make sure file opened*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

		/*Works like deletePass() but instead of excluding matched entry, modfies its buffer values and then outputs to 3rd temp file*/
        int updateEntryResult = updateEntry(yaxaDataFileTmp, entryNameToSearch);
        
        fclose(yaxaDataFileTmp);

		if(updateEntryResult == 0) {
			if (toggle.sendToClipboard == 1) {
				printf("Sent new password to clipboard. Paste with middle-click.\n");
				sendToClipboard(entryPass);
			}

			if (sealEnvelope(tmpFile3) != 0) {
				cleanUpBuffers();
				cleanUpFiles();
			}
		}
    } else if (toggle.updateEncPass == 1) /*Update the database encryption password*/
    {
        fclose(dbFile);

        if (toggle.dbPassArg != 1) /*If user did not specify to take pass off command line*/
        {
            getPass("Enter old database password: ", dbPass);
        }

        if (openEnvelope(encCipher, messageDigest, dbPass) != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

		/*the file whose name is pointed to by tmpFile2 now contains YAXA data with no MAC and can be passed to updateEncPass()*/
        yaxaDataFileTmp = fopen(tmpFile2, "rb+"); /*Open a temporary file*/
        if (yaxaDataFileTmp == NULL) /*Make sure file opened*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*Must store old yaxa key data to decrypt database since yaxaKDF will replace these when generating key material for new pass*/
        strcpy(dbPassOld, dbPass);
        memcpy(yaxaKeyOld, yaxaKey, sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
        memcpy(yaxaNonceOld, yaxaNonce, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
        memcpy(hmacKeyOld, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
        //memcpy(yaxaKeyArrayOld, yaxaKeyArray, sizeof(unsigned char) * 1024);
        keyStreamGenByteOld = keyStreamGenByte;
        originalPassLengthOld = originalPassLength;

        /*If -U was given but neither -c or -H*/
        if (toggle.updateEncPass == 1 && (toggle.encCipher != 1 && toggle.messageDigest != 1)) {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);
            
            getPass("Verify password:",dbPassStore);
            if (strcmp(dbPass, dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                /*If not changing, replace old dbPass back into dbPass*/
                strcpy(dbPass, dbPassOld);
                strcpy(yaxaKey, yaxaKeyOld);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                genYaxaSalt();
                yaxaKDF();
                /*Send new yaxa key material to storage variables so their values can be recalled later on in updateEncPass()*/
                keyStreamGenByteNew = keyStreamGenByte;
                originalPassLengthNew = originalPassLength;
                memcpy(yaxaNonceNew, yaxaNonce, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
                memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
            }

            /*Change cipher and digest if specified*/
            if (toggle.encCipher == 1) {
                strcpy(encCipher, encCipherStore);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest, messageDigestStore);
                printf("Changing digest to %s\n", messageDigestStore);
            }
        }
        /*-U was given but not -P and -c and/or -H might be there*/
        else if (toggle.updateEncPass == 1 && toggle.updateEntryPass != 1) {
            if (toggle.encCipher == 1) {
                strcpy(encCipher, encCipherStore);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest, messageDigestStore);
                printf("Changing digest to %s\n", messageDigestStore);
            }
            keyStreamGenByteNew = keyStreamGenByte;
            originalPassLengthNew = originalPassLength;
            memcpy(yaxaNonceNew, yaxaNonce, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
            memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
        }
        /*If -P is given along with -c or -H*/
        else {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

			getPass("Verify password:",dbPassStore);
            if (strcmp(dbPass,dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                strcpy(dbPass, dbPassOld);
                strcpy(yaxaKey, yaxaKeyOld);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                genYaxaSalt();
                yaxaKDF();
                keyStreamGenByteNew = keyStreamGenByte;
                originalPassLengthNew = originalPassLength;
                memcpy(yaxaNonceNew, yaxaNonce, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
                memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
            }

            /*Change crypto settings*/
            if (toggle.encCipher == 1) {
                strcpy(encCipher, encCipherStore);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest, messageDigestStore);
                printf("Changing digest to %s\n", messageDigestStore);
            }
        }

        /*Do OpenSSL priming operations*/
        /*This will change to the cipher just specified*/
        if (primeSSL() != 0) {
            return 1;
        }
        
        evpCipher1 = EVP_get_cipherbyname("bf-ofb");
		evpDigest1 = EVP_get_digestbyname("whirlpool");

		
        int updateEncPassResult = updateEncPass(yaxaDataFileTmp); /*Function to update password*/

        fclose(yaxaDataFileTmp);

		if(updateEncPassResult == 0) {
			if (sealEnvelope(tmpFile3) != 0) {
				cleanUpBuffers();
				cleanUpFiles();
				return 1;
			}
		}
        
    } else {
        printSyntax("passmanager"); /*Just in case something else happens...*/
        return 1;
    }

    cleanUpBuffers();
    cleanUpFiles();
    return 0;
}

/*Print the passwords using the filename, dbPass and if needed the entryname as arguments*/
int printPasses(FILE* dbFile, char* searchString)
{
    int i, ii = 0, iii;
    int n = 0;
    int x;
    int entriesMatched = 0;
    
    int outlen, tmplen;
    
    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* entryBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);
    unsigned char* passBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);
    unsigned char* encryptedBuffer = malloc(sizeof(unsigned char) * fileSize);
    unsigned char* decryptedBuffer = malloc(sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);

    nullReturn = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);
    
    if (!EVP_BytesToKey(evpCipher2, evpDigest2, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey2, evpIv2)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }
    
    /*Decrypted the YAXA data into decryptedBuffer*/
		        
        if(!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    
    if(!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

    /*Generate hash based on YAXA data*/
    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, outlen, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via genMac()*/
    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);
        memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);

		free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

	/*Loop to process the file*/
    for (iii = 0; iii < outlen; iii += (BUFFER_SIZES * 2)) {

        /*Copy the decrypted information into entryBuffer and passBuffer*/
        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + iii];
            passBuffer[i] = decryptedBuffer[i + iii + BUFFER_SIZES];
        }

        if (searchString != NULL) /*If an entry name was specified*/
        {
            /*Use strncmp and search the first n elements of entryBuffer, where n is the length of the search string*/
            /*This will allow partial matches to be printed to search the file*/
            if (strncmp(searchString, entryBuffer, strlen(searchString)) == 0) /*Search entry buffer for the string in searchString*/
            {
                if (toggle.sendToClipboard == 1) {
                    printf("%s\n", entryBuffer);
                    sendToClipboard(passBuffer);
                } else {
                    printf("%s : %s\n", entryBuffer, passBuffer);
                }
                entriesMatched++;
            }
        } else /*If an entry name wasn't specified, print them all*/
            printf("%s : %s\n", entryBuffer, passBuffer);
    }

    if (entriesMatched == 0 && searchString != NULL)
        printf("Nothing matched \"%s\"\n", searchString);

    //For Debugging PUrposes
    //DISABLE FOR ACTUL USE
    //FILE* fileBufferFile = fopen("decryptedBuffer.cap","wb");
    //fwrite(decryptedBuffer,sizeof(unsigned char), fileSize,fileBufferFile);
    //fclose(fileBufferFile);

    memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);

    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(ctx);

    return 0;
}

/*Update's an entry's name or password*/
int updateEntry(FILE* dbFile, char* searchString)
{
    int i, ii = 0, iii = 0, n = 0; /*We need iterators!*/
    int lastCheck = 0;
    int noEntryMatched = 1;
    int x;
    
    int outlen, tmplen;
    
    int numberOfSymbols = 0;

    char* fileBuffer; /*We're gonna store the data in a buffer to modify it*/

    FILE* tmpFile;

    unsigned char* entryBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);
    unsigned char* passBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* encryptedBuffer = malloc(sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
    unsigned char* decryptedBuffer = malloc(sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);

    nullReturn = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    
    if(!nullReturn == fileSize/sizeof(unsigned char))
    {
		printf("Fread failed\n");
		return 1;
	}
    
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    
    if (!EVP_BytesToKey(evpCipher2, evpDigest2, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey2, evpIv2)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    fileBuffer = malloc(sizeof(unsigned char) * fileSize);

    /*Initialize yaxa variables, and one for iterators. Remember this needs to be done for every encryption/decryption*/
    ii = 0;
    n = 0;

    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);
		
        /*Decrypt file and store into temp buffer*/
        if(!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    
		if(!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

    //For Debugging PUrposes
    //DISABLE FOR ACTUL USE
    //FILE* fileBufferFile = fopen("decryptedBuffer.cap","wb");
    //fwrite(decryptedBuffer,sizeof(unsigned char), fileSize,fileBufferFile);
    //fclose(fileBufferFile);

    /*Generate hash based on YAXA data*/
    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, outlen, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via genMac()*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);
        cleanUpFiles();
        
        memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(fileBuffer,0,sizeof(unsigned char) * fileSize);

		free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
        
        cleanUpBuffers();
        return 1;
    }

    for (iii = 0; iii < fileSize; iii += (BUFFER_SIZES * 2)) {

        /*Initialize yaxa variables for next encryption/decryption*/
        ii = 0;
        n = 0;

        genYaxaSalt();
        yaxaKDF();

        /*Copy the encrypted information into the yaxaBuffer*/
        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + iii];
            passBuffer[i] = decryptedBuffer[i + iii + BUFFER_SIZES];
        }

        /*Use strcmp to match the exact entry here*/
        /*Or allpasses if it was specified*/
        if ((lastCheck = strncmp(searchString, entryBuffer, strlen(searchString))) == 0 || toggle.allPasses == 1)
        {

            noEntryMatched = 0;

            //Update content in entryName before encrypting back with yaxa
            if (toggle.entryGiven == 1) {
                memcpy(entryBuffer, newEntry, BUFFER_SIZES);
            }
            
            /*This will preserve the alphanumeric nature of a password if it has no symbols*/
            if(toggle.allPasses == 1)
            {
				for(i = 0; i < strlen(passBuffer); i++)
				{
					if(isupper(passBuffer[i]) == 0 && islower(passBuffer[i]) == 0 && isdigit(passBuffer[i]) == 0)
						numberOfSymbols++;
				}
				
				if(numberOfSymbols == 0) {
					toggle.generateEntryPassAlpha = 1;
					toggle.generateEntryPass = 0;
				}
				else {
					toggle.generateEntryPassAlpha = 0;
					toggle.generateEntryPass = 1;
				}
				numberOfSymbols = 0;
			}

            /*Generate random passwords if gen was given, and for all if allpasses was given*/
            /*If allpasses was given, they will be random regardless if gen is not set.*/
            if (toggle.updateEntryPass == 1 && (toggle.generateEntryPass == 1 || toggle.allPasses == 1)) {

                /*This way we can generate a new pass for each entry during a bulk update*/
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
                    /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strcpy(newEntryPass, entryPass);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strcpy(newEntryPass, entryPass);
                }
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);
            } else if (toggle.updateEntryPass == 1 && (toggle.generateEntryPassAlpha == 1 || toggle.allPasses == 1)) {
                /*This way we can generate a new pass for each entry during a bulk update*/
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
                    /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strcpy(newEntryPass, entryPass);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strcpy(newEntryPass, entryPass);
                }
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);
            }

            if (toggle.updateEntryPass == 1)
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);

			/*Copy the entryBuffer and passBuffer out to fileBuffer*/
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[iii + i] = entryBuffer[i];
                else
                    fileBuffer[(iii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
			if(toggle.entryGiven == 1)
				printf("Updating \"%s\" to \"%s\" ...\n", searchString, entryBuffer);
			else
				printf("Matched \"%s\" to \"%s\" (Updating...)\n", searchString, entryBuffer);
        } else {
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[iii + i] = entryBuffer[i];
                else
                    fileBuffer[(iii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
        }
    }

    /*Hash the yaxa data with HMAC-SHA512*/
    /*Append this as the "generated" MAC later*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, fileBuffer, fileSize, gMac, gMacLength);

    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    free(encryptedBuffer);
    encryptedBuffer = malloc(sizeof(unsigned char) * fileSize);

    ii = 0;

    for (i = 0; i < fileSize; i++) {

        encryptedBuffer[i] = yaxa(fileBuffer[i], yaxaKey[ii], yaxaNonce[n]);

        if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
    }

    if (noEntryMatched == 1) {
        printf("Nothing matched the entry specified, nothing was deleted.\n");
    } else
        printf("If you updated more than you intended to, restore from %s.autobak\n", dbFileName);

    tmpFile = fopen(tmpFile3, "wb"); /*Now open a temp file just to write the new yaxa data to, clean up in the calling function*/
    if (tmpFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }

    //For Debugging Purposes
    //DISABLE FOR ACTUAL USE
    //fileBufferFile = fopen("encryptedBuffer.cap","wb");
    //fwrite(encryptedBuffer,sizeof(unsigned char), fileSize + (BUFFER_SIZES * 2),fileBufferFile);
    //fclose(fileBufferFile);

    chmod(tmpFile3, S_IRUSR | S_IWUSR);
    fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    fclose(tmpFile);

    memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(fileBuffer,0,sizeof(unsigned char) * fileSize);

    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(fileBuffer);

    return 0;
}

/*Finds and removes a specific entry from the file*/
int deletePass(FILE* dbFile, char* searchString)
{
    int i, ii = 0, iii = 0, iiii = 0, n = 0; /*We need iterators!*/
    int x;
    int lastCheck = 0;
    int noEntryMatched = 1;
    int entriesMatched = 0;

    char* fileBuffer; /*We're gonna store the data in a buffer to modify it*/
    char* fileBufferOld;

    FILE* tmpFile;

    /*Declare variables for yaxa operations*/

    /*yaxaBuffer stores both entryName and passWord in an encrypted form*/
    unsigned char* yaxaBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    unsigned char* entryBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);
    unsigned char* passBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* encryptedBuffer = malloc(sizeof(unsigned char) * fileSize);
    unsigned char* decryptedBuffer = malloc(sizeof(unsigned char) * fileSize);

    nullReturn = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);

    /*Now make a buffer for the file.  Reallocate later if we find a match to delete*/
    fileBuffer = malloc((sizeof(unsigned char) * fileSize));

    /*Initialize yaxa variables, and one for iterators. Remember this needs to be done for every encryption/decryption*/
    ii = 0;
    n = 0;

    for (i = 0; i < fileSize; i++) {

        decryptedBuffer[i] = yaxa(encryptedBuffer[i], yaxaKey[ii], yaxaNonce[n]);

        if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
    }

    /*Generate hash based on YAXA data*/
    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via genMac()*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);
        memset(yaxaBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
		memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
		memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(fileBuffer, 0, sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));

		free(yaxaBuffer);
		free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    for (iii = 0; iii < fileSize; iii += (BUFFER_SIZES * 2)) {

        /*Initialize yaxa variables for next encryption/decryption*/
        ii = 0;

        /*Copy the encrypted information into the yaxaBuffer*/
        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + iii];
            passBuffer[i] = decryptedBuffer[i + iii + BUFFER_SIZES];
        }

        /*Use strcmp to match the exact entry here*/
        if ((lastCheck = strncmp(searchString, entryBuffer, strlen(searchString))) == 0) /*Now we're going to find the specific entry to delete it*/
        {
            if (iii == (fileSize - (BUFFER_SIZES * 2))) /*If iii is one entry short of fileSize*/
            {
                if (entriesMatched < 1) /*If entry was matched we need to shrink the file buffer*/
                {
					/*Re-size the buffer to reflect deleted passwords*/
					fileBufferOld = malloc(sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					memcpy(fileBufferOld,fileBuffer,sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					memset(fileBuffer,0,sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					free(fileBuffer);
					
					fileBuffer = malloc(sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					memcpy(fileBuffer,fileBufferOld,sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					memset(fileBufferOld,0,sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
					free(fileBufferOld);
					
                }
            }
            printf("Matched \"%s\" to \"%s\" (Deleting)...\n", searchString, entryBuffer);
            entriesMatched++;
        } else {
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[iiii + i] = entryBuffer[i];
                else
                    fileBuffer[(iiii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
            iiii += BUFFER_SIZES * 2;
        }
    }

    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    free(encryptedBuffer);
    encryptedBuffer = malloc(sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));

    ii = 0;
    n = 0;

    genYaxaSalt();
    yaxaKDF();

    for (i = 0; i < fileSize - ((BUFFER_SIZES * 2) * entriesMatched); i++) {

        encryptedBuffer[i] = yaxa(fileBuffer[i], yaxaKey[ii], yaxaNonce[n]);

        if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
    }

    /*Hash the yaxa data with HMAC-SHA512*/
    /*Append this as the "generated" MAC later*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, fileBuffer, fileSize - ((BUFFER_SIZES * 2) * entriesMatched), gMac, gMacLength);

    tmpFile = fopen(tmpFile3, "wb"); /*Now open a temp file just to write the new yaxa data to, clean up in the calling function*/
    if (tmpFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    if (entriesMatched < 1) {
        printf("Nothing matched that exactly.\n");
        fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    } else {
        printf("If you deleted more than you intended to, restore from %s.autobak\n", dbFileName);
        fwrite(encryptedBuffer, fileSize - ((BUFFER_SIZES * 2) * entriesMatched), sizeof(char), tmpFile);
    }
    fclose(tmpFile);

    memset(yaxaBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
    memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));
    memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(fileBuffer, 0, sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));

    free(yaxaBuffer);
    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(fileBuffer);

    return 0;
}

/*Update encryption password*/
int updateEncPass(FILE* dbFile)
{
    int i, ii = 0, iii = 0, n = 0; /*We need iterators!*/
    int x;

	int outlen, tmplen;

    unsigned char* fileBuffer; /*We're gonna store the data in a buffer to modify it*/
    FILE* tmpFile;

    unsigned char* entryBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);
    unsigned char* passBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* decryptedBuffer = malloc(sizeof(unsigned char) * fileSize);
    unsigned char* encryptedBuffer = malloc(sizeof(unsigned char) * fileSize);

    nullReturn = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);

    /*Now make a buffer for the file*/
    fileBuffer = malloc(sizeof(unsigned char) * fileSize);

    ii = 0;
    n = 0;
    /*Set yaxa key variables to the old password data for decryption*/
    keyStreamGenByte = keyStreamGenByteOld;
    originalPassLength = originalPassLengthOld;
    memcpy(yaxaNonce, yaxaNonceOld, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    memcpy(hmacKey, hmacKeyOld, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);
    
    if (!EVP_BytesToKey(evpCipher1, evpDigest1, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey1, evpIv1)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }
    
    /*Decrypted the YAXA data into decryptedBuffer*/
		        
        if(!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    
    if(!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

    //For Debugging PUrposes
    //DISABLE FOR ACTUL USE
    //FILE* fileBufferFile = fopen("decryptedBuffer.cap","wb");
    //fwrite(decryptedBuffer,sizeof(unsigned char), fileSize,fileBufferFile);
    //fclose(fileBufferFile);

    /*Generate hash based on YAXA data*/
    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKeyOld, SHA512_DIGEST_LENGTH, decryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via genMac()*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);
        memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
		memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
		memset(fileBuffer, 0, sizeof(unsigned char) * fileSize);

		free(entryBuffer);
		free(passBuffer);
		free(decryptedBuffer);
		free(encryptedBuffer);
		free(fileBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    

    /*Now enrypt the buffers right back with the new key*/

    /*Initialize yaxa variables for next encryption/decryption*/
    ii = 0;
    n = 0;
    /*Now set yaxa key variables to the new password data*/
    keyStreamGenByte = keyStreamGenByteNew;
    originalPassLength = originalPassLengthNew;
    memcpy(yaxaNonce, yaxaNonceNew, sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    memcpy(hmacKey, hmacKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    fileSize = outlen;
    outlen = 0;
    tmplen = 0;
			
            EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
			if(!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, decryptedBuffer, fileSize))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
			if(!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

    //For Debugging Purposes
    //DISABLE FOR ACTUAL USE
    //fileBufferFile = fopen("encryptedBuffer.cap","wb");
    //fwrite(encryptedBuffer,sizeof(unsigned char), fileSize + (BUFFER_SIZES * 2),fileBufferFile);
    //fclose(fileBufferFile);

    /*Hash the yaxa data with HMAC-SHA512*/
    /*Append this as the "generated" MAC later*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, fileSize, gMac, gMacLength);

    tmpFile = fopen(tmpFile3, "wb"); /*Now open a temp file just to write the new yaxa data to, clean up in the calling function*/
    if (tmpFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);
    fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    fclose(tmpFile);

    memset(entryBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(passBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES);
    memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(fileBuffer, 0, sizeof(unsigned char) * fileSize);

    free(entryBuffer);
    free(passBuffer);
    free(decryptedBuffer);
    free(encryptedBuffer);
    free(fileBuffer);
    free(paddedPass);
    free(ctx);

    return 0;
}

/*Add entry to database*/
int writePass(FILE* dbFile)
{
    /*We need a set of incrementors to crawl through buffers*/
    int i, ii = 0;
    int n = 0;
    int x;
    long fileSize;
    
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, tmplen;

    /*Get the filesize*/
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    /*Priming the variables needed of yaxa encryption*/

    /*entryPass and entryName are both copied into infoBuffer, which is then encrypted with yaxa into yaxaBuffer and written*/
    unsigned char* infoBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    unsigned char* yaxaBuffer = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    unsigned char* decryptedBuffer = malloc(sizeof(unsigned char) * fileSize + (BUFFER_SIZES * 2));
    unsigned char* encryptedBuffer = malloc(sizeof(unsigned char) * fileSize);
    unsigned char* tmpBuffer = malloc(sizeof(unsigned char) * fileSize + (BUFFER_SIZES * 2));

    /*Put the chars, include random whitespace ones, from entryName and entryPass into infoBuffer, again splitting the BUFFER_SIZES * 2 chars between the two*/
    for (i = 0; i < BUFFER_SIZES; i++)
        infoBuffer[i] = entryName[i];
    for (i = 0; i < BUFFER_SIZES; i++)
        infoBuffer[i + BUFFER_SIZES] = entryPass[i];

    /*Store encrypted file in buffer*/
    nullReturn = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    
    if(!nullReturn == fileSize/sizeof(unsigned char))
    {
		printf("Fread failed\n");
		return 1;
	}
    
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    
    if (!EVP_BytesToKey(evpCipher2, evpDigest2, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey2, evpIv2)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    if (toggle.firstRun != 1) {
		EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);
		
        /*Decrypt file and store into temp buffer*/
        if(!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    
		if(!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

        /*Generate hash based on YAXA data*/
        /*This will be the gMac as in generated MAC*/
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, outlen, gMac, gMacLength);

        /*Check if the MAC from the EVPDecryptedFile matches MAC generated via genMac()*/

        /*Return error status before proceeding and clean up sensitive data*/
        if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
            printMACErrMessage(backupFileName);
            memset(infoBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
			memset(yaxaBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
			memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
			memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
			memset(tmpBuffer,0,sizeof(unsigned char) * fileSize + (BUFFER_SIZES * 2));
			free(infoBuffer);
			free(yaxaBuffer);
			free(decryptedBuffer);
			free(encryptedBuffer);
			free(tmpBuffer);
            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
    }

    if (toggle.firstRun == 1) {
		EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
        ii = 0;
        n = 0;

        /*This looping operation is different than the one in printPasses, because it encrypts and writes the whole buffer to file*/
			
			if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, infoBuffer, BUFFER_SIZES * 2))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
			
        if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

        /*Hash the yaxa data with HMAC-SHA512*/
        /*Append this as the "generated" MAC later*/
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, infoBuffer, outlen, gMac, gMacLength);

        /*Write the encrypted information to file*/
        fwrite(outbuf, 1, sizeof(unsigned char) * outlen, dbFile);
        
        /*For Debugging Purposes*/
        //printf("\n");
        //printf("\nyaxaSalt first run:");
        //for(i=0; i < 8 ; i++)
        //printf("%x:", yaxaSalt[i] & 0xff);
        //printf("\n");
    } else {
		EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
        ii = 0;
        n = 0;

        genYaxaSalt();
        yaxaKDF();

		/*For Debugging Purposes*/
        //printf("\n");
        //printf("\nyaxaSalt before encryption:");
        //for(i=0; i < 8 ; i++)
        //printf("%x:", yaxaSalt[i] & 0xff);
        //printf("\n");

        memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
        free(encryptedBuffer);
        encryptedBuffer = malloc(sizeof(unsigned char) * outlen + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH);
        
        for(i=0; i < BUFFER_SIZES * 2; i++)
        {
			decryptedBuffer[outlen + i] = infoBuffer[i];
		}
        
        fileSize = outlen;
        outlen = 0;
        tmplen = 0;
			
            
			if(!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, decryptedBuffer, fileSize + (BUFFER_SIZES *2)))
                {
                /* Error */
                return 0;
                }
            /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
			if(!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen))
                {
                /* Error */
                return 0;
                }
			outlen += tmplen;
			EVP_CIPHER_CTX_cleanup(ctx);

        /*Hash the yaxa data with HMAC-SHA512*/
        /*Append this as the "generated" MAC later*/
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, decryptedBuffer, fileSize + (BUFFER_SIZES * 2), gMac, gMacLength);

        fclose(dbFile);
        wipeFile(tmpFile2);
        dbFile = fopen(tmpFile2, "wb");

        fwrite(encryptedBuffer, sizeof(unsigned char), outlen, dbFile);
    }

    //For Debugging Purposes
    //DISABLE FOR ACTUAL USE
    //FILE* fileBufferFile = fopen("encryptedBuffer.cap","wb");
    //fwrite(encryptedBuffer,sizeof(unsigned char), fileSize + (BUFFER_SIZES * 2),fileBufferFile);
    //fclose(fileBufferFile);

    memset(infoBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
    memset(yaxaBuffer, 0, sizeof(unsigned char) * BUFFER_SIZES * 2);
    memset(decryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(encryptedBuffer, 0, sizeof(unsigned char) * fileSize);
    memset(tmpBuffer,0,sizeof(unsigned char) * fileSize + (BUFFER_SIZES * 2));
    free(infoBuffer);
    free(yaxaBuffer);
    free(decryptedBuffer);
    free(encryptedBuffer);
    free(tmpBuffer);
    free(ctx);

    fclose(dbFile);
    return 0;
}

/*Over write the data we put in the temporary files*/
/*https://en.wikipedia.org/wiki/Data_remanence#Feasibility_of_recovering_overwritten_data*/
/*https://en.wikipedia.org/wiki/Data_erasure#Standards*/
int wipeFile(const char* filename)
{
    int fileSize = returnFileSize(filename);
    int i, ii, passes = 7;
    char b;
    FILE* fileToWrite;
    for (ii = 0; ii <= passes; ii++) {
        fileToWrite = fopen(filename, "w+");
        if (fileToWrite == NULL) /*Make sure the file opens*/
        {
            perror("passmanager");
            return errno;
        }
        if (ii == 0) {
            for (i = 0; i <= fileSize; i++)
                fprintf(fileToWrite, "%i", 1);
        } else if (ii == 1) {
            for (i = 0; i <= fileSize; i++)
                fprintf(fileToWrite, "%i", 0);

        } else {
            for (i = 0; i <= fileSize; i++) {
                if (!RAND_bytes(&b, 1))
                    printf("Warning: CSPRNG bytes may not be unpredictable\n");
                fprintf(fileToWrite, "%c", 0);
            }
        }
        fclose(fileToWrite);
    }
    return 0;
}

/*Use stat() to check if a file exists. Returns 0 on success*/
int doesFileExist(const char* filename)
{
    struct stat st;
    int result = stat(filename, &st);
    return result;
}

/*Use stat() to return the filesize of file given at filename*/
int returnFileSize(const char* filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

/*OpenSSL EVP routines to encrypt in sealEnvelope()*/
/*Would be great to get these to work on memory buffers instead of files*/
/*Whenever I do however, EVP_EncryptFinal_ex only outputs 16 bytes of nonsense*/
/*Code was gleamed from OpenSSL man pages for EVP_EncryptInit*/
int dbEncrypt(FILE* in, FILE* out)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[EVP_BLOCK_SIZE], outbuf[EVP_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen, tlen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, evpCipher2, NULL, evpKey2, evpIv2);

    for (;;) {
        inlen = fread(inbuf, 1, EVP_BLOCK_SIZE, in);
        if (inlen <= 0)
            break;
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return 0;
}

/*OpenSSL EVP routines to decrypt*/
/*Basically the same operation but to be used in openEnvelope()*/
int dbDecrypt(FILE* in, FILE* out)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[EVP_BLOCK_SIZE], outbuf[EVP_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen, tlen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit(ctx, evpCipher2, evpKey2, evpIv2);

    for (;;) {
        inlen = fread(inbuf, 1, EVP_BLOCK_SIZE, in);
        if (inlen <= 0)
            break;
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    return 0;
}

/*To be honest I'm not really sure how this works*/
/*Borrowed from StackOverflow*/
/*https://stackoverflow.com/questions/47476427/get-a-list-of-all-supported-digest-algorithms*/
void encList(const OBJ_NAME* obj, void* arg)
{
    printf("Cipher: %s\n", obj->name);
}

/*Print out a list of cipher algorithms available to OpenSSL to use*/
/*Not ALL of these work.  *wrap and a couple of the efb and des ciphers fail*/
/*There's a full list in the file "non-working-ciphers"*/
/*There's also a script to check all the ciphers in "dev-tools"*/
void encLister()
{
    void* my_arg;
    OpenSSL_add_all_ciphers(); //make sure they're loaded

    my_arg = NULL;
    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encList, my_arg);
}

/*Same as encList but for message digest*/
void mdList(const OBJ_NAME* obj, void* arg)
{
    printf("Digest: %s\n", obj->name);
}

void mdLister()
{
    void* my_arg;
    OpenSSL_add_all_digests(); //make sure they're loaded

    my_arg = NULL;
    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, mdList, my_arg);
}
/*This function will load the appropriate cipher/digest structures based on user choice*/
int primeSSL()
{
    /*If the user has specified a cipher to use*/
    if (toggle.encCipher == 1 || encCipher[0] != 0) {
        evpCipher2 = EVP_get_cipherbyname(encCipher);
        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!evpCipher2) {
            fprintf(stderr, "no such cipher\n");
            return 1;
        }
    } else { /*If not default to aes-256-ctr*/
        strcpy(encCipher, "aes-256-ctr");
        evpCipher2 = EVP_get_cipherbyname(encCipher);
        if (!evpCipher2) { /*If that's not a valid cipher name*/
            fprintf(stderr, "no such cipher\n");
            return 1;
        }
    }

    /*If the user has specified a digest to use*/
    if (toggle.messageDigest == 1 || messageDigest[0] != 0) {
        evpDigest2 = EVP_get_digestbyname(messageDigest);
        if (!evpDigest2) {
            fprintf(stderr, "no such digest\n");
            return 1;
        }
    } else { /*If not default to sha512*/
        strcpy(messageDigest, "sha512");
        evpDigest2 = EVP_get_digestbyname(messageDigest);
        if (!evpDigest2) { /*If that's not a valid digest name*/
            fprintf(stderr, "no such digest\n");
            return 1;
        }
    }

    return 0;
}

int sealEnvelope(const char* tmpFileToUse)
{
    unsigned char cryptoBuffer[BUFFER_SIZES];
    if (!RAND_bytes(cryptoBuffer, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
    int yaxaDataSize = returnFileSize(tmpFileToUse);

    /*File handles to pass the information between*/
    FILE *EVPDecryptedFile, *yaxaDataFileTmp, *dbFile;

    /*Generate MAC from yaxaData written to temp file*/
    yaxaDataFileTmp = fopen(tmpFileToUse, "rb");
    if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*Read the enveloped yaxa data into a temporary buffer to hash it*/
    //nullReturn = fread(tmpBuffer, sizeof(char), yaxaDataSize, yaxaDataFileTmp);

    fclose(yaxaDataFileTmp);

    /*Now append new generated MAC to end of the YAXA data*/
    yaxaDataFileTmp = fopen(tmpFileToUse, "ab");
    if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*Copy yaxaDataFileTmp into a temp buffer then hash that buffer into gmac*/

    /*Append the MAC and close the file*/
    fwrite(gMac, sizeof(unsigned char), SHA512_DIGEST_LENGTH, yaxaDataFileTmp);
    fclose(yaxaDataFileTmp);

    /*Open YAXA+DATA file for reading, so we can use OpenSSL to encrypt it into the final password database file*/
    EVPDecryptedFile = fopen(tmpFileToUse, "rb"); /*Now open the file deletePass made to read in the yaxa data*/
    if (EVPDecryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*This will now be an EVPEncryptedFile but calling it dbFile to clarify it is the final step*/
    dbFile = fopen(dbFileName, "wb");
    if (dbFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }

    /*Write crypto information as a header*/

    /*Write encCipher:messageDigest to cryptoBuffer*/
    sprintf(cryptoBuffer, "%s:%s", encCipher, messageDigest);

    if (toggle.firstRun != 1) {
        /*Generates a random 8 byte string into buffer pointed to by saltBuff*/
        genSalt();
    }

    /*Write the salt*/
    fwrite(evpSalt, sizeof(unsigned char), EVP_SALT_SIZE, dbFile);

    /*Write the salt*/
    fwrite(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, dbFile);

	/*For Debugging Purposes*/
    //printf("\nyaxaSalt sealing with:");
    //for(int i=0; i < 8 ; i++)
    //printf("%x:", yaxaSalt[i] & 0xff);
    //printf("\n");

    /*Write buffer pointed to by cryptoBuffer*/
    fwrite(cryptoBuffer, sizeof(unsigned char), BUFFER_SIZES, dbFile);

    /*This function generates a key and possibly iv needed for encryption algorithims*/
    /*OpenSSL will generate appropriately sized values depending on which cipher and message digest are named*/
    if (!EVP_BytesToKey(evpCipher2, evpDigest2, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey2, evpIv2)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    /*Do the OpenSSL encryption*/
    if (dbEncrypt(EVPDecryptedFile, dbFile) != 0) {
        printf("\\nWrong key used.\n");
        printf("\nFilename: %s", tmpFile1);
        return 1;
    }

    /*Not really sure if this is needed, but just make sure that everything is written before closing the file*/
    /*Had some problems with fclose() before adding this but may have been unrelated*/
    fsync(fileno(EVPDecryptedFile));

    /*Close the files*/
    fclose(EVPDecryptedFile);
    fclose(dbFile);
    

    cleanUpFiles();

    return 0;
}

int openEnvelope()
{
    unsigned char cryptoHeader[BUFFER_SIZES];
    unsigned char* token;
    int i;

    /*This creates a temporary buffer to store the contents of the password file between read and writes to temporary files*/
    /*Also creates file handles to be used  for envelope and temporary files*/
    unsigned char* tmpBuffer;
    FILE *EVPEncryptedFile, *EVPDecryptedFile, *yaxaDataFileTmp;

    /*Open the OpenSSL encrypted envelope containing YAXA+MAC data*/
    EVPEncryptedFile = fopen(dbFileName, "rb");
    if (EVPEncryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }

    /*Grab the crypto information from header*/
    /*This will first contain the 8 byte salt for evpSalt*/
    /*Then an 8 byte salt for yaxaSalt*/
    /*Then will be the cipher and the message digest names delimited with ':'*/

    /*genSalt() allocates 8 bytes into saltBuff and filles it with random data*/
    genSalt();
    /*genSalt() allocates 8 bytes into evpSalt and filles it with random data*/
    /*fread overwrites the randomly generated salt with the one read from file*/
    nullReturn = fread(evpSalt, sizeof(unsigned char), EVP_SALT_SIZE, EVPEncryptedFile);

    nullReturn = fread(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, EVPEncryptedFile);

	/*For Debugging Purposes*/
    //printf("\nyaxaSalt opening:");
    //for(i=0; i < 8 ; i++)
    //printf("%x:", yaxaSalt[i] & 0xff);
    //printf("\n");

    /*Copy evpSalt to yaxaSalt*/
    yaxaKDF();

    /*Read the cipher and message digest information in*/
    nullReturn = fread(cryptoHeader, sizeof(unsigned char), BUFFER_SIZES, EVPEncryptedFile);

    /*Use strtok to parse the string delinieated by ':'*/

    /*First the cipher*/
    token = strtok(cryptoHeader, ":");
    if(token == NULL) {
		printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
		return 1;
	}
    strcpy(encCipher, token);

    /*Now the message digest*/
    token = strtok(NULL, ":");
    if(token == NULL) {
		printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
		return 1;
	}
    strcpy(messageDigest, token);

    /*Check that the ciphername retrieved was valid*/
    evpCipher2 = EVP_get_cipherbyname(encCipher);
    /*If the cipher doesn't exists or there was a problem loading it return with error status*/
    if (!evpCipher2) {
        fprintf(stderr, "Could not find valid cipher name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    /*Check that the digest name retrieved was valid*/
    evpDigest2 = EVP_get_digestbyname(messageDigest);
    if (!evpDigest2) {
        fprintf(stderr, "Could not find a valid digest name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    /*This function generates a key and possibly iv needed for encryption algorithims*/
    /*OpenSSL will generate appropriately sized values depending on which cipher and message digest are named*/
    if (!EVP_BytesToKey(evpCipher2, evpDigest2, evpSalt,
            (unsigned char*)dbPass,
            strlen(dbPass), strlen(dbPass) * PBKDF2_ITERATIONS, evpKey2, evpIv2)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    /*Now open a temporary file to write the decrypted YAXA+MAC into called tmpFile1*/
    yaxaDataFileTmp = fopen(tmpFile1, "wb");
    if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        printf("Could not open file: %s", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);

    /*Decrypted the OpenSSL envelope file into passman.tmp*/
    if (dbDecrypt(EVPEncryptedFile, yaxaDataFileTmp) != 0) {
        printf("\nWrong key used.\n");
        fclose(EVPEncryptedFile);
        fclose(yaxaDataFileTmp);
        wipeFile(tmpFile1);
        remove(tmpFile1);
        return 1;
    }

    /*Now close the encrypted envelope and temp file*/
    fclose(EVPEncryptedFile);
    fclose(yaxaDataFileTmp);

    /*a temp file whose name is pointed to by tmpFile1 now contains YAXA+MAC data*/
    /*Open the decrypted envelope to strip and authenticate the SHA512 MAC/

			/*Open YAXA+MAC from the temporary file*/
    EVPDecryptedFile = fopen(tmpFile1, "rb");
    if (EVPDecryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        printf("Could not open file: %s", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);

    /*Open a file to write the YAXA data into once we've stripped the MAC off*/
    yaxaDataFileTmp = fopen(tmpFile2, "wb");
    if (yaxaDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile2, S_IRUSR | S_IWUSR);

    /*Set EVPDecryptedFile file position to the beginning of the 512 bit MAC*/

    /*Need to get the size of the file, then fseek to that value minus the length SHA512 hash*/
    //Maybe use returnFileSize instead
    long fileSize;
    fseek(EVPDecryptedFile, 0L, SEEK_END);
    fileSize = ftell(EVPDecryptedFile);
    fseek(EVPDecryptedFile, fileSize - SHA512_DIGEST_LENGTH, SEEK_SET);

    /*Read the MAC from EVPDecryptedFile into buffer pointed to by fMac*/
    /*fMac for file MAC. Will compared this one against the one generated for gMac*/
    nullReturn = fread(fMac, sizeof(unsigned char), SHA512_DIGEST_LENGTH, EVPDecryptedFile);
    
    /*Reset to beginning of the EVPDecryptedFile file to get ready to copy it to tmpFile2*/
    fseek(EVPDecryptedFile, 0L, SEEK_SET);

    /*Allocate a buffer big enough for the EVPDecryptedFile file minus the 512 bit MAC*/
    tmpBuffer = malloc(sizeof(unsigned char) * (fileSize - SHA512_DIGEST_LENGTH));

    /*Read the YAXA data into the temp buffer, then write it out to tmpFile2*/
    nullReturn = fread(tmpBuffer, sizeof(unsigned char), fileSize - SHA512_DIGEST_LENGTH, EVPDecryptedFile);

    fwrite(tmpBuffer, sizeof(unsigned char), fileSize - SHA512_DIGEST_LENGTH, yaxaDataFileTmp);

    /*Close the temporary files used*/
    fclose(EVPDecryptedFile);
    fclose(yaxaDataFileTmp);

    /*Erase YAXA+MAC data left behind in EVPDecryptedFile (passman.tmp)*/
    /*wipeFile() will overwrite the file 25 times with zeroes*/
    wipeFile(tmpFile1);
    remove(tmpFile1);
    
    free(tmpBuffer);

    return 0;
}

/*Wipes and removes temporary files used*/
void cleanUpFiles()
{
    /*doesFileExist returns 0 if stat() can stat the file*/
    if (doesFileExist(tmpFile1) == 0) {
        wipeFile(tmpFile1);
        remove(tmpFile1);
    }
    if (doesFileExist(tmpFile2) == 0) {
        wipeFile(tmpFile2);
        remove(tmpFile2);
    }
    if (doesFileExist(tmpFile3) == 0) {
        wipeFile(tmpFile3);
        remove(tmpFile3);
    }
}

/*Allocate and randomize with OpenSSL's PRNG*/
void allocateBuffers()
{
    entryPass = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(entryPass, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    entryPassStore = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(entryPassStore, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    entryName = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(entryName, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    entryNameToSearch = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(entryNameToSearch, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    newEntry = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(newEntry, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    newEntryPass = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(newEntryPass, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    newEntryPassStore = malloc(sizeof(char) * BUFFER_SIZES);
    if (!RAND_bytes(newEntryPassStore, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

	/*yaxaKey nees to be allocated to 1025 bytes so that yaxaKey[1024] can be validly accessed*/
    yaxaKey = malloc(sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
    yaxaKey[YAXA_KEY_LENGTH] = 1;
    if (!RAND_bytes(yaxaKey, YAXA_KEY_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    dbPass = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPass, BUFFER_SIZES * 2))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    dbPassStore = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPassStore, BUFFER_SIZES * 2))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    dbPassOld = malloc(sizeof(unsigned char) * BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPassOld, BUFFER_SIZES * 2))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaKeyOld = malloc(sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
    yaxaKeyOld[YAXA_KEY_LENGTH] = 1;
    if (!RAND_bytes(yaxaKeyOld, YAXA_KEY_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaKeyChunk = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    if (!RAND_bytes(yaxaKeyChunk, SHA512_DIGEST_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaNonce = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    yaxaNonce[YAXA_NONCE_LENGTH] = 1;
    if (!RAND_bytes(yaxaNonce, YAXA_NONCE_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaNonceOld = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    yaxaNonceOld[YAXA_NONCE_LENGTH] = 1;
    if (!RAND_bytes(yaxaNonceOld, YAXA_NONCE_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaNonceNew = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    yaxaNonceNew[YAXA_NONCE_LENGTH] = 1;
    if (!RAND_bytes(yaxaNonceNew, YAXA_NONCE_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    hmacKey = malloc(sizeof(unsigned char) * YAXA_NONCE_LENGTH);
    if (!RAND_bytes(hmacKey, SHA512_DIGEST_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    hmacKeyOld = malloc(sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    if (!RAND_bytes(hmacKeyOld, SHA512_DIGEST_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
        
    hmacKeyNew = malloc(sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    if (!RAND_bytes(hmacKeyNew, SHA512_DIGEST_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaSalt = malloc(sizeof(unsigned char) * YAXA_SALT_SIZE);
    evpSalt = malloc(sizeof(unsigned char) * EVP_SALT_SIZE);
}

/*Fill up the buffers we stored the information in with 0's before exiting*/
void cleanUpBuffers()
{
	memset(entryPass,0,sizeof(unsigned char) * BUFFER_SIZES);
	memset(entryName,0,sizeof(unsigned char) * BUFFER_SIZES);
	memset(entryNameToSearch,0,sizeof(unsigned char) * BUFFER_SIZES);
	memset(newEntry,0,sizeof(unsigned char) * BUFFER_SIZES);
	memset(newEntryPass,0,sizeof(unsigned char) * BUFFER_SIZES);
	memset(yaxaKey,0,sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
	memset(dbPass,0,sizeof(unsigned char) * strlen(dbPass));
	memset(dbPassOld,0,sizeof(unsigned char) * BUFFER_SIZES * 2);
	memset(yaxaKeyArray,0,sizeof(unsigned char) * BUFFER_SIZES * 2);
	memset(yaxaKeyOld,0,sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
	memset(yaxaKeyChunk,0,sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
	memset(yaxaNonce,0,sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
	memset(yaxaNonceOld,0,sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
	memset(yaxaNonceNew,0,sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
	memset(evpKey2,0,sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
	memset(evpIv2,0,sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
	memset(fMac,0,sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
	memset(gMac,0,sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
  
}

/*This function generates a random passsword if 'gen' is given as the entry's password*/
void genPassWord(int stringLength)
{
    char b; /*Random byte*/
    char tempPassString[stringLength];
    int i = 0;

    /*Go until i has iterated over the length of the pass requested*/
    while (i < stringLength) {
        /*Gets a random byte from OpenSSL PRNG*/
        if (!RAND_bytes(&b, 1))
            printf("Warning: CSPRNG bytes may not be unpredictable\n");

        /*Tests that byte to be printable and not blank*/
        /*If it is it fills the temporary pass string buffer with that byte*/
        if (toggle.generateEntryPass == 1) {
            if (isalnum(b) != 0 || ispunct(b) != 0 && isblank(b) == 0) {
                tempPassString[i] = b;
                i++;
            }
        }

        if (toggle.generateEntryPassAlpha == 1) {
            if (isupper(b) != 0 || islower(b) != 0 || isdigit(b) != 0 && isblank(b) == 0) {
                tempPassString[i] = b;
                i++;
            }
        }
    }

    /*Insert a null byte at the end of the randome bytes*/
    /*Then send that to entryPass*/
    tempPassString[stringLength] = '\0';
    strcpy(entryPass, tempPassString);
}

char* genFileName()
{
    char b; /*Random byte*/
    char* fileNameBuffer = malloc(sizeof(char) * NAME_MAX);
    /*Allocate fileName buffer to be large enough to accomodate default temporary directory name*/
    char* fileName = malloc(sizeof(char) * NAME_MAX - strlen(P_tmpdir));
    int i = 0;

    /*Go until i has iterated over the length of the pass requested*/
    while (i < NAME_MAX) {
        /*Gets a random byte from OpenSSL PRNG*/
        RAND_bytes(&b, 1);

        /*Tests that byte to be printable and not blank*/
        /*If it is it fills the temporary pass string buffer with that byte*/
        if (isupper(b) != 0 || islower(b) != 0 || isdigit(b) != 0 && isblank(b) == 0) {
            fileNameBuffer[i] = b;
            i++;
        }
    }

	/*Add null byte at end of random string generated for filename*/
    fileNameBuffer[b % (NAME_MAX - strlen(P_tmpdir))] = '\0';

    /*Preced the sprintf string below with a . to make tmp files write to ./tmp/ for use in testing temp-file attacks*/
    sprintf(fileName, "%s/%s", P_tmpdir, fileNameBuffer);

    free(fileNameBuffer);

    return fileName;
}

/*Generates a random 8 byte salt for OpenSSL EVP_BytesToKey*/
/*Operates the same as genPassWord except only generates 8 bytes*/
void genSalt()
{

    char b; /*Random byte*/
    int i = 0;

    while (i < EVP_SALT_SIZE) {
        if (!RAND_bytes(&b, 1))
            printf("Warning: CSPRNG bytes may not be unpredictable\n");
        evpSalt[i] = b;
        i++;
    }
}

void genYaxaSalt()
{

    char b; /*Random byte*/
    int i = 0;

    while (i < YAXA_SALT_SIZE) {
        if (!RAND_bytes(&b, 1))
            printf("Warning: CSPRNG bytes may not be unpredictable\n");
        yaxaSalt[i] = b;
        i++;
    }
}

/*Puts an entry's password directly into the clipboard*/
/*System must have xclip installed*/
int sendToClipboard(char* textToSend)
{
    char xclipCommand[] = "xclip -in";
    char wipeCommand[] = "xclip -in";
    char wipeOutBuffer[strlen(textToSend)];
    memset(wipeOutBuffer, 0, strlen(textToSend));
    FILE* xclipFile = popen(xclipCommand, "w");
    FILE* wipeFile = popen(wipeCommand, "w");
    pid_t pid, sid;

    if (xclipFile == NULL) {
        perror("xclip");
        return errno;
    }
    fwrite(textToSend, sizeof(char), strlen(textToSend), xclipFile);
    if (pclose(xclipFile) == -1) {
        perror("xclip");
        return errno;
    }
    memset(textToSend, 0, strlen(textToSend));

    printf("\n%i seconds before password is cleared from clipboard\n", xclipClearTime);

    /*Going to fork off the application into the background, and wait 30 seconds to send 0s to the xclip clipboard*/
    /*This is so that we don't have to contain sensitive information in buffers while we wait*/

    /*Stops the parent process from waiting for child process to complete*/
    signal(SIGCHLD, SIG_IGN);

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(1);
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        return 0;
    }

    /* At this point we are executing as the child process */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(1);
    }

    signal(SIGHUP, SIG_IGN);

    sid = setsid();

    sleep(xclipClearTime);

    fwrite(wipeOutBuffer, sizeof(char), strlen(textToSend), wipeFile);

    exit(0);
}

/*Derive a cyrptographically secure key from the supplied database password*/
void yaxaKDF()
{

    int i;
    unsigned char hmacSalt[HMAC_SALT_SIZE];
    
	/*Use a counter of 3 so this XOR doesn't undo last xor'd bytes*/
    for (i = 0; i < HMAC_SALT_SIZE; i++)
        hmacSalt[i] = yaxaSalt[i] ^ (i + 3);


    //For Debugging Purposes
    //printf("\ndbPassRecieved: %ld\n",strlen(dbPass));
    //for(i=0; i < strlen(dbPass) + 1 ; i++)
    //printf("%x", dbPass[i]);
    //printf("\n");

    originalPassLength = strlen(dbPass);

    /*Generate 512bit yaxa nonce*/
    /*Must generate +1 byte for iterators to reach 64th element*/
    /*Must be able to access yaxaNonce[64] because iterating only to 63 results in periodic keystream after only 262400 bytes*/
    PKCS5_PBKDF2_HMAC(dbPass, -1, yaxaSalt, YAXA_SALT_SIZE, PBKDF2_ITERATIONS * originalPassLength, EVP_get_digestbyname("sha512"), YAXA_NONCEBUF_SIZE, yaxaNonce);
    
    /*Generate a separate key to use for HMAC*/    
    PKCS5_PBKDF2_HMAC(dbPass, -1, hmacSalt, HMAC_SALT_SIZE, PBKDF2_ITERATIONS * originalPassLength, EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, hmacKey);

    /*Generate 8192 bit yaxa key*/
    for (i = 0; i < YAXA_SALT_SIZE; i++) {
        PKCS5_PBKDF2_HMAC(dbPass, -1, yaxaSalt, YAXA_SALT_SIZE, PBKDF2_ITERATIONS * originalPassLength++ + yaxaSalt[i], EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, yaxaKeyChunk);
        memcpy(yaxaKeyArray[i], yaxaKeyChunk, SHA512_DIGEST_LENGTH);
    }

    //For Debugging Purposes
    //FILE* fileBufferFile = fopen("yaxaKeyArrayDerived.cap","wb");
    //fwrite(yaxaKeyArray,sizeof(unsigned char), 1025,fileBufferFile);
    //fclose(fileBufferFile);

    memcpy(yaxaKey, yaxaKeyArray, BUFFER_SIZES * 2);
    
    /*Generate a 1025th byte for yaxaKey, because the iterators need to be able to read yaxaKey[1024]*/
    /*If the iterators only reach yaxaKey[1023] the keystream generated in yaxa() will become periodic after only 262400 bytes*/
    /*If the iterators reach yaxaKey[1024] without this byte, it is always 0, but technically undefined behavior*/
    /*Going to generate 1 extra byte to prevent undefined behavior and predictability of that final byte*/
    yaxaKey[1024] = yaxaKey[1023] + yaxaKey[0];
    
    //For Debugging Purposes
    //fileBufferFile = fopen("yaxaKeyDerived.cap","wb");
    //fwrite(yaxaKey,sizeof(unsigned char), 1025,fileBufferFile);
    //fclose(fileBufferFile);
    
    

    ////For Debugging Purposes
    //printf("\ndbKeyDerived: %ld\n",strlen(dbPass));
    //for(i=0; i < strlen(dbPass) ; i++)
    //printf("%x", dbPass[i] & 0xff);
    //printf("\n");
    //printf("\nyaxaSalt in KDF:");
    //for(i=0; i < 8 ; i++)
    //printf("%x:", yaxaSalt[i] & 0xff);
    //printf("\n");
    //printf("\nevpSalt\n");
    //for(i=0; i < 8 ; i++)
    //printf("%x:", evpSalt[i] & 0xff);
    //printf("\n");
    //printf("\n");
    //printf("\nbigSalt:");
    //for(i=0; i < 16 ; i++)
    //printf("%x:", bigSalt[i] & 0xff);
    //printf("\n");
    //printf("\nhmacSalt:");
    //for(i=0; i < 16 ; i++)
    //printf("%x:", hmacSalt[i] & 0xff);
    //printf("\n");
}

unsigned char yaxa(unsigned char messageByte, unsigned char keyByte, unsigned char nonceByte)
{
	/*YAXA Algorithm*/
	
	/*E() = encryption and decryption function*/
	/*f() = keystream generator function*/
	/*g() = keycounter generator function*/
	/*KS = kestream*/
	/*KC = keycounter variable*/
	/*N = 65 byte nonce*/
	/*K = 1025 byte key*/
	/*C = Cipher-text byte*/
	/*P = Plain-text byte*/
	
	/*Subscript numbers except for KC's represet the array element being indexed*/
	/*KC's subscript numbers represent the actual value of KC*/
	
	/*At first byte of message*/
	/*C₀ = E(P₀ ⊕ N₀ ⊕ KS₀ = f(K₀ ⊕ KC₀ = g(KC₁ + 1)))*/
	
	/*At 64th byte of message*/
	/*Note N's index rolls over to 0 after 64*/
	/*C₆₄ = E(P₆₄ ⊕ N₆₄ ⊕ KS₆₄ = f(K₆₄ ⊕ KC₆₅ = g(KC₆₅ + 1)))*/
	/*C₆₅ = E(P₆₅ ⊕ N₀ ⊕ KS₆₅ = f(K₆₅ ⊕ KC₆₆ = g(KC₆₆ + 1)))*/
	
	/*At 1022th byte of message*/
	/*KC will equal 255 and roll over to 0
	/*C₁₀₂₂ = E(P₁₀₂₂ ⊕ N₄₇ ⊕ KS₁₀₂₂ = f(K₁₀₂₂ ⊕ KC₂₅₅ = g(KC₂₅₅ + 1)))*/
	/*C₁₀₂₃ = E(P₁₀₂₃ ⊕ N₄₈ ⊕ KS₁₀₂₃ = f(K₁₀₂₃ ⊕ KC₀ = g(KC₀ + 1)))*/
	
	/*At 1024th byte of message*/
	/*Note K's index rolls over to 0 after 1024*/
	/*C₁₀₂₄ = E(P₁₀₂₄ ⊕ N₄₉ ⊕ KS₁₀₂₄ = f(K₁₀₂₄ ⊕ KC₁ = g(KC₁ + 1)))*/
	/*C₁₀₂₅ = E(P₁₀₂₅ ⊕ N₅₀ ⊕ KS₁₀₂₅ = f(K₀ ⊕ KC₁₀₂₅ = g(KC₁₀₂₅ + 1)))*/
		
	/*'keyStreamGenByte ^ ...' represents the keystream generator function f()*/
	/*the incrementation of keyStreamGenByte via keyStreamGenByte++ fulfills keycounter function g()*/
	/*keyStreamGenByte will dually act as KC counter variable and generate KS byte*/
	/*return line acts as function E()*/
	
	/*with 1025 byte key buffer and 65 byte nonce buffer the keystream still becomes periodic after 3411200 byte*/
	/*if 1024 byte and 64 bytes were used instead, period would be at 262400 bytes*/
	
	/*KC/keyStreamGenByte can never be equal to more than 255 because writing it to a file will reduce it to char anyway*/
	
    return keyStreamGenByte++ ^ nonceByte ^ keyByte ^ messageByte;
}

void signalHandler(int signum)
{
    printf("\nCaught signal %d\n\nCleaning up temp files...\nCleaning up buffers...\n", signum);
    // Cleanup and close up stuff here

    cleanUpBuffers();
    cleanUpFiles();

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    // Terminate program
    exit(signum);
}

char* getPass(const char* prompt, unsigned char *paddedPass)
{
    size_t len = 0;
    
    if (!RAND_bytes(paddedPass, BUFFER_SIZES))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");
    size_t nread;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr(fileno(stdin), &termisOld) != 0)
        exit(-1);
    termiosNew = termisOld;
    termiosNew.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0)
        exit(-1);

    ///* Read the password. */
    printf("\n%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1)
        exit(1);
    else if(nread > BUFFER_SIZES) {
		/* Restore terminal. */
		(void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
		for(int i = 0; i < nread; i++)
		pass[i] = 0;
		free(pass);
		cleanUpBuffers();
		cleanUpFiles();
		printf("\nPassword was too large\n");
		exit(1);
		return NULL;
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    printf("\n");
    
    /*Remove sensitive data from memory*/
    for (int i = 0; i < strlen(pass) + 1; i++)
        paddedPass[i] = pass[i];
    for(int i = 0; i < nread; i++)
		pass[i] = 0;
	free(pass);
	
    return paddedPass;
}

int printMACErrMessage(char* backupFileName)
{
    printf("Message Authentication Failed. \
	\n If using CTR or OFB mode, this probably means the key was wrong\
	\n and/or otherwise, data integrity may be compromised \
	\n");

    return 0;
}

int printSyntax(char* arg)
{
    printf("\
\nReccomend Syntax: \
\n\n%s [-a entry name | -r entry name | -d entry name | -u entry name [-n new name ] | -U ] [-p new entry password] [-l random password length] [-x database password] [-c cipher] [-H digest] [ -P ] -f database file [ -C ] [ -s seconds ]\
\nOptions: \
\n-n new name - entry name up to 512 characters (can contain white space or special characters) \
\n-p new entry password - entry password up to 512 characters (don't call to be prompted instead) ('gen' will generate a random password, 'genalpha' will generate a random password with no symbols)\
\n-l random password length - makes 'gen' or 'genalpha' generate a password random password length digits long (defaults to 16 without this option) \
\n-x database password - To supply database password as command-line argument (not reccomended) \
\n-c cipher - Specify 'list' for a list of methods available to OpenSSL. Default: AES-256-CTR. \
\n-H digest - Specify 'list' for a list of methods available to OpenSSL. Default: SHA512. \
\n-P - In Update entry or Update database mode (-u and -U respectively) this option enables updating the entry password or database password via prompt instead of as command line argument \
\n-f - database file ( must be specified ) \
\n-C - end entry password directly to clipboard. Clipboard is cleared 30 seconds afterward. (needs xclip) \
\n-s seconds - clear clipboard seconds after instead of default 30 \
\n-h - Quick usage help \
\nEach functioning mode has a subset of applicable options \
\n-a - Add mode \
\n     \t-p 'password'\
\n     \t-l 'password length'\
\n     \t-x 'database password'\
\n     \t-c 'cipher' - Initializes a password database with cipher 'cipher'\
\n     \t-H 'md' - Initiailzes a password database with message digest 'md'.\
\n     \t-C send new entry's password to clipboard (useful if randomly generated)\
\n     \t-s seconds - clear clipboard seconds after instead of default 30\
\n-r - Read mode \
\n     \t-x 'database password'\
\n     \t-C  send a specified entry's password directly to clipboard \
\n     \t-s seconds - clear clipboard seconds after instead of default 30\
\n-d - Delete mode \
\n     \t-x 'database password'\
\n-u - Update entry mode \
\n     \t-P  updates entry name and password, getting password via user input instead of -p\
\n     \t-p 'password' - update the entry's password to 'password' \
\n     \t-l 'password length'\
\n     \t-n 'entry' - update the entry's name to 'entry'. Without this its assumed you're only changing entry's password. \
\n     \t-x 'database password'\
\n     \t-C send entry's new password directly to clipboard\
\n     \t-s seconds - clear clipboard seconds after instead of default 30\
\n-U - Update database mode \
\n     \t-P  updates database password. Read via prompt. Cannot be supplied via commandline. \
\n     \t-x 'database password' (the current database password to decrypt/with) \
\n     \t-c 'cipher' - Update to 'cipher'\
\n     \t-H 'md' - Update to 'digest'\
\nVersion 1.24.1\
\n\
",
        arg);
        printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return 1;
}
