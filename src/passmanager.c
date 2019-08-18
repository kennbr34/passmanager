/* Copyright 2019 Kenneth Brown */

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
#include <openssl/crypto.h>
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
#include <sys/mman.h>
#ifdef __linux__
#include <sys/capability.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>



/*Define a size in bytes for the buffers. The entry name and password are handled separately so combined they will make 1024 sized buffers*/
#define BUFFER_SIZES 512

//*Define sizes of salts*/
#define EVP_SALT_SIZE 16
#define HMAC_SALT_SIZE EVP_SALT_SIZE

/*Define block size for EVP ciphers to use*/
#define EVP_BLOCK_SIZE 1024

/*Default size of password if generation is chosen*/
#define DEFAULT_GENPASS_LENGTH 16

/*Naming the structure 'toggle' just makes it easy to remember these are option-toggle variables*/
/*If the value is 1 the option is true/on, if not the option is false/off*/
struct toggleStruct {
    int Add; /*To add a password to a file*/
    int Read; /*To read a password to a file*/
    int Delete; /*To delete an entry from a file*/
    int entryPassArg; /*To enable passing the password from the command line*/
    int dbPassArg; /*To enable passing the password from the command line*/
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
    int keyIterations; /*To toggle whether a user-specified iteration for KDF is used*/
    int firstRun; /*Keep track if it's the first run*/
    int generateEntryPass; /*Toggle to generate random entry pass*/
    int generateEntryPassAlpha; /*Toggle to generate alphanumeric pass*/
    int allPasses; /*Toggle to read or update allpasses*/
};

struct toggleStruct toggle;

/*Prototype functions*/

/*OpenSSL related functions*/
int primeSSL(); /*Loads EVP cipher and digest objects via name after user species them or parsed from file header*/
int openEnvelope(); /*Opens EVP encrypted envelope file and checks MAC attached*/
int sealEnvelope(const char* tmpFileToUse); /*Writes Message data to EVP ecncrypted envelope and attaches MAC*/
void mdList(const OBJ_NAME* obj, void* arg); /*Sets up structure objects needed to list message digests available to OpenSSL*/
void mdLister(); /*Lists the message digests available to OpenSSL*/
void encList(const OBJ_NAME* obj, void* arg); /*Same as mdList but for encryption ciphers*/
void encLister(); /*Same as mdLIster but for encryption ciphers*/
void genEvpSalt(); /*Generates EVP salt*/
void hmacKDF(); /*Derive key for HMAC*/
int evpKDF(char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv); /*Derive key for EVP cipher*/
/*Password management functions*/
int writePass(FILE* dbFile); /*Uses EVP cipher to write passes to a file*/
int printPasses(FILE* dbFile, char* searchString); /*Uses EVP cipher to read passes from file*/
int deletePass(FILE* dbFile, char* searchString); /*Uses EVP cipher to delete passes from a file*/
int updateEntry(FILE* dbFile, char* searchString); /*Updates entryName or entryName AND passWord*/
int updateEncPass(FILE* dbFile); /*Update database encryption password*/
/*Password input functions*/
void genPassWord(int stringLength); /*Generates an entry password if 'gen' is specifed*/
char* getPass(const char* prompt, char* paddedPass); /*Function to retrive passwords with no echo*/
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
int printMACErrMessage(void); /*Print MAC error information*/

/*OpenSSL variables*/

/*These are needed for OpenSSL key ring material*/
const EVP_CIPHER *evpCipher, *evpCipherOld;
unsigned char evpKey[EVP_MAX_KEY_LENGTH], evpKeyOld[EVP_MAX_KEY_LENGTH];
unsigned char evpIv[EVP_MAX_IV_LENGTH], evpIvOld[EVP_MAX_KEY_LENGTH];
const EVP_MD *evpDigest = NULL;

/*These hold the user-supplied password for the database encryption*/
char* dbPass; /*Will hold the user-supplied database password*/
char* dbPassStore; /*This stores the dbPass entered by the user to verify it was not mistyped*/
char* dbPassOld; /*Store old dbPassword for updateEncPass()*/

/*EVP cipher and MD name character arrays*/
char messageDigest[NAME_MAX]; /*Message digest name to send to EVP functions*/
char messageDigestStore[NAME_MAX]; /*Stores messageDigest given on commandline*/
char encCipher[NAME_MAX]; /*Cipher name to send to EVP functions*/
char encCipherStore[NAME_MAX]; /*Stores the encCipher given on commandline*/

/*Holds a 64 byte key derived in hmacKDF to be used in HMAC function*/
unsigned char *hmacKey, *hmacKeyNew, *hmacKeyOld;

/*Misc crypto variables*/

/*Salt*/
unsigned char* evpSalt; /*This stores the salt to use in EVPBytestoKey for the first/inner algorithm used*/
/*Buffers and variables needed for HMAC*/
unsigned char gMac[SHA512_DIGEST_LENGTH]; /*MAC generated from plain-text, thus gMac for generatedMac*/
unsigned char fMac[SHA512_DIGEST_LENGTH]; /*MAC read from file to check against, thus fMac for fileMac*/
unsigned int* gMacLength; /*HMAC() needs an int pointer to put the length of the mac generated into*/

/*KDF*/
int keyIterations = 200000; /*Default iterations to use for KDF*/

/*Character arrays to hold temp file random names*/
char* tmpFile1;
char* tmpFile2;
char* tmpFile3;

/*Backup and database file names*/
char dbFileName[NAME_MAX]; /*Password file name*/
char backupFileName[NAME_MAX]; /*Buffer to hold the name of backup file for passwords file which will be the same with a .autobak suffix*/

/*Input buffers*/
char* entryPass; /*Entry password*/
char* entryPassStore; /*Buffer to store password for verification checks*/
char* entryName; /*Entry name*/
char* entryNameToSearch; /*A buffer with an entry name to search for with updateEntry*/
char* newEntry; /*A buffer with an entry name to update to with updateEntry*/
char* newEntryPass; /*A buffer with a password to update an entry's password to with updateEntry*/
char* newEntryPassStore; /*A buffer to store previous mentioned password for verification*/
char* paddedPass; /*Holds pointer to buffer for user pass from getPass()*/

/*Misc variables*/

/*The amount of seconds to wait before clearing the clipboard if we send pass to it with xclip*/
/*This will default to 30 unless the user species -s n to set it to n seconds*/
int xclipClearTime = 30;

/*How long an entry password to generate if generation is specifed*/
int entryPassLength;

/*To store return values for checking*/
/*Made global in case a function needs to return something else to its caller*/
unsigned int returnVal;

/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
struct termios termisOld, termiosNew;

int main(int argc, char* argv[])
{
    /*Print help if no arguments given*/
    if (argc == 1) {
        printSyntax(argv[0]);
        return 1;
    }
    
    #ifdef __linux__
    /*Check for super user priveleges*/
    if(geteuid() != 0 && getuid() != 0) {
		printf("euid: %i uid: %i\n", geteuid(), getuid());
		printf("No priveleges to lock memory.  You may lose sensitive data to swap! Aborting.\n");
		exit(1);
	} else {
		/*Lock program memory*/	
		
		//printf("euid: %i uid: %i\n", geteuid(), getuid());

		/*Prevent core dump if program crashes*/
		struct rlimit rl;

		rl.rlim_cur = 0;
		rl.rlim_max = 0;

		setrlimit(RLIMIT_CORE,&rl);

		/*Need variables for libcap functions*/
		cap_t caps;
		cap_value_t cap_list[2];
		cap_value_t clear_list[1];
		caps = cap_get_proc();
		if (caps == NULL) {
			perror("libcap");
			exit(1);
		}
		cap_list[0] = CAP_IPC_LOCK;
		clear_list[0] = CAP_SYS_PTRACE;
		
		/*Set CAP_IPC_LOCK so we're not limited to a measely 32K of locked memory*/
		if (cap_set_flag(caps, CAP_EFFECTIVE,1, cap_list, CAP_SET) == -1) {
			perror("caplist CAP_EFFECTIVE");
			exit(1);
		}
		if (cap_set_flag(caps, CAP_INHERITABLE,1, cap_list, CAP_SET) == -1) {
			perror("caplit CAP INHERITABLE");
			exit(1);
		}
		/*Disable ptrace ability*/
		if (cap_set_flag(caps, CAP_EFFECTIVE,1, clear_list, CAP_CLEAR) == -1) {
			perror("clearlist CAP_EFFECTIVE");
			exit(1);
		}
		if (cap_set_flag(caps, CAP_INHERITABLE,1, clear_list, CAP_CLEAR) == -1) {
			perror("clearlist CAP INHERITABLE");
			exit(1);
		}
		if (cap_set_proc(caps) == -1) {
			perror("cap_set_proc");
			exit(1);
		}
		if (cap_free(caps) == -1) {
			perror("cap_free");
			exit(1);
		}
				
		/*Lock all current and future  memory from being swapped*/
		if ( mlockall(MCL_CURRENT|MCL_FUTURE) == -1 ) {
			perror("mlockall");
			exit(1);
		}
		
		/*Drop root*/
		if(geteuid() != 0) { /*If executable was not started as root, but given root privelge through SETUID/SETGID bit*/
			if(setuid(geteuid()) == -1) { /*Drop back to the privelges of the user who executed the binary*/
			perror("setuid");
			exit(1);
			}
			if(getuid() == 0) { /*Fail if we could not drop root priveleges*/
				printf("Could not drop root\n");
				exit(1);
			}
		}
	}
	#endif
    
    /*These calls will ensure that cleanUpFiles and cleanUpBuffers is ran after return call within main*/

    atexit(cleanUpFiles);
    atexit(cleanUpBuffers);

    allocateBuffers();

    signal(SIGINT, signalHandler);

    tmpFile1 = genFileName();
    tmpFile2 = genFileName();
    tmpFile3 = genFileName();

    /*These file handles refer to temporary and final files in the openEnvelope/sealEnvelope process*/
    /*EVPEncryptedFile is the EVP algorithm's cipher-text, which will also represent the final database file without its header*/
    /*EVPDecryptedFile is the EVP algorithm's plain-text*/
    /*EVPDataFileTmp is the EVP algorithm's cipher-text, which will be loaded into buffers for decryption and processing*/
    /*dbFile will contain salt and crypto information as a header, followed by the EVP algorithm's cipher-text, and MAC at end*/
    FILE *EVPEncryptedFile, *EVPDecryptedFile, *EVPDataFileTmp, *dbFile;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdLIster() and encLister() functions to work*/
    OpenSSL_add_all_algorithms();

    int opt; /*for getop()*/
    int errflg = 0; /*Toggle this flag on and off so we can check for errors and act accordingly*/

    int i;

    /*Process through arguments*/
    while ((opt = getopt(argc, argv, "i:s:l:f:u:n:d:a:r:p:x:H:c:hUPC")) != -1) {
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
        case 'i':
            if (optarg[0] == '-') {
                printf("Option -i requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            keyIterations = atoi(optarg);
            toggle.keyIterations = 1;
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
            strncpy(entryName, optarg, BUFFER_SIZES);
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
            strncpy(entryName, optarg, BUFFER_SIZES);
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
            strncpy(entryName, optarg, BUFFER_SIZES);
            toggle.entryGiven = 1;
            toggle.entrySearch = 1;
            break;
        case 'H': /*Hashing digest for PBKDF2 to use*/
            if (optarg[0] == '-') {
                printf("Option -H requires an operand\n");
                errflg++; /*Set the error flag so program will halt after getopt() is done*/
            }
            if (strcmp(optarg, "list") == 0) {
                mdLister();
                return 0;
            }
            toggle.messageDigest = 1;

            strncpy(messageDigest, optarg, NAME_MAX);

            /*Store command-line given parameters for use after messageDigest are read from file header*/
            strncpy(messageDigestStore, messageDigest, NAME_MAX);

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

            strncpy(encCipher, optarg, NAME_MAX);

            /*Store command-line given parameters for use after encCipher are read from file header*/
            strncpy(encCipherStore, encCipher, NAME_MAX);

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
                strncpy(dbFileName, optarg, NAME_MAX);
            }
            if (toggle.Read == 1) {
                dbFile = fopen(optarg, "rb");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }

                strncpy(dbFileName, optarg, NAME_MAX);
            }
            if (toggle.Delete == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strncpy(dbFileName, optarg, NAME_MAX);
            }
            if (toggle.updateEncPass == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strncpy(dbFileName, optarg, NAME_MAX);
            }
            if (toggle.updateEntry == 1) {
                dbFile = fopen(optarg, "rb+");
                if (dbFile == NULL) /*Make sure the file opens*/
                {
                    perror(optarg);
                    return errno;
                }
                strncpy(dbFileName, optarg, NAME_MAX);
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
            strncpy(entryName, optarg, BUFFER_SIZES);
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
            strncpy(entryNameToSearch, optarg, BUFFER_SIZES);
            break;
        case 'p': /*If passing entry password from command line*/
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
            strncpy(entryPass, optarg, BUFFER_SIZES);
            OPENSSL_cleanse(optarg, strlen(optarg));
            break;
        case 'x': /*If passing database password from command line*/
            toggle.dbPassArg = 1;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                errflg++; /*Set error flag*/
                printf("Option -x requires an operand\n");
            }
            strncpy(dbPass, optarg, BUFFER_SIZES);
            OPENSSL_cleanse(optarg, strlen(optarg));
            break;
        case ':':
            printf("Option -%c requires an operand\n", optopt);
            errflg++; /*Set error flag*/
            break;
        case '?': /*Get opt error handling, these check that the options were entered in correct syntax but not that the options are right*/
            //u:n:p:x:f:H:c:
            if (optopt == 'f')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 's')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            if (optopt == 'i')
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

    /*Sanitize argv and argc of any sensitive information*/
    for (i = 1; i < argc; i++)
        OPENSSL_cleanse(argv[i], strlen(argv[i]));

    /*If the user didn't specify a file with -f set error flag on*/
    if (toggle.fileGiven != 1)
        errflg++;
    /*Finally test for errflag and halt program if on*/
    if (errflg) {
        printSyntax("passmanger"); /*Print proper usage of program*/
        return 1;
    }

    /*Before anything else, back up the password database*/
    if (returnFileSize(dbFileName) != 0 && toggle.Read != 1) {
        strncpy(backupFileName, dbFileName, NAME_MAX);
        strncat(backupFileName, ".autobak", NAME_MAX);
        FILE* backUpFile = fopen(backupFileName, "w");
        if (backUpFile == NULL) {
            printf("Couldn't make a backup file. Be careful...\n");
        } else {
            FILE* copyFile = fopen(dbFileName, "r");
            char* backUpFileBuffer = calloc(sizeof(char), returnFileSize(dbFileName));
            returnVal = fread(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), copyFile);
            if (returnVal != returnFileSize(dbFileName) / sizeof(char)) {
                if (ferror(copyFile)) {
                    perror("backupfile read");
                    return errno;
                }
            }

            returnVal = fwrite(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), backUpFile);
            if (returnVal != returnFileSize(dbFileName) / sizeof(char))
            {
                if (ferror(backUpFile)) {
                    perror("backupile write");
                    return errno;
                }
            }
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
            getPass("Enter entry password to be saved: ", entryPass);

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
                getPass("Verify password:", entryPassStore);
                if (strcmp(entryPass, entryPassStore) != 0) {
                    printf("\nPasswords do not match.  Nothing done.\n\n");
                    cleanUpBuffers();
                    return 1;
                }
            }
        }

        /*Prompt for database password if not supplied as argument*/
        if (toggle.dbPassArg != 1) {
            getPass("Enter database password to encode with: ", dbPass);

            /*If this function returns 0 then it is the first time entering the database password so input should be verified*/
            if (returnFileSize(dbFileName) == 0) {
                getPass("Verify password:", dbPassStore);
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
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        /*If password file exists run openEnvelope on it*/
        if (returnFileSize(dbFileName) > 0) {
            if (openEnvelope() != 0) {
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            }
        } else {
            /*Otherwise run these functions to initialize a database*/
            genEvpSalt();
            hmacKDF();
            toggle.firstRun = 1;
        }

        /*openEnvelope has decrypted the EVP algorithm, and placed its plain-text into a tempfile whose randomly-generated name is in a buffer pointed to by tmpFile2*/

        /*Open EVP algorithm's cipher-text for decryption and processing*/
        /*In this case, appending a new entry to it*/
        EVPDataFileTmp = fopen(tmpFile2, "a+");
        if (EVPDataFileTmp == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*Derives a key for the EVP algorithm*/
        /*The choosen EVP digest algorithm will be used*/
        /*The salt generated for the EVP algorithm will also be used*/
        
		if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv) != 0) {
			return 1;
		}
		
        /*writePass() appends a new entry to EVPDataFileTmp encrypted with the EVP algorithm chosen*/
        int writePassResult = writePass(EVPDataFileTmp);

        if (writePassResult == 0) {
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

        EVPEncryptedFile = fopen(dbFileName, "rb");
        if (EVPEncryptedFile == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            return errno;
        }

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

        /*the file whose name is pointed to by tmpFile2 now contains EVP data with no MAC and can be passed to printPasses()*/
        EVPDataFileTmp = fopen(tmpFile2, "rb");
        if (EVPDataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            printf("Couldn't open file: %s\n", tmpFile2);
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

		
		if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv) != 0) {
			return 1;
		}

        if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") != 0) /*Find a specific entry to print*/
        {
            printPasses(EVPDataFileTmp, entryName); /*Decrypt and print pass specified by entryName*/
            if (toggle.sendToClipboard == 1) {
                printf("Sent password to clipboard. Paste with middle-click.\n");
            }
        } else if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") == 0)
            printPasses(EVPDataFileTmp, NULL); /*Decrypt and print all passess*/

        fclose(EVPDataFileTmp);
        fclose(EVPDecryptedFile);
        fclose(EVPEncryptedFile);
        fclose(dbFile);

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
            cleanUpBuffers();
            cleanUpFiles();
            printf("Couldn't open file: %s\n", tmpFile2);
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVPDataFileTmp = fopen(tmpFile2, "rb+");
        if (EVPDataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

		
		if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv) != 0) {
			return 1;
		}

        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified to a new temporary file*/
        int deletePassResult = deletePass(EVPDataFileTmp, entryName);

        fclose(EVPDataFileTmp);

        if (deletePassResult == 0) {

            /*After the password entry was deleted the rest of the passwords were written to a 3rd temporary file which is finalized into the password database file by sealEnvelope*/
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
            strncpy(newEntry, entryName, BUFFER_SIZES);
        } else {
            /*If no new entry was specified then just update the password*/
            strncpy(newEntry, entryNameToSearch, BUFFER_SIZES);
            toggle.updateEntryPass = 1;
        }

        /*If entry password to update to was supplied by command line argument*/
        if (toggle.entryPassArg == 1)
            toggle.updateEntryPass = 1;

        /*Get new pass*/
        if (toggle.updateEntryPass) {
            /*If entryPass supplied by command line, and generated randomly if it is 'gen'*/
            if (strcmp(entryPass, "gen") == 0) {
                if (toggle.entryPassLengthGiven == 1) {
                    toggle.generateEntryPass = 1;
                    genPassWord(entryPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                }
            } else if (strcmp(entryPass, "genalpha") == 0) {
                toggle.generateEntryPassAlpha = 1;
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
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
                        strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                    }
                } else if (strcmp(newEntryPass, "genalpha") == 0) {
                    toggle.generateEntryPassAlpha = 1;
                    printf("\nGenerating a random password\n");
                    if (toggle.entryPassLengthGiven == 1) {
                        genPassWord(entryPassLength);
                        /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                        strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                    }
                } else {
                    /*If retrieved password was not gen/genalpha verify it was not mistyped*/
                    getPass("Veryify password:", newEntryPassStore);
                    if (strcmp(newEntryPass, newEntryPassStore) != 0) {
                        printf("\nPasswords do not match.  Nothing done.\n\n");
                        cleanUpBuffers();
                        return 1;
                    }
                }
            } else if (toggle.entryPassArg == 1) /*This condition is true if the user DID supply a password but it isn't 'gen'*/
            {
                strncpy(newEntryPass, entryPass, BUFFER_SIZES);
            }
        }

        fclose(dbFile);

        /*Do OpenSSL priming operations*/
        if (primeSSL() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVPDataFileTmp = fopen(tmpFile2, "rb+");
        if (EVPDataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            printf("Couldn't open file: %s\n", tmpFile2);
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);
		
		if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv) != 0) {
			return 1;
		}

        /*Works like deletePass() but instead of excluding matched entry, modfies its buffer values and then outputs to 3rd temp file*/
        int updateEntryResult = updateEntry(EVPDataFileTmp, entryNameToSearch);

        fclose(EVPDataFileTmp);

        if (updateEntryResult == 0) {
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
            getPass("Enter current database password: ", dbPass);
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVPDataFileTmp = fopen(tmpFile2, "rb+");
        if (EVPDataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            printf("Couldn't open file: %s\n", tmpFile2);
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*Must store old EVP key data to decrypt database before new key material is generated*/
        strncpy(dbPassOld, dbPass, BUFFER_SIZES);
        memcpy(hmacKeyOld, hmacKey, sizeof(char) * SHA512_DIGEST_LENGTH);

        /*If -U was given but neither -c or -H*/
        if (toggle.updateEncPass == 1 && (toggle.encCipher != 1 && toggle.messageDigest != 1)) {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassStore);
            if (strcmp(dbPass, dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                /*If not changing, replace old dbPass back into dbPass*/
                strncpy(dbPass, dbPassOld, BUFFER_SIZES);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                hmacKDF();
                memcpy(hmacKeyNew, hmacKey, sizeof(char) * SHA512_DIGEST_LENGTH);
            }

            /*Change cipher and digest if specified*/
            if (toggle.encCipher == 1) {
                strncpy(encCipher, encCipherStore, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strncpy(messageDigest, messageDigestStore, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestStore);
            }
        }
        /*-U was given but not -P and -c and/or -H might be there*/
        else if (toggle.updateEncPass == 1 && toggle.updateEntryPass != 1) {
            if (toggle.encCipher == 1) {
                strncpy(encCipher, encCipherStore, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strncpy(messageDigest, messageDigestStore, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestStore);
            }
            memcpy(hmacKeyNew, hmacKey, sizeof(char) * SHA512_DIGEST_LENGTH);
        }
        /*If -P is given along with -c or -H*/
        else {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassStore);
            if (strcmp(dbPass, dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                strncpy(dbPass, dbPassOld, BUFFER_SIZES);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                hmacKDF();
                memcpy(hmacKeyNew, hmacKey, sizeof(char) * SHA512_DIGEST_LENGTH);
            }

            /*Change crypto settings*/
            if (toggle.encCipher == 1) {
                strncpy(encCipher, encCipherStore, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherStore);
            }
            if (toggle.messageDigest == 1) {
                strncpy(messageDigest, messageDigestStore, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestStore);
            }
        }

        /*Do OpenSSL priming operations*/
        /*This will change to the cipher just specified*/
        if (primeSSL() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        /*The updateEncPass function simply decrypts with the old key and cipher settings and re-encrypts with new key and/or cipher settings*/
        int updateEncPassResult = updateEncPass(EVPDataFileTmp);

        fclose(EVPDataFileTmp);

        if (updateEncPassResult == 0) {
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
    free(evpSalt);
    return 0;
}

int printPasses(FILE* dbFile, char* searchString)
{
    int i, ii;
    int entriesMatched = 0;
    
    char entryName[BUFFER_SIZES];

    int outlen, tmplen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* entryBuffer = calloc(sizeof(char), BUFFER_SIZES);
    unsigned char* passBuffer = calloc(sizeof(char), BUFFER_SIZES);
    unsigned char* encryptedBuffer = calloc(sizeof(char), fileSize + EVP_MAX_BLOCK_LENGTH);
    unsigned char* decryptedBuffer = calloc(sizeof(char), fileSize + EVP_MAX_BLOCK_LENGTH);

    /*Read the file into a buffer and check for error*/
    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (returnVal != fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            perror("printPasses fread encryptedBuffer");
            return errno;
        }
    }

    /*This will be the gMac, as in generated MAC*/
    unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
    unsigned char hmacBuffer[fileSize + IvLength];
    memcpy(hmacBuffer,evpIv,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via HMAC*/
    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage();

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
        /* Error */
        printf("EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen)) {
        /* Error */
        printf("EVP_DecryptFinal_ex failed \n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Loop to process the file.*/
    for (ii = 0; ii < outlen; ii += (BUFFER_SIZES * 2)) {

        /*Copy the decrypted information into entryBuffer and passBuffer*/
        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + BUFFER_SIZES];
        }
        
        memcpy(entryName,entryBuffer,BUFFER_SIZES);

        if (searchString != NULL) /*If an entry name was specified*/
        {
            /*Use strncmp and search the first n elements of entryBuffer, where n is the length of the search string*/
            /*This will allow the search of partial matches, or an exact match to be printed*/
            if (strncmp(searchString, entryName, strlen(searchString)) == 0) {
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

    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);

    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(ctx);

    return 0;
}

int updateEntry(FILE* dbFile, char* searchString)
{
    int i, ii = 0;
    int lastCheck = 0;
    int noEntryMatched = 1;
    int passLength;
    
    char entryName[BUFFER_SIZES];
    char passWord[BUFFER_SIZES];

    int outlen, tmplen;

    int numberOfSymbols = 0;

    unsigned char* fileBuffer;

    FILE* tmpFile;

    unsigned char* entryBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);
    unsigned char* passBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* encryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (returnVal != fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            perror("updateEntry fread encryptedBuffer");
            return errno;
        }
    }

    /*This will be the gMac as in generated MAC*/
    unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
	unsigned char hmacBuffer[fileSize + IvLength];
	memcpy(hmacBuffer,evpIv,IvLength);
	memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via HMAC*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage();

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    fileBuffer = calloc(sizeof(unsigned char), fileSize);

    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

    /*Decrypt file and store into decryptedBuffer*/
    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    for (ii = 0; ii < outlen; ii += (BUFFER_SIZES * 2)) {

        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + BUFFER_SIZES];
        }
        
        memcpy(entryName,entryBuffer,BUFFER_SIZES);
        memcpy(passWord,passBuffer,BUFFER_SIZES);

        /*If an entry matched searchString or allpasses was specified*/
        if ((lastCheck = strncmp(searchString, entryName, strlen(searchString))) == 0 || toggle.allPasses == 1) {

            /*A clunky boolean to test if any entries were matched*/
            noEntryMatched = 0;

            //Update content in entryName before encrypting back
            if (toggle.entryGiven == 1) {
                memcpy(entryBuffer, newEntry, BUFFER_SIZES);
            }

            /*This will preserve the alphanumeric nature of a password if it has no symbols*/
            if (toggle.allPasses == 1) {
				passLength = strlen(passWord);
                for (i = 0; i < passLength; i++) {
                    if (isupper(passBuffer[i]) == 0 && islower(passBuffer[i]) == 0 && isdigit(passBuffer[i]) == 0)
                        numberOfSymbols++;
                }

                if (numberOfSymbols == 0) {
                    toggle.generateEntryPassAlpha = 1;
                    toggle.generateEntryPass = 0;
                } else {
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
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                }
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);
                /*Do the same as above but if an alphanumeric pass was specified*/
            } else if (toggle.updateEntryPass == 1 && (toggle.generateEntryPassAlpha == 1 || toggle.allPasses == 1)) {
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, BUFFER_SIZES);
                }
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);
            }

            if (toggle.updateEntryPass == 1)
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);

            /*Copy the entryBuffer and passBuffer out to fileBuffer*/
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[ii + i] = entryBuffer[i];
                else
                    fileBuffer[(ii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
            if (toggle.entryGiven == 1)
                printf("Updating \"%s\" to \"%s\" ...\n", searchString, entryBuffer);
            else
                printf("Matched \"%s\" to \"%s\" (Updating...)\n", searchString, entryBuffer);
        } else { /*Write back the original entry and pass if nothing matched searchString*/
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[ii + i] = entryBuffer[i];
                else
                    fileBuffer[(ii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
        }
    }

    /*Clear out sensitive buffers ASAP*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(passWord, sizeof(char) * BUFFER_SIZES);

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), outlen + EVP_MAX_BLOCK_LENGTH);

    fileSize = outlen;

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    if (!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, fileBuffer, fileSize)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * fileSize);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    if (!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * fileSize);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Clear out fileBuffer ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * fileSize);

    /*Append this as the "generated" MAC later*/
    memcpy(hmacBuffer,evpIv,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,outlen);
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, outlen + IvLength, gMac, gMacLength);

    /*Check if any entries were updated*/
    if (noEntryMatched == 1) {
        printf("Nothing matched the entry specified, nothing was deleted.\n");
    } else
        printf("If you updated more than you intended to, restore from %s.autobak\n", dbFileName);

    /*Write the modified cipher-text to this temporary file for sealEnvelope()*/
    tmpFile = fopen(tmpFile3, "wb");
    if (tmpFile == NULL) {
        perror("updateEntry fwrite tmpFile3");
        printf("Couldn't open file: %s\n", tmpFile3);
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    /*Write the encryptedBuffer out and check for errors*/
    returnVal = fwrite(encryptedBuffer, outlen, sizeof(unsigned char), tmpFile);
    if (returnVal != outlen / sizeof(unsigned char))
    {
        if (ferror(tmpFile)) {
            perror("updateEntry fwrite encryptedBuffer");
            return errno;
        }
    }

    fclose(tmpFile);

    /*Free pointers used for buffers*/
    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(fileBuffer);
    free(ctx);

    return 0;
}

int deletePass(FILE* dbFile, char* searchString)
{
    int i, ii = 0, iii = 0;
    int lastCheck = 0;
    int entriesMatched = 0;
    
    char entryName[BUFFER_SIZES];

    int outlen, tmplen;

    unsigned char* fileBuffer;
    unsigned char* fileBufferOld;

    FILE* tmpFile;

    unsigned char* entryBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);
    unsigned char* passBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* encryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (returnVal != fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            perror("deletePass fread encryptedBuffer");
            return errno;
        }
    }

    /*This will be the gMac as in generated MAC*/
    unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
	unsigned char hmacBuffer[fileSize + IvLength];
	memcpy(hmacBuffer,evpIv,IvLength);
	memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via HMAC*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage();

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*Now make a buffer for the file.  Reallocate later if we find a match to delete*/
    fileBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

    /*Decrypt file and store into temp buffer*/
    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    for (ii = 0; ii < outlen; ii += (BUFFER_SIZES * 2)) {

        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + BUFFER_SIZES];
        }
        
        memcpy(entryName,entryBuffer,BUFFER_SIZES);

        /*Use strcmp to match the exact entry here*/
        if ((lastCheck = strncmp(searchString, entryName, strlen(searchString))) == 0) /*Now we're going to find the specific entry to delete it*/
        {
            if (ii == (outlen - (BUFFER_SIZES * 2))) /*If ii is one entry short of fileSize*/
            {
                if (entriesMatched < 1) /*If entry was matched we need to shrink the file buffer*/
                {
                    /*Re-size the buffer to reflect deleted passwords*/
                    /*Not using realloc() because it will leak and prevent wiping sensitive information*/
                    fileBufferOld = calloc(sizeof(unsigned char), outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    memcpy(fileBufferOld, fileBuffer, sizeof(unsigned char) * outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    free(fileBuffer);

                    fileBuffer = calloc(sizeof(unsigned char), outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    memcpy(fileBuffer, fileBufferOld, sizeof(unsigned char) * outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    OPENSSL_cleanse(fileBufferOld, sizeof(unsigned char) * outlen - ((BUFFER_SIZES * 2) * entriesMatched));
                    free(fileBufferOld);
                    
                    }
            }
            printf("Matched \"%s\" to \"%s\" (Deleting)...\n", searchString, entryBuffer);
            entriesMatched++;
        } else {
            for (i = 0; i < BUFFER_SIZES * 2; i++) {
                if (i < BUFFER_SIZES)
                    fileBuffer[iii + i] = entryBuffer[i];
                else
                    fileBuffer[(iii + BUFFER_SIZES) + (i - BUFFER_SIZES)] = passBuffer[i - BUFFER_SIZES];
            }
            iii += BUFFER_SIZES * 2;
        }
    }
    
    if(entriesMatched > 1)
		outlen = outlen - ((BUFFER_SIZES * 2) * entriesMatched);

    /*Clear out sensitive information ASAP*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * outlen);

    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), (outlen + EVP_MAX_BLOCK_LENGTH));
    
    fileSize = outlen;
    

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    if (!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, fileBuffer, outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * (fileSize - ((BUFFER_SIZES * 2) * entriesMatched)));
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    if (!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * (fileSize - ((BUFFER_SIZES * 2) * entriesMatched)));
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(fileBuffer);
        free(ctx);

        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Clear out sensitive information in fileBuffer ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * fileSize - ((BUFFER_SIZES * 2) * entriesMatched));

    /*Append this as the "generated" MAC later*/
    memcpy(hmacBuffer,evpIv,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,outlen );
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, outlen + IvLength, gMac, gMacLength);


    /*Write the modified cipher-text to this temporary file for sealEnvelope()*/
    tmpFile = fopen(tmpFile3, "wb");
    if (tmpFile == NULL) {
        perror("deletePass fwrite tmpFile3");
        printf("Couldn't open file: %s\n", tmpFile3);
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    if (entriesMatched < 1) {
        printf("Nothing matched that exactly.\n");
        returnVal = fwrite(encryptedBuffer, outlen, sizeof(unsigned char), tmpFile);
        if (returnVal != outlen / sizeof(unsigned char))
        {
            if (ferror(tmpFile)) {
                perror("deletePass fwrite encryptedBuffer");
                return errno;
            }
        }
    } else {
        printf("If you deleted more than you intended to, restore from %s.autobak\n", dbFileName);
        returnVal = fwrite(encryptedBuffer, outlen, sizeof(unsigned char), tmpFile);
        if (returnVal != outlen / sizeof(unsigned char))
        {
            if (ferror(tmpFile)) {
                perror("deletePass fwrite encryptedBuffer");
                return errno;
            }
        }
    }
    fclose(tmpFile);

    free(entryBuffer);
    free(passBuffer);
    free(encryptedBuffer);
    free(decryptedBuffer);
    free(fileBuffer);
    free(ctx);

    return 0;
}

int updateEncPass(FILE* dbFile)
{
    int outlen, tmplen;

    FILE* tmpFile;

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    unsigned char* encryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (returnVal != fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            perror("updateEncPass fread encryptedBuffer");
            return errno;
        }
    }

    /*This will be the gMac as in generated MAC*/
    unsigned int IvLength = EVP_CIPHER_iv_length(evpCipherOld);
    unsigned char hmacBuffer[fileSize + IvLength];
    memcpy(hmacBuffer,evpIvOld,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
    HMAC(EVP_sha512(), hmacKeyOld, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

    /*Check if the MAC from the EVPDecryptedFile matches MAC generated via HMAC)*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage();

        free(decryptedBuffer);
        free(encryptedBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    memcpy(hmacKey, hmacKeyOld, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    /*evpKDF() needs to run before ctx is initialized with EVP_CIPHER_CTX_new*/

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit(ctx, evpCipherOld, evpKeyOld, evpIvOld);

    /*Decrypted the data into decryptedBuffer*/

    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(decryptedBuffer);
        free(encryptedBuffer);
        free(ctx);
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(decryptedBuffer);
        free(encryptedBuffer);
        free(ctx);
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);
		
	if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv) != 0) {
			return 1;
	}

    memcpy(hmacKey, hmacKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    fileSize = outlen;

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    if (!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, decryptedBuffer, fileSize)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(decryptedBuffer);
        free(encryptedBuffer);
        free(ctx);
        return 1;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
    if (!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);
        free(decryptedBuffer);
        free(encryptedBuffer);
        free(ctx);
        return 1;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Clear sensitive data from decryptedBuffer ASAP*/
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize);

    /*Append this as the "generated" MAC later*/
    IvLength = EVP_CIPHER_iv_length(evpCipher);
    memcpy(hmacBuffer,evpIv,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

    tmpFile = fopen(tmpFile3, "wb"); /*Now open a temp file just to write the new evp data to, clean up in the calling function*/
    if (tmpFile == NULL) /*Make sure the file opens*/
    {
        perror("updateEncPass tmpFile3");
        printf("Couldn't open file: %s\n", tmpFile3);
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    returnVal = fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    if (returnVal != fileSize / sizeof(unsigned char))
    {
        if (ferror(tmpFile)) {
            perror("updateEncPass fwrite encryptedBuffer");
            return errno;
        }
    }
    fclose(tmpFile);

    free(decryptedBuffer);
    free(encryptedBuffer);
    free(ctx);

    return 0;
}

int writePass(FILE* dbFile)
{
    int i;
    long fileSize;

    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, tmplen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*Get the filesize*/
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    /*entryPass and entryName are both copied into infoBuffer, which is then encrypted*/
    unsigned char* infoBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES * 2);
    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH);
    unsigned char* encryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    /*Put the chars, include random whitespace ones, from entryName and entryPass into infoBuffer, again splitting the BUFFER_SIZES * 2 chars between the two*/
    for (i = 0; i < BUFFER_SIZES; i++)
        infoBuffer[i] = entryName[i];
    for (i = 0; i < BUFFER_SIZES; i++)
        infoBuffer[i + BUFFER_SIZES] = entryPass[i];

    /*Store encrypted file in buffer*/
    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (returnVal != fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            perror("writePass fread encryptedBuffer");
            return errno;
        }
    }

    if (toggle.firstRun != 1) {

        /*This will be the gMac as in generated MAC*/
        unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
		unsigned char hmacBuffer[fileSize + IvLength];
		memcpy(hmacBuffer,evpIv,IvLength);
		memcpy(hmacBuffer + IvLength,encryptedBuffer,fileSize);
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, fileSize + IvLength, gMac, gMacLength);

        /*Check if the MAC from the EVPDecryptedFile matches MAC generated via HMAC*/

        /*Return error status before proceeding and clean up sensitive data*/
        if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
            printMACErrMessage();
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);

            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }

        EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

        /*Decrypt file and store into decryptedBuffer*/
        if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * (fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

        if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + outlen, &tmplen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * (fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH));
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        outlen += tmplen;
        EVP_CIPHER_CTX_cleanup(ctx);
    }

    if (toggle.firstRun == 1) {
        EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);

        /*This looping operation is different than the one in printPasses, because it encrypts and writes the whole buffer to file*/

        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, infoBuffer, BUFFER_SIZES * 2)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/

        if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        outlen += tmplen;
        EVP_CIPHER_CTX_cleanup(ctx);

        /*Clear out sensitive information in infoBuffer ASAP*/
        OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);

        /*Append this as the "generated" MAC later*/
        unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
        unsigned char hmacBuffer[outlen + IvLength];
        memcpy(hmacBuffer,evpIv,IvLength);
        memcpy(hmacBuffer + IvLength,outbuf,outlen);
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, outlen + IvLength, gMac, gMacLength);;

        /*Write the encrypted information to file*/
        returnVal = fwrite(outbuf, 1, sizeof(unsigned char) * outlen, dbFile);
        if (returnVal != outlen * sizeof(unsigned char))
        {
            if (ferror(dbFile)) {
                perror("writePass fwrite outbuf");
                return errno;
            }
        }

    } else {

        EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);

        OPENSSL_cleanse(encryptedBuffer, sizeof(unsigned char) * fileSize);
        free(encryptedBuffer);
        encryptedBuffer = calloc(sizeof(unsigned char), outlen + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH);

        for (i = 0; i < BUFFER_SIZES * 2; i++) {
            decryptedBuffer[outlen + i] = infoBuffer[i];
        }

        OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);

        fileSize = outlen;

        if (!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, decryptedBuffer, fileSize + (BUFFER_SIZES * 2))) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * (fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH));
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        /* Buffer passed to EVP_EncryptFinal() must be after data just
			* encrypted to avoid overwriting it.
			*/
        if (!EVP_EncryptFinal_ex(ctx, encryptedBuffer + outlen, &tmplen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(ctx);
            OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * (fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH));
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);

            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }
        outlen += tmplen;
        EVP_CIPHER_CTX_cleanup(ctx);

        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + (BUFFER_SIZES * 2) + EVP_MAX_BLOCK_LENGTH);

		unsigned int IvLength = EVP_CIPHER_iv_length(evpCipher);
        unsigned char hmacBuffer[outlen + IvLength];
        memcpy(hmacBuffer,evpIv,IvLength);
        memcpy(hmacBuffer + IvLength,encryptedBuffer,outlen);
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, hmacBuffer, outlen + IvLength, gMac, gMacLength);

        fclose(dbFile);
        wipeFile(tmpFile2);
        dbFile = fopen(tmpFile2, "wb");

        returnVal = fwrite(encryptedBuffer, 1, outlen * sizeof(unsigned char), dbFile);
        if (returnVal != outlen * sizeof(unsigned char))
        {
            if (ferror(dbFile)) {
                perror("writePass fwrite encryptedBuffer");
                return errno;
            }
        }
    }

    free(infoBuffer);
    free(decryptedBuffer);
    free(encryptedBuffer);
    free(ctx);

    fclose(dbFile);
    return 0;
}

/*Over write the data we put in the temporary files with Schneier 7-Pass Method*/
/*https://en.wikipedia.org/wiki/Data_remanence#Feasibility_of_recovering_overwritten_data*/
/*https://en.wikipedia.org/wiki/Data_erasure#Standards*/
int wipeFile(const char* filename)
{
    int fileSize = returnFileSize(filename);
    int i, ii, passes = 7;
    unsigned char b;
    FILE* fileToWrite;
    for (ii = 0; ii <= passes; ii++) {
        fileToWrite = fopen(filename, "w+");
        if (fileToWrite == NULL) /*Make sure the file opens*/
        {
            perror("wipeFile");
            printf("Couldn't open file: %s\n", filename);
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
                if (!RAND_bytes(&b, 1)) {
                    printf("Failure: CSPRNG bytes could not be made unpredictable\n");
                }
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

/*To be honest I'm not really sure how this works*/
/*Borrowed from StackOverflow*/
/*https://stackoverflow.com/questions/47476427/get-a-list-of-all-supported-digest-algorithms*/
void encList(const OBJ_NAME* obj, void* arg)
{
	/*I don't want to use -Wno-unused-parameter to suppress compiler warnings*/
	/*So this does nothing with it to make gcc think it did something*/
	arg = arg;
	
    printf("Cipher: %s\n", obj->name);
}

/*Print out a list of cipher algorithms available to OpenSSL to use*/
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
	
	/*I don't want to use -Wno-unused-parameter to suppress compiler warnings*/
	/*So this does nothing with it to make gcc think it did something*/
	arg = arg;
	
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
/*Will also enforce CFB, OFB or CTR modes*/
int primeSSL()
{
    int i;

    /*If the user has specified a cipher to use*/
    if (toggle.encCipher == 1) {
		
		if(!EVP_get_cipherbyname(encCipher))
		{
			printf("Could not load cipher %s. Check that it is available with -c list\n", encCipher);
			return 1;
		}
		else
			evpCipher = EVP_get_cipherbyname(encCipher);

        /*Find start of mode*/
        for (i = strlen(encCipher); i > 0; i--) {
            if (encCipher[i] == '-') {
                break;
            }
        }

        /*If no hyphen present, and encCipher is not a stream cipher*/
        if (i == 0 && EVP_CIPHER_mode(EVP_get_cipherbyname(encCipher)) != EVP_CIPH_STREAM_CIPHER) {
            printf("Specify %s cipher with algorithm-bits-mode. Must be in OFB, CFB or CTR mode.\n", encCipher);
            return 1;
        } 

        if (EVP_CIPHER_mode(EVP_get_cipherbyname(encCipher)) == EVP_CIPH_STREAM_CIPHER || EVP_CIPHER_mode(EVP_get_cipherbyname(encCipher)) == EVP_CIPH_CFB_MODE || EVP_CIPHER_mode(EVP_get_cipherbyname(encCipher)) == EVP_CIPH_OFB_MODE || EVP_CIPHER_mode(EVP_get_cipherbyname(encCipher)) == EVP_CIPH_CTR_MODE) {
            evpCipher = EVP_get_cipherbyname(encCipher);
        } else {
            printf("\n%s specified\nCipher should be stream cipher or in OFB, CFB or CTR mode\n", encCipher);
            return 1;
        }

        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", encCipher);
            return 1;
        }

    } else { /*If not default to aes-256-ctr*/
        strcpy(encCipher, "aes-256-ctr");
        evpCipher = EVP_get_cipherbyname(encCipher);
        if (!evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", encCipher);
            return 1;
        }
    }

    /*If the user has specified a digest to use*/
    if (toggle.messageDigest == 1) {
        evpDigest = EVP_get_digestbyname(messageDigest);
        if (!evpDigest) {
            fprintf(stderr, "Could not load digest: %s Check if available with -H list\n", messageDigest);
            return 1;
        }
    } else { /*If not default to sha512*/
        strcpy(messageDigest, "sha512");
        evpDigest = EVP_get_digestbyname(messageDigest);
        if (!evpDigest) {
            fprintf(stderr, "Could not load digest: %s Check if available with -H list\n", messageDigest);
            return 1;
        }
    }

    return 0;
}

int sealEnvelope(const char* tmpFileToUse)
{
    char cryptoBuffer[BUFFER_SIZES];
    unsigned char *cryptoBufferPadding = calloc(sizeof(unsigned char),BUFFER_SIZES);
    int i;
    
    if (!RAND_bytes(cryptoBufferPadding, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        cleanUpBuffers();
        cleanUpFiles();
        exit(1);
    }
    memcpy(cryptoBuffer,cryptoBufferPadding,sizeof(char) * BUFFER_SIZES);
    free(cryptoBufferPadding);
    
    FILE *EVPDecryptedFile, *EVPDataFileTmp, *dbFile;
    
    /*Generate MAC from EVP data written to temp file*/
    EVPDataFileTmp = fopen(tmpFileToUse, "rb");
    if (EVPDataFileTmp == NULL) {
        perror("sealEnvelope fopen tmpFileToUse");
        printf("Couldn't open file: %s\n", tmpFileToUse);
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    fclose(EVPDataFileTmp);

    /*Now append new generated MAC to end of the EVP data*/
    EVPDataFileTmp = fopen(tmpFileToUse, "ab");
    if (EVPDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("sealEnvelope fopen tmpFileToUse");
        printf("Couldn't open file: %s\n", tmpFileToUse);
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*Append the MAC and close the file*/
    returnVal = fwrite(gMac, sizeof(unsigned char), SHA512_DIGEST_LENGTH, EVPDataFileTmp);
    if (returnVal != SHA512_DIGEST_LENGTH / sizeof(unsigned char))
    {
        if (ferror(EVPDataFileTmp)) {
            perror("sealEnvelope: fwrite gMac");
            return errno;
        }
    }
    fclose(EVPDataFileTmp);

    EVPDecryptedFile = fopen(tmpFileToUse, "rb");
    if (EVPDecryptedFile == NULL) {
        perror("sealEnvelope fopen tmpFileToUse");
        printf("Couldn't open file: %s\n", tmpFileToUse);
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*This will now be an EVPEncryptedFile but calling it dbFile to clarify it is the final step*/
    dbFile = fopen(dbFileName, "wb");
    if (dbFile == NULL) {
        perror("sealEnvelope fopen dbFileName");
        printf("Couldn't open file: %s\n", dbFileName);
        return errno;
    }

    /*Write crypto information as a header*/

    /*Write encCipher:messageDigest to cryptoBuffer*/
    snprintf(cryptoBuffer, BUFFER_SIZES, "%s:%s", encCipher, messageDigest);

    /*Write the salt*/
    returnVal = fwrite(evpSalt, sizeof(unsigned char), EVP_SALT_SIZE, dbFile);
    if (returnVal != EVP_SALT_SIZE / sizeof(unsigned char))
    {
        if (ferror(dbFile)) {
            perror("sealEnvelope fwrite evpSalt");
            return errno;
        }
    }

    /*Write buffer pointed to by cryptoBuffer*/
    returnVal = fwrite(cryptoBuffer, sizeof(unsigned char), BUFFER_SIZES, dbFile);
    if (returnVal != BUFFER_SIZES / sizeof(unsigned char))
    {
        if (ferror(dbFile)) {
            perror("sealEnvelope fwrite cryptoBuffer");
            return errno;
        }
    }
	
	for(i = 0; i < returnFileSize(tmpFileToUse); i++)
		fputc(fgetc(EVPDecryptedFile), dbFile);

    /*Close the files*/
    fclose(EVPDecryptedFile);
    fclose(dbFile);

    /*Cleanup temp files*/
    cleanUpFiles();

    return 0;
}

int openEnvelope()
{
    char cryptoHeader[BUFFER_SIZES];
    char* token;
    int i;

    /*a temporary buffer to store the contents of the password file between read and writes to temporary files*/
    char* tmpBuffer;

    /*file handles to be used  for envelope and temporary files*/
    FILE *EVPEncryptedFile, *EVPDecryptedFile, *EVPDataFileTmp;

    /*Open the OpenSSL encrypted envelope containing EVP Cipher Text + MAC data*/
    EVPEncryptedFile = fopen(dbFileName, "rb");
    if (EVPEncryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("openEnvelope fopen dbFileName");
        printf("Couldn't open file: %s\n", dbFileName);
        return errno;
    }

    /*Grab the crypto information from header*/
    /*Then an EVP_SALT_SIZE byte salt for evpSalt*/
    /*Then will be the cipher and the message digest names delimited with ':'*/

    /*fread overwrites the randomly generated salt with the one read from file*/

    returnVal = fread(evpSalt, sizeof(char), EVP_SALT_SIZE, EVPEncryptedFile);
    if (returnVal != EVP_SALT_SIZE / sizeof(char)) {
        if (ferror(EVPEncryptedFile)) {
            perror("openEnvelope fread evpSalt");
            return errno;
        }
    }

    /*Generate a separate salt and key for HMAC authentication*/
    hmacKDF();

    /*Read the cipher and message digest information in*/
    returnVal = fread(cryptoHeader, sizeof(char), BUFFER_SIZES, EVPEncryptedFile);
    if (returnVal != BUFFER_SIZES / sizeof(char)) {
        if (ferror(EVPEncryptedFile)) {
            perror("openEnvelope fread cryptoBuffer");
            return errno;;
        }
    }

    /*Use strtok to parse the strings delimited by ':'*/

    /*First the cipher*/
    token = strtok(cryptoHeader, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }
    strncpy(encCipher, token, NAME_MAX);

    token = strtok(NULL, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        cleanUpFiles();
        exit(1);
    }

    /*Then the message digest*/
    strncpy(messageDigest, token, NAME_MAX);

    /*Check the strings recieved are valid cipher and digest names*/
    evpCipher = EVP_get_cipherbyname(encCipher);
    /*If the cipher doesn't exists or there was a problem loading it return with error status*/
    if (!evpCipher) {
        fprintf(stderr, "Could not load cipher %s. Is it installed? Use -c list to list available ciphers\n", encCipher);
        return 1;
    }

    evpDigest = EVP_get_digestbyname(messageDigest);
    if (!evpDigest) {
        fprintf(stderr, "Could not load digest %s. Is it installed? Use -c list to list available ciphers\n", messageDigest);
        return 1;
    }

    if (toggle.updateEncPass) {
        /*Copy old evpCipher to evpCipherOld and generate evpKeyOld based on this*/
        /*This needs to be done in openEnvelope() before cipher and digest parameters are changed later on */
        evpCipherOld = evpCipher;
		
		if(evpKDF(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKeyOld,evpIvOld) != 0) {
			return 1;
		}
    }

    /*Now open a temporary file with a randomly generated file name pointed to by tmpFile1*/
    /*This file will contain the algorithm's decrypted plain-text, plus the MAC*/
    EVPDataFileTmp = fopen(tmpFile1, "wb");
    if (EVPDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("openEnvelope fopen tmpFile1");
        printf("Couldn't open file: %s\n", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);
		
	for(i = 0; i < returnFileSize(dbFileName) - (BUFFER_SIZES + EVP_SALT_SIZE); i++)
		fputc(fgetc(EVPEncryptedFile), EVPDataFileTmp);

    /*Now close the encrypted envelope and temp file*/
    fclose(EVPEncryptedFile);
    fclose(EVPDataFileTmp);

    /*Open EVP algorithm's cipher-text + MAC from the temporary file*/
    EVPDecryptedFile = fopen(tmpFile1, "rb");
    if (EVPDecryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("openEnvelope fopen tmpFile1");
        printf("Couldn't open file: %s\n", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);

    /*Open a file to write the cipher-text into once we've stripped the MAC off*/
    EVPDataFileTmp = fopen(tmpFile2, "wb");
    if (EVPDataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("openEnvelope fopen tmpFile2");
        printf("Couldn't open file: %s\n", tmpFile2);
        return errno;
    }
    chmod(tmpFile2, S_IRUSR | S_IWUSR);

    /*Set EVPDecryptedFile file position to the beginning of the SHA512_DIGEST_LENGTH sized MAC*/

    /*Need to get the size of the file, then fseek to that value minus the length SHA512_DIGEST_LENGTH sized MAC*/
    long fileSize;
    fseek(EVPDecryptedFile, 0L, SEEK_END);
    fileSize = ftell(EVPDecryptedFile);
    fseek(EVPDecryptedFile, fileSize - SHA512_DIGEST_LENGTH, SEEK_SET);

    /*Read the MAC from EVPDecryptedFile into buffer pointed to by fMac*/
    /*fMac for file MAC. Will compare this one against the one generated for gMac*/
    returnVal = fread(fMac, sizeof(char), SHA512_DIGEST_LENGTH, EVPDecryptedFile);
    if (returnVal != SHA512_DIGEST_LENGTH / sizeof(char)) {
        if (ferror(EVPDecryptedFile)) {
            perror("openEnvelope fread fMac");
            return errno;
        }
    }

    /*Reset to beginning of the EVPDecryptedFile file to get ready to copy it to tmpFile2*/
    fseek(EVPDecryptedFile, 0L, SEEK_SET);

    /*Allocate a buffer big enough for the EVPDecryptedFile file minus the MAC*/
    tmpBuffer = calloc(sizeof(char), (fileSize - SHA512_DIGEST_LENGTH));

    /*Read the cipher-text data into the temp buffer, then write it out to tmpFile2*/
    returnVal = fread(tmpBuffer, sizeof(char), fileSize - SHA512_DIGEST_LENGTH, EVPDecryptedFile);
    if (returnVal != fileSize - SHA512_DIGEST_LENGTH / sizeof(char)) {
        if (ferror(EVPDecryptedFile)) {
            perror("openEnvelope fread tmpBuffer");
            return errno;
        }
    }

    returnVal = fwrite(tmpBuffer, sizeof(char), fileSize - SHA512_DIGEST_LENGTH, EVPDataFileTmp);
    if (returnVal != fileSize - SHA512_DIGEST_LENGTH / sizeof(char))
    {
        if (ferror(EVPDataFileTmp)) {
            perror("openEnvelope fwrite tmpBuffer");
            return errno;
        }
    }

    /*Close the temporary files used*/
    fclose(EVPDecryptedFile);
    fclose(EVPDataFileTmp);

    /*Erase data left behind in EVPDecryptedFile*/
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
	unsigned char *tmpBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);
	
    entryPass = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(entryPass,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    entryPassStore = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
	memcpy(entryPassStore,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    entryName = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(entryName,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    entryNameToSearch = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(entryNameToSearch,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    newEntry = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(entryPass,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    newEntryPass = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(newEntryPass,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    newEntryPassStore = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(newEntryPassStore,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    dbPass = calloc(sizeof(unsigned char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(dbPass,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    dbPassStore = calloc(sizeof(unsigned char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(dbPassStore,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    dbPassOld = calloc(sizeof(unsigned char), BUFFER_SIZES);
    if (!RAND_bytes(tmpBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }
    memcpy(dbPassOld,tmpBuffer,sizeof(unsigned char) * BUFFER_SIZES);

    hmacKey = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if (!RAND_bytes(hmacKey, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    hmacKeyOld = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if (!RAND_bytes(hmacKeyOld, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    hmacKeyNew = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if (!RAND_bytes(hmacKeyNew, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    evpSalt = calloc(sizeof(unsigned char), EVP_SALT_SIZE);
    
    free(tmpBuffer);
}

/*Fill up the buffers we stored the information in with 0's before exiting*/
void cleanUpBuffers()
{
    OPENSSL_cleanse(entryPass, sizeof(char) * BUFFER_SIZES);
    OPENSSL_cleanse(entryPassStore, sizeof(char) * BUFFER_SIZES);
    OPENSSL_cleanse(newEntryPass, sizeof(char) * BUFFER_SIZES);
    OPENSSL_cleanse(newEntryPassStore, sizeof(char) * BUFFER_SIZES);
    OPENSSL_cleanse(dbPass, sizeof(unsigned char) * strlen(dbPass));
    OPENSSL_cleanse(dbPassOld, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(dbPassStore, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(evpKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(evpIv, sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(evpKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(evpIvOld, sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    OPENSSL_cleanse(hmacKeyOld, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    OPENSSL_cleanse(hmacKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH); 

}

/*This function generates a random passsword if 'gen' is given as the entry's password*/
void genPassWord(int stringLength)
{
    unsigned char b; /*Random byte*/
    char tempPassString[stringLength];
    int i = 0;

    /*Go until i has iterated over the length of the pass requested*/
    while (i < stringLength) {
        /*Gets a random byte from OpenSSL PRNG*/
        if (!RAND_bytes(&b, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            cleanUpBuffers();
            cleanUpFiles();
            exit(1);
        }

        /*Tests that byte to be printable and not blank*/
        /*If it is it fills the temporary pass string buffer with that byte*/
        if (toggle.generateEntryPass == 1) {
            if ((isalnum(b) != 0 || ispunct(b) != 0) && isblank(b) == 0) {
                tempPassString[i] = b;
                i++;
            }
        }

        if (toggle.generateEntryPassAlpha == 1) {
            if ((isupper(b) != 0 || islower(b) != 0 || isdigit(b) != 0) && isblank(b) == 0) {
                tempPassString[i] = b;
                i++;
            }
        }
    }

    /*Insert a null byte at the end of the randome bytes*/
    /*Then send that to entryPass*/
    tempPassString[stringLength] = '\0';
    strncpy(entryPass, tempPassString, BUFFER_SIZES);
}

char* genFileName()
{
    unsigned char b; /*Random byte*/
    char* fileNameBuffer = calloc(sizeof(char), NAME_MAX);
    /*Allocate fileName buffer to be large enough to accomodate default temporary directory name*/
    char* fileName = calloc(sizeof(char), NAME_MAX - strlen(P_tmpdir));
    int i = 0;

    /*Go until i has iterated over the length of the pass requested*/
    while (i < NAME_MAX) {
        /*Gets a random byte from OpenSSL PRNG*/
        RAND_bytes(&b, 1);

        /*Tests that byte to be printable and not blank*/
        /*If it is it fills the temporary pass string buffer with that byte*/
        if ((isupper(b) != 0 || islower(b) != 0 || isdigit(b) != 0) && isblank(b) == 0) {
            fileNameBuffer[i] = b;
            i++;
        }
    }

    /*Add null byte at end of random string generated for filename*/
    fileNameBuffer[b % (NAME_MAX - strlen(P_tmpdir))] = '\0';

    /*Preced the sprintf string below with a . to make tmp files write to ./tmp/ for use in testing temp-file attacks*/
    snprintf(fileName, NAME_MAX, "%s/%s", P_tmpdir, fileNameBuffer);

    free(fileNameBuffer);

    return fileName;
}

void genEvpSalt()
{

    unsigned char b; /*Random byte*/
    int i = 0;

    while (i < EVP_SALT_SIZE) {
        if (!RAND_bytes(&b, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            cleanUpBuffers();
            cleanUpFiles();
            exit(1);
        }
        evpSalt[i] = b;
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
    char *passBuffer = calloc(sizeof(char), strlen(textToSend));
    OPENSSL_cleanse(wipeOutBuffer, strlen(textToSend));
    FILE* xclipFile = popen(xclipCommand, "w");
    FILE* wipeFile = popen(wipeCommand, "w");
    pid_t pid, sid;
    
    strncpy(passBuffer,textToSend,strlen(textToSend));

    if (xclipFile == NULL) {
        perror("xclip");
        return errno;
    }
    returnVal = fwrite(passBuffer, sizeof(char), strlen(passBuffer), xclipFile);
    if (returnVal != strlen(passBuffer) / sizeof(char))
    {
        if (ferror(xclipFile)) {
            perror("xclip");
			return errno;
        }
    }
    if (pclose(xclipFile) == -1) {
        perror("xclip");
        return errno;
    }
    OPENSSL_cleanse(passBuffer, strlen(passBuffer));
    OPENSSL_cleanse(textToSend,strlen(textToSend));

    printf("\n%i seconds before password is cleared from clipboard\n", xclipClearTime);

    /*Going to fork off the application into the background, and wait 30 seconds to send zeroes to the xclip clipboard*/
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

    /*Tells child process to ignore sighup so the child doesn't exit when the parent does*/
    signal(SIGHUP, SIG_IGN);

    sid = setsid();
    
    cleanUpBuffers();
    
    sleep(xclipClearTime);

    returnVal = fwrite(wipeOutBuffer, sizeof(char), strlen(passBuffer), wipeFile);
    if (returnVal != strlen(passBuffer) / sizeof(char))
    {
        if (ferror(wipeFile)) {
            perror("sendToClipboard fwrite wipeOutBuffer");
            return errno;
        }
    }

    exit(0);
}

/*Derive a secondary key for HMAC to use*/
void hmacKDF()
{

    int i;
    unsigned char hmacSalt[HMAC_SALT_SIZE];

    /*Derive a larger salt for HMAC from evpSalt*/
    /*Use a counter of 3 so this XOR doesn't undo last xor'd bytes*/
    for (i = 0; i < HMAC_SALT_SIZE; i++)
        hmacSalt[i] = evpSalt[i] ^ (i + 3);

    /*Generate a separate key to use for HMAC*/
    PKCS5_PBKDF2_HMAC(dbPass, -1, hmacSalt, HMAC_SALT_SIZE, keyIterations, EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, hmacKey);
}

int evpKDF(char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv)
{
	/*First generate the key*/
	if (!PKCS5_PBKDF2_HMAC((char*)dbPass, strlen(dbPass),
		evpSalt, saltLen,
		keyIterations,
		evpDigest,EVP_CIPHER_key_length(evpCipher),
		evpKey)) {
        fprintf(stderr, "PBKDF2 failed\n");
        return 1;
    }
    
    /*If this cipher uses an IV, generate that as well*/
    if(EVP_CIPHER_iv_length(evpCipher) != 0) {
		if (!PKCS5_PBKDF2_HMAC((char*)dbPass, strlen(dbPass),
		    evpSalt, saltLen,
            keyIterations,
            evpDigest,EVP_CIPHER_iv_length(evpCipher),
            evpIv)) {
        fprintf(stderr, "PBKDF2 failed\n");
        return 1;
		}
	}
	
	return 0;
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

char* getPass(const char* prompt, char* paddedPass)
{
    size_t len = 0;
    int i;
    int passLength;
    char* pass = NULL;
    unsigned char *paddedPassTmp = calloc(sizeof(unsigned char), BUFFER_SIZES);


    if (!RAND_bytes(paddedPassTmp, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        cleanUpBuffers();
        cleanUpFiles();
        printf("\nPassword was too large\n");
        exit(1);
    }
    memcpy(paddedPass,paddedPassTmp,sizeof(char) * BUFFER_SIZES);
    OPENSSL_cleanse(paddedPassTmp, sizeof(char) * BUFFER_SIZES);
    free(paddedPassTmp);
    
    int nread;

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
    else if (nread > BUFFER_SIZES) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        OPENSSL_cleanse(pass, sizeof(char) * nread);
        free(pass);
        cleanUpBuffers();
        cleanUpFiles();
        printf("\nPassword was too large\n");
        exit(1);
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    printf("\n");

    /*Copy pass into paddedPass then remove sensitive information*/
    passLength = strlen(pass);
    for (i = 0; i < passLength + 1; i++)
        paddedPass[i] = pass[i];

    OPENSSL_cleanse(pass, sizeof(char) * nread);
    free(pass);

    return paddedPass;
}

int printMACErrMessage(void)
{
    printf("Message Authentication Failed\nWrong password?\n");

    return 0;
}

int printSyntax(char* arg)
{
    printf("\
\nReccomend Syntax: \
\n\n%s [-a entry name | -r entry name | -d entry name | -u entry name [-n new name ] | -U ] [-p new entry password] [-l random password length] [-x database password] [-c cipher ] [-H digest ] [ -P ] -f database file [ -C ] [ -s seconds ]\
\nOptions: \
\n-n new name - entry name up to 512 characters (can contain white space or special characters) \
\n-p new entry password - entry password up to 512 characters (don't call to be prompted instead) ('gen' will generate a random password, 'genalpha' will generate a random password with no symbols)\
\n-l random password length - makes 'gen' or 'genalpha' generate a password random password length digits long (defaults to 16 without this option) \
\n-x database password - To supply database password as command-line argument (not reccomended) \
\n-c cipher - Specify 'list' for a list of methods available to OpenSSL. Default: aes-256-ctr. \
\n-H digest - Specify 'list' for a list of methods available to OpenSSL. Default: sha512. \
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
\n     \t-c 'cipher' - Initializes a password database with encryption of 'cipher' \
\n     \t-H 'digest' - Derives keys for 'cipher' with digest 'digest'.\
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
\n     \t-c 'cipher' - Update encryption algorithm  \
\n     \t-H 'digest' - Update digest used for algorithms' KDFs \
\nVersion 3.0\
\n\
",
        arg);
    printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return 1;
}
