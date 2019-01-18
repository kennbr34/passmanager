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
#define EVP2_SALT_SIZE 16
#define EVP1_SALT_SIZE 16
#define HMAC_SALT_SIZE EVP1_SALT_SIZE

/*Define block sizes for dbDecrypt and dbEncrypt to use*/
#define EVP_BLOCK_SIZE 1024

/*The default PBKDF2 iteration count as per RFC 2889 reccomendation*/
/*The final iteration will differ from this depending on length of user pass and salts generated*/
#define RFC_2889_REC_ITERATIONS 1000

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
void genEvp2Salt(); /*Generates an 8byte random salt to be used by EVP*/
int dbDecrypt(FILE* in, FILE* out); /*OpenSSSL EVP decryption routine*/
int dbEncrypt(FILE* in, FILE* out); /*OpenSSL EVP encryption routine*/
int sealEnvelope(const char* tmpFileToUse); /*Writes Message data to EVP ecncrypted envelope and attaches MAC*/
void mdList(const OBJ_NAME* obj, void* arg); /*Sets up structure objects needed to list message digests available to OpenSSL*/
void mdLister(); /*Lists the message digests available to OpenSSL*/
void encList(const OBJ_NAME* obj, void* arg); /*Same as mdList but for encryption ciphers*/
void encLister(); /*Same as mdLIster but for encryption ciphers*/
void genEvp1Salt(); /*Generates EVP1 salt*/
void hmacKDF(); /*Derive key for HMAC*/
int evpKDF(unsigned char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv); /*Derive key for EVP ciphers*/
/*Password management functions*/
int writePass(FILE* dbFile); /*Uses EVP1 cipher to write passes to a file*/
int printPasses(FILE* dbFile, char* searchString); /*Uses EVP1 cipher to read passes from file*/
int deletePass(FILE* dbFile, char* searchString); /*Uses EVP1 cipher to delete passes from a file*/
int updateEntry(FILE* dbFile, char* searchString); /*Updates entryName or entryName AND passWord*/
int updateEncPass(FILE* dbFile); /*Update database encryption password*/
/*Password input functions*/
void genPassWord(int stringLength); /*Generates an entry password if 'gen' is specifed*/
char* getPass(const char* prompt, unsigned char* paddedPass); /*Function to retrive passwords with no echo*/
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
/*evpCipher1 will be the first/inner algorithm choosen*/
/*evpCipher2 will be the second/outer algorithm choosen*/
const EVP_CIPHER *evpCipher1, *evpCipher1Old, *evpCipher2;
unsigned char evpKey1[EVP_MAX_KEY_LENGTH], evpKey1Old[EVP_MAX_KEY_LENGTH], evpKey2[EVP_MAX_KEY_LENGTH];
unsigned char evpIv1[EVP_MAX_IV_LENGTH], evpIv1Old[EVP_MAX_KEY_LENGTH], evpIv2[EVP_MAX_IV_LENGTH];
const EVP_MD *evpDigest1 = NULL, *evpDigest2 = NULL;

/*These hold the user-supplied password for the database encryption*/
unsigned char* dbPass; /*Will hold the user-supplied database password*/
unsigned char* dbPassStore; /*This stores the dbPass entered by the user to verify it was not mistyped*/
unsigned char* dbPassOld; /*Store old dbPassword for updateEncPass()*/

/*EVP cipher and MD name character arrays*/
char messageDigest1[NAME_MAX], messageDigest2[NAME_MAX]; /*Message digest name to send to EVP functions*/
char messageDigestStore1[NAME_MAX], messageDigestStore2[NAME_MAX]; /*Stores messageDigest given on commandline*/
char encCipher1[NAME_MAX], encCipher2[NAME_MAX]; /*Cipher name to send to EVP functions*/
char encCipherStore1[NAME_MAX], encCipherStore2[NAME_MAX]; /*Stores the encCipher given on commandline*/

/*Holds a 64 byte key derived in hmacKDF to be used in HMAC function*/
unsigned char *hmacKey, *hmacKeyNew, *hmacKeyOld;

/*Misc crypto variables*/

/*Salts*/
unsigned char* evp2Salt; /*This stores the salt to use in EVPBytestoKey for the second/outer algorithm used*/
unsigned char* evp1Salt; /*This stores the salt to use in EVPBytestoKey for the first/inner algorithm used*/
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
char* entryPassStore; /*Buffer to store password for verification checks*/
char* entryName; /*Entry name*/
char* entryNameToSearch; /*A buffer with an entry name to search for with updateEntry*/
char* newEntry; /*A buffer with an entry name to update to with updateEntry*/
char* newEntryPass; /*A buffer with a password to update an entry's password to with updateEntry*/
char* newEntryPassStore; /*A buffer to store previous mentioned password for verification*/
char* pass = NULL; /*Used in getPass() for getline()*/ /*Then why isn't it local*?*/
char* paddedPass; /*Holds pointer to buffer for user pass from getPass()*/

/*Misc variables*/

/*The amount of seconds to wait before clearing the clipboard if we send pass to it with xclip*/
/*This will default to 30 unless the user species -s n to set it to n seconds*/
int xclipClearTime = 30;

/*How long an entry password to generate if generation is specifed*/
int entryPassLength;

/*To store return values for checking*/
/*Made global in case a function needs to return something else to its caller*/
int returnVal;

/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
struct termios termisOld, termiosNew;

int main(int argc, char* argv[])
{
    /*Print help if no arguments given*/
    if (argc == 1) {
        printSyntax(argv[0]);
        return 1;
    }
    
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

		#ifdef __linux__
		/*Need variables for libcap functions*/
		cap_t caps;
		cap_value_t cap_list[2];
		cap_value_t clear_list[1];
		caps = cap_get_proc();
		if (caps == NULL) {
			perror("caps");
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
		
		#endif
		
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

    /*These calls will ensure that cleanUpFiles and cleanUpBuffers is ran after return call within main*/

    atexit(cleanUpFiles);
    atexit(cleanUpBuffers);

    allocateBuffers();

    signal(SIGINT, signalHandler);

    tmpFile1 = genFileName();
    tmpFile2 = genFileName();
    tmpFile3 = genFileName();

    /*These file handles refer to temporary and final files in the openEnvelope/sealEnvelope process*/
    /*EVP2EncryptedFile is the second EVP algorithms' cipher-text, which will also represent the final database file without its header*/
    /*EVP2DecryptedFile is the second EVP algorithms' plain-text, i.e. the first EVP algorithms' cipher-text*/
    /*EVP1DataFileTmp is the first EVP algorithms' cipher-text, which will be loaded into buffers for decryption and processing*/
    /*dbFile will contain two salts and crypto information as a header, followed by the second EVP algorithms' cipher-text*/
    FILE *EVP2EncryptedFile, *EVP2DecryptedFile, *EVP1DataFileTmp, *dbFile;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdLIster() and encLister() functions to work*/
    OpenSSL_add_all_algorithms();

    int opt; /*for getop()*/
    int errflg = 0; /*Toggle this flag on and off so we can check for errors and act accordingly*/

    int i;

    unsigned char* token;

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
            token = strtok(optarg, ":");
            if (token == NULL) {
                printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
                return 1;
            }
            strcpy(messageDigest1, token);

            token = strtok(NULL, ":");

            strcpy(messageDigest2, token);

            /*Store command-line given parameters for use after messageDigest are read from file header*/
            strcpy(messageDigestStore1, messageDigest1);
            strcpy(messageDigestStore2, messageDigest2);

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

            token = strtok(optarg, ":");
            if (token == NULL) {
                printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
                return 1;
            }
            strcpy(encCipher1, token);

            token = strtok(NULL, ":");

            strcpy(encCipher2, token);

            /*Store command-line given parameters for use after encCipher are read from file header*/
            strcpy(encCipherStore1, encCipher1);
            strcpy(encCipherStore2, encCipher2);

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
            strcpy(entryPass, optarg);
            OPENSSL_cleanse(optarg, strlen(optarg));
            break;
        case 'x': /*If passing database password from command line*/
            toggle.dbPassArg = 1;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                errflg++; /*Set error flag*/
                printf("Option -x requires an operand\n");
            }
            strcpy(dbPass, optarg);
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
        strcpy(backupFileName, dbFileName);
        strcat(backupFileName, ".autobak");
        FILE* backUpFile = fopen(backupFileName, "w");
        if (backUpFile == NULL) {
            printf("Couldn't make a backup file. Be careful...\n");
        } else {
            FILE* copyFile = fopen(dbFileName, "r");
            char* backUpFileBuffer = calloc(sizeof(char), returnFileSize(dbFileName));
            returnVal = fread(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), copyFile);
            if (!returnVal == returnFileSize(dbFileName) / sizeof(unsigned char)) {
                if (ferror(copyFile)) {
                    printf("Fread failed\n");
                    return 1;
                }
            }

            returnVal = fwrite(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), backUpFile);
            if (!returnVal == returnFileSize(dbFileName) / sizeof(unsigned char))
                ;
            {
                if (ferror(backUpFile)) {
                    printf("fwrite failed @ 485\n");
                    return 1;
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
            genEvp1Salt();
            genEvp2Salt();
            hmacKDF();
            toggle.firstRun = 1;
        }

        /*openEnvelope has decrypted the second EVP algorithm, and placed its plain-text into a tempfile whose randomly-generated name is in a buffer pointed to by tmpFile2*/

        /*Open first EVP algorithms' cipher-text for decryption and processing*/
        /*In this case, appending a new entry to it*/
        EVP1DataFileTmp = fopen(tmpFile2, "a+");
        if (EVP1DataFileTmp == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*Derives a key for the first EVP algorithm*/
        /*The choosen EVP digest algorithm will be used*/
        /*The salt generated for the first EVP algorithm will also be used*/
        /*The entire KDF will reiterate according to the password length multiplied by the reccomended amount in RFC 2889*/
        
		if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1,evpIv1) != 0) {
			return 1;
		}
		
        /*writePass() appends a new entry to EVP1DataFileTmp encrypted with the first EVP algorithm chosen*/
        int writePassResult = writePass(EVP1DataFileTmp);

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

        EVP2EncryptedFile = fopen(dbFileName, "rb");
        if (EVP2EncryptedFile == NULL) /*Make sure the file opens*/
        {
            perror(argv[0]);
            cleanUpBuffers();
            return errno;
        }

        EVP2DecryptedFile = fopen(tmpFile1, "wb");
        if (EVP2DecryptedFile == NULL) /*Make sure the file opens*/
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

        /*the file whose name is pointed to by tmpFile2 now contains EVP1 data with no MAC and can be passed to printPasses()*/
        EVP1DataFileTmp = fopen(tmpFile2, "rb");
        if (EVP1DataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

		
		if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1,evpIv1) != 0) {
			return 1;
		}

        if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") != 0) /*Find a specific entry to print*/
        {
            printPasses(EVP1DataFileTmp, entryName); /*Decrypt and print pass specified by entryName*/
            if (toggle.sendToClipboard == 1) {
                printf("Sent password to clipboard. Paste with middle-click.\n");
            }
        } else if (toggle.entrySearch == 1 && strcmp(entryName, "allpasses") == 0)
            printPasses(EVP1DataFileTmp, NULL); /*Decrypt and print all passess*/

        fclose(EVP1DataFileTmp);

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
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVP1DataFileTmp = fopen(tmpFile2, "rb+");
        if (EVP1DataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

		
		if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1,evpIv1) != 0) {
			return 1;
		}

        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified to a new temporary file*/
        int deletePassResult = deletePass(EVP1DataFileTmp, entryName);

        fclose(EVP1DataFileTmp);

        if (deletePassResult == 0) {

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
            if (strcmp(entryPass, "gen") == 0) {
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
                    if (strcmp(newEntryPass, newEntryPassStore) != 0) {
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
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        if (openEnvelope() != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVP1DataFileTmp = fopen(tmpFile2, "rb+");
        if (EVP1DataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);
		
		if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1,evpIv1) != 0) {
			return 1;
		}

        /*Works like deletePass() but instead of excluding matched entry, modfies its buffer values and then outputs to 3rd temp file*/
        int updateEntryResult = updateEntry(EVP1DataFileTmp, entryNameToSearch);

        fclose(EVP1DataFileTmp);

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

        if (openEnvelope(encCipher2, messageDigest2, dbPass) != 0) {
            cleanUpBuffers();
            cleanUpFiles();
            return 1;
        }

        EVP1DataFileTmp = fopen(tmpFile2, "rb+");
        if (EVP1DataFileTmp == NULL) {
            perror(argv[0]);
            cleanUpBuffers();
            cleanUpFiles();
            return errno;
        }
        chmod(tmpFile2, S_IRUSR | S_IWUSR);

        /*Must store old evp1 key data to decrypt database before new key material is generated*/
        strcpy(dbPassOld, dbPass);
        memcpy(hmacKeyOld, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

        /*If -U was given but neither -c or -H*/
        if (toggle.updateEncPass == 1 && (toggle.encCipher != 1 && toggle.messageDigest != 1)) {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassStore);
            if (strcmp(dbPass, dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                /*If not changing, replace old dbPass back into dbPass*/
                strcpy(dbPass, dbPassOld);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                hmacKDF();
                memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
            }

            /*Change cipher and digest if specified*/
            if (toggle.encCipher == 1) {
                strcpy(encCipher1, encCipherStore1);
                strcpy(encCipher2, encCipherStore2);
                printf("Changing cipher to %s:%s\n", encCipherStore1, encCipherStore2);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest1, messageDigestStore2);
                strcpy(messageDigest2, messageDigestStore2);
                printf("Changing digest to %s\n", messageDigestStore2);
            }
        }
        /*-U was given but not -P and -c and/or -H might be there*/
        else if (toggle.updateEncPass == 1 && toggle.updateEntryPass != 1) {
            if (toggle.encCipher == 1) {
                strcpy(encCipher1, encCipherStore1);
                strcpy(encCipher2, encCipherStore2);
                printf("Changing cipher to %s:%s\n", encCipherStore1, encCipherStore2);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest1, messageDigestStore1);
                strcpy(messageDigest2, messageDigestStore2);
                printf("Changing digest to %s:%s\n", messageDigestStore1, messageDigestStore2);
            }
            memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
        }
        /*If -P is given along with -c or -H*/
        else {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassStore);
            if (strcmp(dbPass, dbPassStore) != 0) {
                printf("Passwords don't match, not changing.\n");
                strcpy(dbPass, dbPassOld);
                cleanUpBuffers();
                cleanUpFiles();
                return 1;
            } else {
                printf("Changed password.\n");
                hmacKDF();
                memcpy(hmacKeyNew, hmacKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
            }

            /*Change crypto settings*/
            if (toggle.encCipher == 1) {
                strcpy(encCipher1, encCipherStore1);
                strcpy(encCipher2, encCipherStore2);
                printf("Changing cipher to %s:%s\n", encCipherStore1, encCipherStore2);
            }
            if (toggle.messageDigest == 1) {
                strcpy(messageDigest1, messageDigestStore1);
                strcpy(messageDigest2, messageDigestStore2);
                printf("Changing digest to %s:%s\n", messageDigestStore1, messageDigestStore2);
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
        int updateEncPassResult = updateEncPass(EVP1DataFileTmp);

        fclose(EVP1DataFileTmp);

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
    return 0;
}

int printPasses(FILE* dbFile, char* searchString)
{
    int i, ii;
    int entriesMatched = 0;

    int outlen, tmplen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*Get the filesize*/
    long fileSize;
    fseek(dbFile, 0L, SEEK_END);
    fileSize = ftell(dbFile);
    fseek(dbFile, 0L, SEEK_SET);

    unsigned char* entryBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);
    unsigned char* passBuffer = calloc(sizeof(unsigned char), BUFFER_SIZES);
    unsigned char* encryptedBuffer = calloc(sizeof(unsigned char), fileSize);
    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);

    /*Read the file into a buffer and check for error*/
    returnVal = fread(encryptedBuffer, sizeof(unsigned char), fileSize, dbFile);
    if (!returnVal == fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            printf("Fread failed in printPasses\n");
            return 1;
        }
    }

    /*This will be the gMac, as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVP2DecryptedFile matches MAC generated via HMAC*/
    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        cleanUpFiles();
        cleanUpBuffers();
        return 1;
    }

    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);

    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, &outlen, encryptedBuffer, fileSize)) {
        /* Error */
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

        if (searchString != NULL) /*If an entry name was specified*/
        {
            /*Use strncmp and search the first n elements of entryBuffer, where n is the length of the search string*/
            /*This will allow the search of partial matches, or an exact match to be printed*/
            if (strncmp(searchString, entryBuffer, strlen(searchString)) == 0) {
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

    int outlen, tmplen;

    int numberOfSymbols = 0;

    char* fileBuffer;

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
    if (!returnVal == fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            printf("Fread failed in updatePass()\n");
            return 1;
        }
    }

    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVP2DecryptedFile matches MAC generated via HMAC*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);

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

    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);

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

        /*If an entry matched searchString or allpasses was specified*/
        if ((lastCheck = strncmp(searchString, entryBuffer, strlen(searchString))) == 0 || toggle.allPasses == 1) {

            /*A clunky boolean to test if any entries were matched*/
            noEntryMatched = 0;

            //Update content in entryName before encrypting back
            if (toggle.entryGiven == 1) {
                memcpy(entryBuffer, newEntry, BUFFER_SIZES);
            }

            /*This will preserve the alphanumeric nature of a password if it has no symbols*/
            if (toggle.allPasses == 1) {
                for (i = 0; i < strlen(passBuffer); i++) {
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
                    strcpy(newEntryPass, entryPass);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strcpy(newEntryPass, entryPass);
                }
                memcpy(passBuffer, newEntryPass, BUFFER_SIZES);
                /*Do the same as above but if an alphanumeric pass was specified*/
            } else if (toggle.updateEntryPass == 1 && (toggle.generateEntryPassAlpha == 1 || toggle.allPasses == 1)) {
                if (toggle.entryPassLengthGiven == 1) {
                    genPassWord(entryPassLength);
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
    /*Maybe I can multi-thread this*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize + EVP_MAX_BLOCK_LENGTH);

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), outlen);

    fileSize = outlen;

    EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
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
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, outlen, gMac, gMacLength);

    /*Check if any entries were updated*/
    if (noEntryMatched == 1) {
        printf("Nothing matched the entry specified, nothing was deleted.\n");
    } else
        printf("If you updated more than you intended to, restore from %s.autobak\n", dbFileName);

    /*Write the modified cipher-text to this temporary file for sealEnvelope()*/
    tmpFile = fopen(tmpFile3, "wb");
    if (tmpFile == NULL) {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    /*Write the encryptedBuffer out and check for errors*/
    returnVal = fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    if (!returnVal == fileSize / sizeof(unsigned char))
        ;
    {
        if (ferror(tmpFile)) {
            printf("fwrite failed @ 1365\n");
            return 1;
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
    //int noEntryMatched = 1;
    int entriesMatched = 0;

    int outlen, tmplen;

    char* fileBuffer;
    char* fileBufferOld;

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
    if (!returnVal == fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            printf("Fread failed in deletePass()\n");
            return 1;
        }
    }

    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVP2DecryptedFile matches MAC generated via HMAC*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);

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

    EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);

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

        /*Copy the encrypted information into the evp1Buffer*/
        for (i = 0; i < BUFFER_SIZES; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + BUFFER_SIZES];
        }

        /*Use strcmp to match the exact entry here*/
        if ((lastCheck = strncmp(searchString, entryBuffer, strlen(searchString))) == 0) /*Now we're going to find the specific entry to delete it*/
        {
            if (ii == (fileSize - (BUFFER_SIZES * 2))) /*If ii is one entry short of fileSize*/
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

    /*Clear out sensitive information ASAP*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * fileSize);

    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), outlen - ((BUFFER_SIZES * 2) * entriesMatched));

    fileSize = outlen;

    EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
    if (!EVP_EncryptUpdate(ctx, encryptedBuffer, &outlen, fileBuffer, fileSize - ((BUFFER_SIZES * 2) * entriesMatched))) {
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
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize - ((BUFFER_SIZES * 2) * entriesMatched), gMac, gMacLength);

    /*Write the modified cipher-text to this temporary file for sealEnvelope()*/
    tmpFile = fopen(tmpFile3, "wb");
    if (tmpFile == NULL) {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    if (entriesMatched < 1) {
        printf("Nothing matched that exactly.\n");
        returnVal = fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
        if (!returnVal == fileSize / sizeof(unsigned char))
            ;
        {
            if (ferror(tmpFile)) {
                printf("fwrite failed @ 1550\n");
                return 1;
            }
        }
    } else {
        printf("If you deleted more than you intended to, restore from %s.autobak\n", dbFileName);
        returnVal = fwrite(encryptedBuffer, fileSize - ((BUFFER_SIZES * 2) * entriesMatched), sizeof(char), tmpFile);
        if (!returnVal == fileSize - ((BUFFER_SIZES * 2) * entriesMatched) / sizeof(unsigned char))
            ;
        {
            if (ferror(tmpFile)) {
                printf("fwrite failed @ 1558\n");
                return 1;
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
    //int i;
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
    if (!returnVal == fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            printf("Fread failed in updateEncPass()\n");
            return 1;
        }
    }

    /*This will be the gMac as in generated MAC*/
    HMAC(EVP_sha512(), hmacKeyOld, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

    /*Check if the MAC from the EVP2DecryptedFile matches MAC generated via HMAC)*/

    /*Return error status before proceeding and clean up sensitive data*/
    if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
        printMACErrMessage(backupFileName);

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
    EVP_DecryptInit(ctx, evpCipher1Old, evpKey1Old, evpIv1Old);

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
		
	if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1,evpIv1) != 0) {
			return 1;
	}

    memcpy(hmacKey, hmacKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    fileSize = outlen;

    EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);
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
    HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

    tmpFile = fopen(tmpFile3, "wb"); /*Now open a temp file just to write the new evp1 data to, clean up in the calling function*/
    if (tmpFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile3, S_IRUSR | S_IWUSR);

    returnVal = fwrite(encryptedBuffer, fileSize, sizeof(unsigned char), tmpFile);
    if (!returnVal == fileSize / sizeof(unsigned char))
        ;
    {
        if (ferror(tmpFile)) {
            printf("fwrite failed @ 1707\n");
            return 1;
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
    /*We need a set of incrementors to crawl through buffers*/
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
    if (!returnVal == fileSize / sizeof(unsigned char)) {
        if (ferror(dbFile)) {
            printf("Fread failed in writePass()\n");
            return 1;
        }
    }

    if (toggle.firstRun != 1) {

        /*This will be the gMac as in generated MAC*/
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, fileSize, gMac, gMacLength);

        /*Check if the MAC from the EVP2DecryptedFile matches MAC generated via HMAC*/

        /*Return error status before proceeding and clean up sensitive data*/
        if (memcmp(fMac, gMac, SHA512_DIGEST_LENGTH) != 0) {
            printMACErrMessage(backupFileName);
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * BUFFER_SIZES * 2);

            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            cleanUpFiles();
            cleanUpBuffers();
            return 1;
        }

        EVP_DecryptInit(ctx, evpCipher1, evpKey1, evpIv1);

        /*Decrypt file and store into temp buffer*/
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
        EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);

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

        /*Hash the evp1 data with HMAC-SHA512*/
        /*Append this as the "generated" MAC later*/
        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, outbuf, outlen, gMac, gMacLength);

        /*Write the encrypted information to file*/
        returnVal = fwrite(outbuf, 1, sizeof(unsigned char) * outlen, dbFile);
        if (!returnVal == outlen * sizeof(unsigned char))
            ;
        {
            if (ferror(dbFile)) {
                printf("fwrite failed @ 1837\n");
                return 1;
            }
        }

    } else {

        EVP_EncryptInit_ex(ctx, evpCipher1, NULL, evpKey1, evpIv1);

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

        HMAC(EVP_sha512(), hmacKey, SHA512_DIGEST_LENGTH, encryptedBuffer, outlen, gMac, gMacLength);

        fclose(dbFile);
        wipeFile(tmpFile2);
        dbFile = fopen(tmpFile2, "wb");

        returnVal = fwrite(encryptedBuffer, 1, outlen * sizeof(unsigned char), dbFile);
        if (!returnVal == outlen * sizeof(unsigned char))
            ;
        {
            if (ferror(dbFile)) {
                printf("fwrite failed @ 1881\n");
                return 1;
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

/*OpenSSL EVP routines to encrypt in sealEnvelope()*/
/*Would be great to get these to work on memory buffers instead of files*/
/*Whenever I do however, EVP_EncryptFinal_ex only outputs 16 bytes of nonsense*/
/*Code was gleamed from OpenSSL man pages for EVP_EncryptInit*/
int dbEncrypt(FILE* in, FILE* out)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[EVP_BLOCK_SIZE], outbuf[EVP_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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
        returnVal = fwrite(outbuf, 1, outlen, out);
        if (!returnVal == outlen)
            ;
        {
            if (ferror(out)) {
                printf("fwrite failed 1975\n");
                return 1;
            }
        }
    }
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }
    returnVal = fwrite(outbuf, 1, outlen, out);
    if (!returnVal == outlen)
        ;
    {
        if (ferror(out)) {
            printf("fwrite failed 1987\n");
            return 1;
        }
    }
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
    int inlen, outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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
        returnVal = fwrite(outbuf, 1, outlen, out);
        if (!returnVal == outlen)
            ;
        {
            if (ferror(out)) {
                printf("fwrite failed @ 2018\n");
                return 1;
            }
        }
    }
    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }
    returnVal = fwrite(outbuf, 1, outlen, out);
    if (!returnVal == outlen)
        ;
    {
        if (ferror(out)) {
            printf("fwrite failed @ 2030\n");
            return 1;
        }
    }
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
/*Will also enforce CFB, OFB or CTR modes*/
int primeSSL()
{
    char modeTag[3];
    int stringStart, modeLength;
    int i;

    /*If the user has specified a cipher to use*/
    if (toggle.encCipher == 1 || encCipher2[0] != 0) {

        /*Find start of mode*/
        for (i = strlen(encCipher1); i > 0; i--) {
            if (encCipher1[i] == '-') {
                stringStart = i;
                break;
            }
        }

        /*If no hyphen present, append -ctr mode to encCipher to enforce CTR mode by default*/
        if (i == 0) {
            printf("Must specify key size in bits and mode like \'%s-bits-mode\'\n", encCipher1);
            return 1;
        } else { /*Otherwise copy the mode specified to modeTag*/

            modeLength = strlen(encCipher1) - stringStart;

            /*Increment stringStart so it points to the first character of the mode string after the hyphen*/
            stringStart++;

            for (i = 0; i < modeLength; i++)
                modeTag[i] = encCipher1[stringStart + i];
        }

        if (strcasecmp(modeTag, "ofb") == 0 || strcasecmp(modeTag, "cfb") >= 0 || strcasecmp(modeTag, "ctr") == 0) {
            evpCipher1 = EVP_get_cipherbyname(encCipher1);
        } else {
            printf("\n%s mode specified\nCipher should be in OFB, CFB or CTR mode\n", modeTag);
            return 1;
        }

        for (i = strlen(encCipher2); i > 0; i--) {
            if (encCipher2[i] == '-') {
                stringStart = i;
                break;
            }
        }

        if (i == 0) {
            printf("Must specify key size in bits and mode like \'%s-bits-mode\'\n", encCipher2);
            return 1;
        } else {

            modeLength = strlen(encCipher2) - stringStart;

            /*Increment stringStart so it points to the first character of the mode string after the hyphen*/
            stringStart++;

            for (i = 0; i < modeLength; i++)
                modeTag[i] = encCipher2[stringStart + i];
        }

        if (strcasecmp(modeTag, "ofb") == 0 || strcasecmp(modeTag, "cfb") >= 0 || strcasecmp(modeTag, "ctr") == 0) {
            evpCipher2 = EVP_get_cipherbyname(encCipher2);
        } else {
            printf("\n%s mode specified\nCipher should be in OFB, CFB or CTR mode\n", modeTag);
            return 1;
        }

        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!evpCipher1) {
            fprintf(stderr, "no such cipher\n");
            return 1;
        }
        evpCipher2 = EVP_get_cipherbyname(encCipher2);
        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!evpCipher2) {
            fprintf(stderr, "no such cipher\n");
            return 1;
        }

    } else { /*If not default to aes-256-ctr*/
        strcpy(encCipher2, "aes-256-ctr");
        evpCipher2 = EVP_get_cipherbyname(encCipher2);
        if (!evpCipher2) { /*If that's not a valid cipher name*/
            fprintf(stderr, "no such cipher\n");
            return 1;
        }
        strcpy(encCipher1, "camellia-256-ofb");
        evpCipher1 = EVP_get_cipherbyname(encCipher1);
        if (!evpCipher1) { /*If that's not a valid cipher name*/
            fprintf(stderr, "no such cipher\n");
            return 1;
        }
    }

    /*If the user has specified a digest to use*/
    if (toggle.messageDigest == 1 || messageDigest2[0] != 0) {
        evpDigest1 = EVP_get_digestbyname(messageDigest1);
        if (!evpDigest1) {
            fprintf(stderr, "no such digest\n");
            return 1;
        }
        evpDigest2 = EVP_get_digestbyname(messageDigest2);
        if (!evpDigest2) {
            fprintf(stderr, "no such digest\n");
            return 1;
        }
    } else { /*If not default to sha512*/
        strcpy(messageDigest2, "sha512");
        evpDigest2 = EVP_get_digestbyname(messageDigest2);
        if (!evpDigest2) { /*If that's not a valid digest name*/
            fprintf(stderr, "no such digest\n");
            return 1;
        }
        strcpy(messageDigest1, "whirlpool");
        evpDigest1 = EVP_get_digestbyname(messageDigest1);
        if (!evpDigest1) { /*If that's not a valid digest name*/
            fprintf(stderr, "no such digest\n");
            return 1;
        }
    }

    return 0;
}

int sealEnvelope(const char* tmpFileToUse)
{
    unsigned char cryptoBuffer[BUFFER_SIZES];
    if (!RAND_bytes(cryptoBuffer, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        cleanUpBuffers();
        cleanUpFiles();
        exit(1);
    }
    //int EVP1DataSize = returnFileSize(tmpFileToUse);

    FILE *EVP2DecryptedFile, *EVP1DataFileTmp, *dbFile;

    /*Generate MAC from EVP1Data written to temp file*/
    EVP1DataFileTmp = fopen(tmpFileToUse, "rb");
    if (EVP1DataFileTmp == NULL) {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    fclose(EVP1DataFileTmp);

    /*Now append new generated MAC to end of the EVP1 data*/
    EVP1DataFileTmp = fopen(tmpFileToUse, "ab");
    if (EVP1DataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*Append the MAC and close the file*/
    returnVal = fwrite(gMac, sizeof(unsigned char), SHA512_DIGEST_LENGTH, EVP1DataFileTmp);
    if (!returnVal == SHA512_DIGEST_LENGTH / sizeof(unsigned char))
        ;
    {
        if (ferror(EVP1DataFileTmp)) {
            printf("fwrite failed @ 2148\n");
            return 1;
        }
    }
    fclose(EVP1DataFileTmp);

    /*Open EVP1 file for reading, so we can use OpenSSL to encrypt it into the final password database file*/
    EVP2DecryptedFile = fopen(tmpFileToUse, "rb");
    if (EVP2DecryptedFile == NULL) {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFileToUse, S_IRUSR | S_IWUSR);

    /*This will now be an EVP2EncryptedFile but calling it dbFile to clarify it is the final step*/
    dbFile = fopen(dbFileName, "wb");
    if (dbFile == NULL) {
        perror("passmanager");
        return errno;
    }

    /*Write crypto information as a header*/

    /*Write encCipher:messageDigest to cryptoBuffer*/
    sprintf(cryptoBuffer, "%s:%s:%s:%s", encCipher1, messageDigest1, encCipher2, messageDigest2);

    if (toggle.firstRun != 1) {
        /*Generates a random EVP*_SALT_SIZE byte string into buffer pointed to by saltBuff*/
        genEvp2Salt();
    }

    /*Write the first algorithm's salt*/
    returnVal = fwrite(evp2Salt, sizeof(unsigned char), EVP2_SALT_SIZE, dbFile);
    if (!returnVal == EVP2_SALT_SIZE / sizeof(unsigned char))
        ;
    {
        if (ferror(dbFile)) {
            printf("fwrite failed @ 2184\n");
            return 1;
        }
    }

    /*Write the second algorithm's salt*/
    returnVal = fwrite(evp1Salt, sizeof(unsigned char), EVP1_SALT_SIZE, dbFile);
    if (!returnVal == EVP1_SALT_SIZE / sizeof(unsigned char))
        ;
    {
        if (ferror(dbFile)) {
            printf("fwrite failed 2 2192\n");
            return 1;
        }
    }

    /*Write buffer pointed to by cryptoBuffer*/
    returnVal = fwrite(cryptoBuffer, sizeof(unsigned char), BUFFER_SIZES, dbFile);
    if (!returnVal == BUFFER_SIZES / sizeof(unsigned char))
        ;
    {
        if (ferror(dbFile)) {
            printf("fwrite failed @ 2200\n");
            return 1;
        }
    }

    /*This function generates a key and possibly iv needed for encryption algorithims*/

	if(evpKDF(dbPass, evp2Salt, EVP2_SALT_SIZE,evpCipher2,evpDigest2,evpKey2,evpIv2) != 0) {
			return 1;
	}

    /*Do the OpenSSL encryption*/
    if (dbEncrypt(EVP2DecryptedFile, dbFile) != 0) {
        printf("\\nWrong key used.\n");
        printf("\nFilename: %s", tmpFile1);
        return 1;
    }

    /*Close the files*/
    fclose(EVP2DecryptedFile);
    fclose(dbFile);

    /*Cleanup temp files*/
    cleanUpFiles();

    return 0;
}

int openEnvelope()
{
    unsigned char cryptoHeader[BUFFER_SIZES];
    unsigned char* token;
    //int i;

    /*a temporary buffer to store the contents of the password file between read and writes to temporary files*/
    unsigned char* tmpBuffer;

    /*file handles to be used  for envelope and temporary files*/
    FILE *EVP2EncryptedFile, *EVP2DecryptedFile, *EVP1DataFileTmp;

    /*Open the OpenSSL encrypted envelope containing EVP1 Cipher Text +MAC data*/
    EVP2EncryptedFile = fopen(dbFileName, "rb");
    if (EVP2EncryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }

    /*Grab the crypto information from header*/
    /*This will first contain the EVP2_SALT_SIZE sized salt for evp2Salt*/
    /*Then an EVP1_SALT_SIZE byte salt for evp1Salt*/
    /*Then will be the cipher and the message digest names delimited with ':'*/

    /*fread overwrites the randomly generated salt with the one read from file*/
    returnVal = fread(evp2Salt, sizeof(unsigned char), EVP2_SALT_SIZE, EVP2EncryptedFile);
    if (!returnVal == EVP2_SALT_SIZE / sizeof(unsigned char)) {
        if (ferror(EVP2EncryptedFile)) {
            printf("Fread failed\n");
            return 1;
        }
    }

    returnVal = fread(evp1Salt, sizeof(unsigned char), EVP1_SALT_SIZE, EVP2EncryptedFile);
    if (!returnVal == EVP1_SALT_SIZE / sizeof(unsigned char)) {
        if (ferror(EVP2EncryptedFile)) {
            printf("Fread failed\n");
            return 1;
        }
    }

    /*Generate a separate salt and key for HMAC authentication*/
    hmacKDF();

    /*Read the cipher and message digest information in*/
    returnVal = fread(cryptoHeader, sizeof(unsigned char), BUFFER_SIZES, EVP2EncryptedFile);
    if (!returnVal == BUFFER_SIZES / sizeof(unsigned char)) {
        if (ferror(EVP2EncryptedFile)) {
            printf("Fread failed\n");
            return 1;
        }
    }

    /*Use strtok to parse the strings delimited by ':'*/

    /*First the cipher*/
    token = strtok(cryptoHeader, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }
    strcpy(encCipher1, token);

    token = strtok(NULL, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        cleanUpFiles();
        exit(1);
    }

    /*Then the message digest*/
    strcpy(messageDigest1, token);

    token = strtok(NULL, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        cleanUpFiles();
        exit(1);
    }

    /*Now the 2nd cipher*/
    strcpy(encCipher2, token);

    token = strtok(NULL, ":");

    /*Then the 2nd message digest*/
    strcpy(messageDigest2, token);

    /*Check the strings recieved are valid cipher and digest names*/
    evpCipher1 = EVP_get_cipherbyname(encCipher1);
    /*If the cipher doesn't exists or there was a problem loading it return with error status*/
    if (!evpCipher1) {
        fprintf(stderr, "Could not find valid cipher name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    evpDigest1 = EVP_get_digestbyname(messageDigest1);
    if (!evpDigest1) {
        fprintf(stderr, "Could not find a valid digest name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    evpCipher2 = EVP_get_cipherbyname(encCipher2);
    if (!evpCipher2) {
        fprintf(stderr, "Could not find valid cipher name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    evpDigest2 = EVP_get_digestbyname(messageDigest2);
    if (!evpDigest2) {
        fprintf(stderr, "Could not find a valid digest name in parsed header.\nIs %s a password file?\n", dbFileName);
        return 1;
    }

    /*This function generates a key and possibly iv needed for encryption algorithims*/
	
	if(evpKDF(dbPass, evp2Salt, EVP2_SALT_SIZE,evpCipher2,evpDigest2,evpKey2,evpIv2) != 0) {
			return 1;
	}

    if (toggle.updateEncPass) {
        /*Copy old evpCipher1 to evpCipher1Old and generate evpKey1Old based on this*/
        /*This needs to be done in openEnvelope() before cipher and digest parameters are changed later on */
        evpCipher1Old = evpCipher1;
		
		if(evpKDF(dbPass, evp1Salt, EVP1_SALT_SIZE,evpCipher1,evpDigest1,evpKey1Old,evpIv1Old) != 0) {
			return 1;
		}
    }

    /*Now open a temporary file with a randomly generated file name pointed to by tmpFile1*/
    /*This file will contain the 2nd algorithm's decrypted plain-text, i.e. the 1st algorithm's cipher-text, plus the MAC*/
    EVP1DataFileTmp = fopen(tmpFile1, "wb");
    if (EVP1DataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        printf("Could not open file: %s", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);

    /*Decrypt the OpenSSL envelope file into the aforementioned temp file*/
    if (dbDecrypt(EVP2EncryptedFile, EVP1DataFileTmp) != 0) {
        printf("\nWrong key used.\n");
        fclose(EVP2EncryptedFile);
        fclose(EVP1DataFileTmp);
        wipeFile(tmpFile1);
        remove(tmpFile1);
        return 1;
    }

    /*Now close the encrypted envelope and temp file*/
    fclose(EVP2EncryptedFile);
    fclose(EVP1DataFileTmp);

    /*Open 1st algorithm's cipher-text + MAC from the temporary file*/
    EVP2DecryptedFile = fopen(tmpFile1, "rb");
    if (EVP2DecryptedFile == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        printf("Could not open file: %s", tmpFile1);
        return errno;
    }
    chmod(tmpFile1, S_IRUSR | S_IWUSR);

    /*Open a file to write the cipher-text into once we've stripped the MAC off*/
    EVP1DataFileTmp = fopen(tmpFile2, "wb");
    if (EVP1DataFileTmp == NULL) /*Make sure the file opens*/
    {
        perror("passmanager");
        return errno;
    }
    chmod(tmpFile2, S_IRUSR | S_IWUSR);

    /*Set EVP2DecryptedFile file position to the beginning of the SHA512_DIGEST_LENGTH sized MAC*/

    /*Need to get the size of the file, then fseek to that value minus the length SHA512_DIGEST_LENGTH sized MAC*/
    long fileSize;
    fseek(EVP2DecryptedFile, 0L, SEEK_END);
    fileSize = ftell(EVP2DecryptedFile);
    fseek(EVP2DecryptedFile, fileSize - SHA512_DIGEST_LENGTH, SEEK_SET);

    /*Read the MAC from EVP2DecryptedFile into buffer pointed to by fMac*/
    /*fMac for file MAC. Will compare this one against the one generated for gMac*/
    returnVal = fread(fMac, sizeof(unsigned char), SHA512_DIGEST_LENGTH, EVP2DecryptedFile);
    if (!returnVal == SHA512_DIGEST_LENGTH / sizeof(unsigned char)) {
        if (ferror(EVP2DecryptedFile)) {
            printf("Fread failed\n");
            return 1;
        }
    }

    /*Reset to beginning of the EVP2DecryptedFile file to get ready to copy it to tmpFile2*/
    fseek(EVP2DecryptedFile, 0L, SEEK_SET);

    /*Allocate a buffer big enough for the EVP2DecryptedFile file minus the MAC*/
    tmpBuffer = calloc(sizeof(unsigned char), (fileSize - SHA512_DIGEST_LENGTH));

    /*Read the cipher-text data into the temp buffer, then write it out to tmpFile2*/
    returnVal = fread(tmpBuffer, sizeof(unsigned char), fileSize - SHA512_DIGEST_LENGTH, EVP2DecryptedFile);
    if (!returnVal == fileSize - SHA512_DIGEST_LENGTH / sizeof(unsigned char)) {
        if (ferror(EVP2DecryptedFile)) {
            printf("Fread failed\n");
            return 1;
        }
    }

    returnVal = fwrite(tmpBuffer, sizeof(unsigned char), fileSize - SHA512_DIGEST_LENGTH, EVP1DataFileTmp);
    if (!returnVal == fileSize - SHA512_DIGEST_LENGTH / sizeof(unsigned char))
        ;
    {
        if (ferror(EVP1DataFileTmp)) {
            printf("fwrite failed @ 2411\n");
            return 1;
        }
    }

    /*Close the temporary files used*/
    fclose(EVP2DecryptedFile);
    fclose(EVP1DataFileTmp);

    /*Erase data left behind in EVP2DecryptedFile*/
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
    entryPass = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(entryPass, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    entryPassStore = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(entryPassStore, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    entryName = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(entryName, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    entryNameToSearch = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(entryNameToSearch, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    newEntry = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(newEntry, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    newEntryPass = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(newEntryPass, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    newEntryPassStore = calloc(sizeof(char), BUFFER_SIZES);
    if (!RAND_bytes(newEntryPassStore, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    dbPass = calloc(sizeof(unsigned char), BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPass, BUFFER_SIZES * 2)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    dbPassStore = calloc(sizeof(unsigned char), BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPassStore, BUFFER_SIZES * 2)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

    dbPassOld = calloc(sizeof(unsigned char), BUFFER_SIZES * 2);
    if (!RAND_bytes(dbPassOld, BUFFER_SIZES * 2)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(1);
    }

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

    evp1Salt = calloc(sizeof(unsigned char), EVP1_SALT_SIZE);
    evp2Salt = calloc(sizeof(unsigned char), EVP2_SALT_SIZE);
}

/*Fill up the buffers we stored the information in with 0's before exiting*/
void cleanUpBuffers()
{
    OPENSSL_cleanse(entryPass, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(entryName, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(entryNameToSearch, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(newEntry, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * BUFFER_SIZES);
    OPENSSL_cleanse(dbPass, sizeof(unsigned char) * strlen(dbPass));
    OPENSSL_cleanse(dbPassOld, sizeof(unsigned char) * BUFFER_SIZES * 2);
    OPENSSL_cleanse(evpKey2, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(evpIv2, sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(fMac, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    OPENSSL_cleanse(gMac, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
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
    strcpy(entryPass, tempPassString);
}

char* genFileName()
{
    char b; /*Random byte*/
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
    sprintf(fileName, "%s/%s", P_tmpdir, fileNameBuffer);

    free(fileNameBuffer);

    return fileName;
}

/*Generates a random EVP2_SALT_SIZE sized byte salt for evpKDF()*/
void genEvp2Salt()
{

    char b; /*Random byte*/
    int i = 0;

    while (i < EVP2_SALT_SIZE) {
        if (!RAND_bytes(&b, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            cleanUpBuffers();
            cleanUpFiles();
            exit(1);
            ;
        }
        evp2Salt[i] = b;
        i++;
    }
}

void genEvp1Salt()
{

    char b; /*Random byte*/
    int i = 0;

    while (i < EVP1_SALT_SIZE) {
        if (!RAND_bytes(&b, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            cleanUpBuffers();
            cleanUpFiles();
            exit(1);
        }
        evp1Salt[i] = b;
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
    OPENSSL_cleanse(wipeOutBuffer, strlen(textToSend));
    FILE* xclipFile = popen(xclipCommand, "w");
    FILE* wipeFile = popen(wipeCommand, "w");
    pid_t pid, sid;

    if (xclipFile == NULL) {
        perror("xclip");
        return errno;
    }
    returnVal = fwrite(textToSend, sizeof(char), strlen(textToSend), xclipFile);
    if (!returnVal == strlen(textToSend) / sizeof(char))
        ;
    {
        if (ferror(xclipFile)) {
            printf("fwrite failed @ 2640\n");
            return 1;
        }
    }
    if (pclose(xclipFile) == -1) {
        perror("xclip");
        return errno;
    }
    OPENSSL_cleanse(textToSend, strlen(textToSend));

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

    sleep(xclipClearTime);

    returnVal = fwrite(wipeOutBuffer, sizeof(char), strlen(textToSend), wipeFile);
    if (!returnVal == strlen(textToSend) / sizeof(char))
        ;
    {
        if (ferror(wipeFile)) {
            printf("fwrite failed @ 2684\n");
            return 1;
        }
    }

    exit(0);
}

/*Derive a secondary key for HMAC to use*/
void hmacKDF()
{

    int i, originalPassLength;
    unsigned char hmacSalt[HMAC_SALT_SIZE];

    /*Derive a larger salt for HMAC from evp1Salt*/
    /*Use a counter of 3 so this XOR doesn't undo last xor'd bytes*/
    for (i = 0; i < HMAC_SALT_SIZE; i++)
        hmacSalt[i] = evp1Salt[i] ^ (i + 3);

    originalPassLength = strlen(dbPass);

    /*Generate a separate key to use for HMAC*/
    PKCS5_PBKDF2_HMAC(dbPass, -1, hmacSalt, HMAC_SALT_SIZE, RFC_2889_REC_ITERATIONS * originalPassLength, EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, hmacKey);
}

int evpKDF(unsigned char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv)
{
	/*First generate the key*/
	if (!PKCS5_PBKDF2_HMAC((unsigned char*)dbPass, strlen(dbPass),
		evpSalt, saltLen,
		strlen(dbPass) * RFC_2889_REC_ITERATIONS,
		evpDigest,EVP_CIPHER_key_length(evpCipher),
		evpKey)) {
        fprintf(stderr, "PBKDF2 failed\n");
        return 1;
    }
    
    /*If this cipher uses an IV, generate that as well*/
    if(EVP_CIPHER_iv_length(evpCipher) != 0) {
		if (!PKCS5_PBKDF2_HMAC((unsigned char*)dbPass, strlen(dbPass),
		    evpSalt, saltLen,
            strlen(dbPass) * RFC_2889_REC_ITERATIONS,
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

char* getPass(const char* prompt, unsigned char* paddedPass)
{
    size_t len = 0;
    int i;

    if (!RAND_bytes(paddedPass, BUFFER_SIZES)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        cleanUpBuffers();
        cleanUpFiles();
        printf("\nPassword was too large\n");
        exit(1);
    }
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
    else if (nread > BUFFER_SIZES) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        OPENSSL_cleanse(pass, sizeof(unsigned char) * nread);
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
    for (i = 0; i < strlen(pass) + 1; i++)
        paddedPass[i] = pass[i];

    OPENSSL_cleanse(pass, sizeof(unsigned char) * nread);
    free(pass);

    return paddedPass;
}

int printMACErrMessage(char* backupFileName)
{
    printf("Message Authentication Failed\nWrong password?\n");

    return 0;
}

int printSyntax(char* arg)
{
    printf("\
\nReccomend Syntax: \
\n\n%s [-a entry name | -r entry name | -d entry name | -u entry name [-n new name ] | -U ] [-p new entry password] [-l random password length] [-x database password] [-c first-cipher:second-cipher ] [-H first-digest:second-digest] [ -P ] -f database file [ -C ] [ -s seconds ]\
\nOptions: \
\n-n new name - entry name up to 512 characters (can contain white space or special characters) \
\n-p new entry password - entry password up to 512 characters (don't call to be prompted instead) ('gen' will generate a random password, 'genalpha' will generate a random password with no symbols)\
\n-l random password length - makes 'gen' or 'genalpha' generate a password random password length digits long (defaults to 16 without this option) \
\n-x database password - To supply database password as command-line argument (not reccomended) \
\n-c first-cipher:second-cipher - Specify 'list' for a list of methods available to OpenSSL. Default: camellia-256-ofb:aes-256-ctr. \
\n-H first-digest:second-digest - Specify 'list' for a list of methods available to OpenSSL. Default: whirlpool:sha512. \
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
\n     \t-c 'first-cipher:second-cipher' - Initializes a password database with cascaded encryption of 'first-cipher' into 'second-cipher'\
\n     \t-H 'first-digest:second-digest' - Derives keys for ciphers with digests 'first-digest' for 'first-cipher' and 'second-digest' for 'second-cipher'.\
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
\n     \t-c 'first-cipher:second-cipher' - Update algorithms in cascade\
\n     \t-H 'first-digest:second-digest' - Update digests used for cascaded algorithms' KDFs\
\nVersion 2.2.1\
\n\
",
        arg);
    printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return 1;
}
