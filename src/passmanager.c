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
#include <openssl/opensslv.h>
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
#include <stdbool.h>

#define printSysError(errCode) \
{ \
	fprintf(stderr,"%s:%s:%d: %s\n", __FILE__, __func__,__LINE__,strerror(errCode)); \
}

#define printFileError(fileName, errCode) \
{ \
	fprintf(stderr,"%s: %s (Line: %i)\n", fileName, strerror(errCode), __LINE__); \
}

#define printError(errMsg) \
{ \
	fprintf(stderr,"%s:%s:%d: %s\n", __FILE__, __func__,__LINE__,errMsg); \
}

#define UI_BUFFERS_SIZE 512

#define CRYPTO_HEADER_SIZE UI_BUFFERS_SIZE

#define EVP_SALT_SIZE 32

#define HMAC_SALT_SIZE EVP_SALT_SIZE

#define DEFAULT_GENPASS_LENGTH 16

#define DEFAULT_PBKDF2_ITER 1000000

struct conditionsStruct {
    bool addingPass;
    bool readingPass;
    bool deletingPass;
    bool entryPassGivenasArg;
    bool dbPassGivenasArg;
    bool fileGiven;
    bool entryGiven;
    bool updatingEntry;
    bool updatingEntryPass;
    bool updatingDbEnc;
    bool searchForEntry;
    bool userChoseDigest;
    bool userChoseCipher;
    bool genPassLengthGiven;
    bool sendToClipboard;
    bool userChoseXclipClearTime;
    bool userChosePBKDF2Iterations;
    bool databaseBeingInitalized;
    bool generateEntryPass;
    bool generateEntryPassAlpha;
    bool printAllPasses;
    bool updateAllPasses;
};

struct conditionsStruct condition;

/*Prototype functions*/

int openDatabase();
int writeDatabase();
int configEvp();
void mdListCallback(const OBJ_NAME* obj, void* arg);
void encListCallback(const OBJ_NAME* obj, void* arg);
void genEvpSalt();
int deriveHMACKey();
int deriveEVPKey(char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv, int PBKDF2Iterations);
int writePass();
int printPasses(char* searchString);
int deletePass(char* searchString);
int updateEntry(char* searchString);
int updateDbEnc();
void genPassWord(int stringLength);
char* getPass(const char* prompt, char* paddedPass);
void allocateBuffers();
bool fileNonExistant(const char* filename);
int returnFileSize(const char* filename);
void cleanUpBuffers();
void signalHandler(int signum);
int sendToClipboard();
int printSyntax(char* arg);
int printMACErrMessage(int errMessage);
int verifyCiphertext(unsigned int IvLength, unsigned int encryptedBufferLength, unsigned char *encryptedBuffer, unsigned char *HMACKey, unsigned char *evpIv);
int signCiphertext(unsigned int IvLength, unsigned int encryptedBufferLength, unsigned char *encryptedBuffer);
int evpDecrypt(EVP_CIPHER_CTX* ctx, int evpInputLength, int* evpOutputLength, unsigned char *encryptedBuffer, unsigned char *decryptedBuffer);
int evpEncrypt(EVP_CIPHER_CTX* ctx, int evpInputLength, int* evpOutputLength, unsigned char *encryptedBuffer, unsigned char *decryptedBuffer);
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream);
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream);
int compareMAC(const void * in_a, const void * in_b, size_t len);


const EVP_CIPHER *evpCipher, *evpCipherOld;
unsigned char evpKey[EVP_MAX_KEY_LENGTH], evpKeyOld[EVP_MAX_KEY_LENGTH];
unsigned char evpIv[EVP_MAX_IV_LENGTH], evpIvOld[EVP_MAX_KEY_LENGTH];
const EVP_MD *evpDigest = NULL;

char* dbPass;
char* dbPassToVerify;
char* dbPassOld;

char messageDigestName[NAME_MAX];
char messageDigestNameFromCmdLine[NAME_MAX];
char encCipherName[NAME_MAX];
char encCipherNameFromCmdLine[NAME_MAX];
char cryptoHeader[CRYPTO_HEADER_SIZE];

unsigned char *HMACKey, *HMACKeyNew, *HMACKeyOld;

unsigned char* evpSalt;

unsigned char MACcipherTextGenerates[SHA512_DIGEST_LENGTH];
unsigned char MACcipherTextSignedWith[SHA512_DIGEST_LENGTH];
unsigned char MACdBFileSignedWith[SHA512_DIGEST_LENGTH];
unsigned char MACdBFileGenerates[SHA512_DIGEST_LENGTH];
unsigned int* HMACLengthPtr;

int PBKDF2Iterations = DEFAULT_PBKDF2_ITER;
int PBKDF2IterationsStore;
int PBKDF2IterationsOld;

char dbFileName[NAME_MAX];
char backupFileName[NAME_MAX];

char* entryPass;
char* entryPassToVerify;
char* entryName;
char* entryNameToFind;
char* newEntry;
char* newEntryPass;
char* newEntryPassToVerify;
char* paddedPass;

unsigned char* encryptedBuffer;
unsigned char dbInitBuffer[(UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH];
int evpDataSize;

int xclipClearTimeSeconds = 30;

int genPassLength;

/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
struct termios termisOld, termiosNew;

int returnVal;

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
		printf("No priveleges to lock memory or disable prace. Your sensitive data might be swapped to disk or exposed to other processes. Aborting.\n");
		exit(EXIT_FAILURE);
	} else {

		/*Variables for libcap functions*/
		cap_t caps;
		cap_value_t set_list[1];
		cap_value_t clear_list[1];
		caps = cap_get_proc();
		if (caps == NULL) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		set_list[0] = CAP_IPC_LOCK;
		clear_list[0] = CAP_SYS_PTRACE;
		
		/*Enable memory locking*/
		if (cap_set_flag(caps, CAP_EFFECTIVE,1, set_list, CAP_SET) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		
		/*Make the capability inheritable to child processes*/
		if (cap_set_flag(caps, CAP_INHERITABLE,1, set_list, CAP_SET) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		/*Disable ptrace ability*/
		if (cap_set_flag(caps, CAP_EFFECTIVE,1, clear_list, CAP_CLEAR) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		if (cap_set_flag(caps, CAP_PERMITTED,1, clear_list, CAP_CLEAR) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		/*Make the disability inheritable to child processes*/
		if (cap_set_flag(caps, CAP_INHERITABLE,1, clear_list, CAP_CLEAR) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		if (cap_set_proc(caps) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		if (cap_free(caps) == -1) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		
		/*Structure values for rlimits*/
		struct rlimit core, memlock;

		core.rlim_cur = 0;
		core.rlim_max = 0;
		memlock.rlim_cur = RLIM_INFINITY;
		memlock.rlim_max = RLIM_INFINITY;

		/*Disable core dumps*/
		if(setrlimit(RLIMIT_CORE,&core) == -1)
		{
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		
		/*Raise limit of locked memory to unlimited*/
		if(setrlimit(RLIMIT_MEMLOCK,&memlock) == -1)
		{
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
				
		/*Lock all current and future  memory from being swapped*/
		if ( mlockall(MCL_CURRENT|MCL_FUTURE) == -1 ) {
			printSysError(errno);
			exit(EXIT_FAILURE);
		}
		
		/*Drop root before executing the rest of the program*/
		if(geteuid() == 0 && getuid() != 0) { /*If executable was not started as root, but given root privelge through SETUID/SETGID bit*/
			if(seteuid(getuid())) { /*Drop EUID back to the user who executed the binary*/
			printSysError(errno);
			exit(EXIT_FAILURE);
			}
			if(setuid(getuid())) { /*Drop UID back to the privelges of the user who executed the binary*/
			printSysError(errno);
			exit(EXIT_FAILURE);
			}
			if(getuid() == 0 || geteuid() == 0) { /*Fail if we could not drop root priveleges, unless started as root or with sudo*/
				printf("Could not drop root\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	#endif
    
    atexit(cleanUpBuffers);

    allocateBuffers();

    signal(SIGINT, signalHandler);

    FILE *dbFile;

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    /*It is also needed for the mdListCallback() and encListCallback() functions to work*/
    OpenSSL_add_all_algorithms();

    int opt;
    int errflg = 0;

    int i;

    /*Process through arguments*/
    while ((opt = getopt(argc, argv, "i:s:l:f:u:n:d:a:r:p:x:H:c:hUPC")) != -1) {
        switch (opt) {
        case 'h':
            printSyntax("passmanager");
            return 1;
            break;
        case 's':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -s requires an argument\n");
                errflg++; 
            }
            xclipClearTimeSeconds = atoi(optarg);
            condition.userChoseXclipClearTime = true;
            break;
        case 'i':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -i requires an argument\n");
                errflg++;
            }
            PBKDF2Iterations = atoi(optarg);
            PBKDF2IterationsStore = PBKDF2Iterations;
            condition.userChosePBKDF2Iterations = true;
            break;
        case 'l':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -l requires an argument\n");
                errflg++;
            }
            genPassLength = atoi(optarg);
            if (UI_BUFFERS_SIZE < genPassLength) {
                genPassLength = UI_BUFFERS_SIZE;
            }
            condition.genPassLengthGiven = true;
            break;
        case 'U':
            condition.updatingDbEnc = true;
            break;
        case 'C':
            condition.sendToClipboard = true;
            break;
        case 'P':
            condition.updatingEntryPass = true;
            break;
        case 'a':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -a requires an argument\n");
                errflg++;
            } else
                condition.addingPass = true;
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\nentry name too long\n");
                return 1;
            }
            strncpy(entryName, optarg, UI_BUFFERS_SIZE);
            condition.entryGiven = true;
            break;
        case 'r':
            condition.readingPass = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -r requires an argument\n");
                errflg++;
            } else
                condition.searchForEntry = true;
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\nentry name too long\n");
                return 1;
            }
            if (strcmp(optarg, "allpasses") == 0)
                condition.printAllPasses = true;
            strncpy(entryName, optarg, UI_BUFFERS_SIZE);
            condition.entryGiven = true;
            break;
        case 'd':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -d requires an argument\n");
                errflg++;
            } else
                condition.deletingPass = true;
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\nentry name too long\n");
                exit(EXIT_FAILURE);
            }
            strncpy(entryName, optarg, UI_BUFFERS_SIZE);
            condition.entryGiven = true;
            condition.searchForEntry = true;
            break;
        case 'H':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -H requires an argument\n");
                errflg++;
            }
            if (strcmp(optarg, "list") == 0) {
				/*Borrowed from StackOverflow*/
				/*https://stackoverflow.com/questions/47476427/get-a-list-of-all-supported-digest-algorithms*/
                OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, mdListCallback, NULL);
                return 0;
            }
            condition.userChoseDigest = true;

			/*Copy optarg into both variables because openDatabase() will replace what's in messageDigestName afer reading the header
			But only if the database is being initialized. This way the program doesn't need extra code for both conditions*/
            strncpy(messageDigestName, optarg, NAME_MAX);
            strncpy(messageDigestNameFromCmdLine, messageDigestName, NAME_MAX);

            condition.userChoseDigest = true;
            break;
        case 'c':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -c requires an argument\n");
                errflg++;
            }
            if (strcmp(optarg, "list") == 0) {
                OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, encListCallback, NULL);
                return 0;
            }
            condition.userChoseCipher = true;

            strncpy(encCipherName, optarg, NAME_MAX);
            strncpy(encCipherNameFromCmdLine, encCipherName, NAME_MAX);

            condition.userChoseCipher = true;
            break;
        case 'f':
			if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -f requires an argument\n");
                errflg++;
            } else
                condition.fileGiven = true;
            strncpy(dbFileName, optarg, NAME_MAX);
            break;
        case 'n':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -n requires an argument\n");
                errflg++;
            } else
                condition.searchForEntry = true;
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\nentry name too long\n");
                exit(EXIT_FAILURE);
            }
            strncpy(entryName, optarg, UI_BUFFERS_SIZE);
            condition.entryGiven = true;
            break;
        case 'u':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -u requires an argument\n");
                errflg++;
            } else
                condition.updatingEntry = true;
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\nentry name too long\n");
                exit(EXIT_FAILURE);
            }
            if (strcmp(optarg, "allpasses") == 0)
                condition.updateAllPasses = true;
            strncpy(entryNameToFind, optarg, UI_BUFFERS_SIZE);
            break;
        case 'p':
            condition.entryPassGivenasArg = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                printf("Option -p requires an argument\n");
                errflg++;
            }
            if (strlen(optarg) > UI_BUFFERS_SIZE) {
                printf("\npassword too long\n");
                exit(EXIT_FAILURE);
            }
            if (strcmp(optarg, "gen") == 0)
                condition.generateEntryPass = true;
            if (strcmp(optarg, "genalpha") == 0)
                condition.generateEntryPassAlpha = true;
            strncpy(entryPass, optarg, UI_BUFFERS_SIZE);
            OPENSSL_cleanse(optarg, strlen(optarg));
            break;
        case 'x':
            condition.dbPassGivenasArg = true;
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                errflg++;
                printf("Option -x requires an argument\n");
            }
            strncpy(dbPass, optarg, UI_BUFFERS_SIZE);
            OPENSSL_cleanse(optarg, strlen(optarg));
            break;
        case ':':
            printf("Option -%c requires an argument\n", optopt);
            errflg++;
            break;
        case '?': /*Get opt error handling, these check that the options were entered in correct syntax but not that the options are right*/
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
            errflg++;
        }
    }

    /*Sanitize argv and argc of any sensitive information*/
    for (i = 1; i < argc; i++)
        OPENSSL_cleanse(argv[i], strlen(argv[i]));

    /*If the user didn't specify a file with -f set error flag on*/
    if (condition.fileGiven != true)
        errflg++;
    
    /*Test if file is readable and if we are initializing a database*/
    
    if(returnFileSize(dbFileName) > 0)
    {
		dbFile = fopen(dbFileName,"rb");
		if(dbFile == NULL)
		{
			printFileError(dbFileName,errno);
			exit(EXIT_FAILURE);
		}
		fclose(dbFile);
	}
	else
	{
		condition.databaseBeingInitalized = true;
	}
        
    /*Finally test for errflag and halt program if on*/
    if (errflg) {
        printSyntax("passmanger"); /*Print proper usage of program*/
        exit(EXIT_FAILURE);
    }

    /*Before anything else, back up the password database*/
    if (condition.databaseBeingInitalized != true && condition.readingPass != true) {
        strncpy(backupFileName, dbFileName, NAME_MAX);
        strncat(backupFileName, ".autobak", NAME_MAX);
        FILE* backUpFile = fopen(backupFileName, "w");
        if (backUpFile == NULL) {
            printf("Couldn't make a backup file. Be careful...\n");
        } else {
            FILE* copyFile = fopen(dbFileName, "r");
            char* backUpFileBuffer = calloc(sizeof(char), returnFileSize(dbFileName));
            if(backUpFileBuffer == NULL)
			{
				printSysError(errno);
				exit(EXIT_FAILURE);
			}
            
            if(freadWErrCheck(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), copyFile) != 0) {
				printSysError(returnVal);
				exit(EXIT_FAILURE);
			}
            
            if(fwriteWErrCheck(backUpFileBuffer, sizeof(char), returnFileSize(dbFileName), backUpFile) != 0) {
				printSysError(returnVal);
				exit(EXIT_FAILURE);
			}
			
            fclose(copyFile);
            fclose(backUpFile);
            free(backUpFileBuffer);
        }
    }

    if (condition.addingPass == true) /*This mode will add an entry*/
    {

        /*Check a few things before proceeding*/

        /*If generating a random password was specified on command line*/
        if (strcmp(entryPass, "gen") == 0) {
            condition.generateEntryPass = true;
            if (condition.genPassLengthGiven == true)
                genPassWord(genPassLength);
            else
                genPassWord(DEFAULT_GENPASS_LENGTH);
        } else if (strcmp(entryPass, "genalpha") == 0) {
            condition.generateEntryPassAlpha = true;
            if (condition.genPassLengthGiven == true)
                genPassWord(genPassLength);
            else
                genPassWord(DEFAULT_GENPASS_LENGTH);
        } else if (condition.entryPassGivenasArg != true) {
            /*Prompt for entry password*/
            getPass("Enter entry password to be saved: ", entryPass);

            /*If user entered gen or genalpha at prompt*/
            if (strcmp(entryPass, "gen") == 0) {
                condition.generateEntryPass = true;
                printf("\nGenerating a random password\n");
                if (condition.genPassLengthGiven == true)
                    genPassWord(genPassLength);
                else
                    genPassWord(DEFAULT_GENPASS_LENGTH);
            } else if (strcmp(entryPass, "genalpha") == 0) {
                condition.generateEntryPassAlpha = true;
                printf("\nGenerating a random password\n");
                if (condition.genPassLengthGiven == true)
                    genPassWord(genPassLength);
                else
                    genPassWord(DEFAULT_GENPASS_LENGTH);
            } else {
                /*Verify user gentered password if not gen or genalpha*/
                getPass("Verify password:", entryPassToVerify);
                if (strcmp(entryPass, entryPassToVerify) != 0) {
                    printf("\nPasswords do not match.  Nothing done.\n\n");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /*Prompt for database password if not supplied as argument*/
        if (condition.dbPassGivenasArg != true) {
            getPass("Enter database password to encode with: ", dbPass);

            /*If this function returns 0 then it is the first time entering the database password so input should be verified*/
            if (returnFileSize(dbFileName) == 0) {
                getPass("Verify password:", dbPassToVerify);
                if (strcmp(dbPass, dbPassToVerify) != 0) {
                    printf("\nPasswords do not match.  Nothing done.\n\n");
                    exit(EXIT_FAILURE);
                }
            }
        }

        /*Note this will be needed before openDatabase() is called in all modes except Read*/
        configEvp();

        /*If password file exists run openDatabase on it*/
        /*Test by filesize and not if the file exists because at this point an empty file by this name will be there*/
        if (condition.databaseBeingInitalized != true) {
			openDatabase();
        } else {
            /*Otherwise run these functions to initialize a database*/
            genEvpSalt();
            deriveHMACKey();
        }

        /*Derives a key for the EVP algorithm*/
        
		deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv,PBKDF2Iterations);
		
        /*writePass() appends a new entry to EVPDataFileTmp encrypted with the EVP algorithm chosen*/
        int writePassResult = writePass();

        if (writePassResult == 0) {
            /*writeDatabase attaches prepends salt and header and appends MACs to cipher-text and writes it all as password database*/
            writeDatabase();
        }
        
    } else if (condition.readingPass == true) /*Read passwords mode*/
    {

        if (condition.dbPassGivenasArg != true)
        {
            getPass("Enter database password: ", dbPass);
        }

        /*Note no configEvp() needed before openDatabase() in Read mode*/
        openDatabase();
		
		deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv,PBKDF2Iterations);

        if (condition.searchForEntry == true && strcmp(entryName, "allpasses") != 0) /*Find a specific entry to print*/
        {
            printPasses(entryName); /*Decrypt and print pass specified by entryName*/
        } else if (condition.searchForEntry == true && condition.printAllPasses == true)
            printPasses(NULL); /*Decrypt and print all passess*/

    } else if (condition.deletingPass == true) /*Delete a specified entry*/
    {
		if (condition.dbPassGivenasArg != true)
        {
            getPass("Enter database password: ", dbPass);
        }

        /*Must specify an entry to delete*/
        if (condition.entryGiven != true) /*Fail if no entry specified*/
        {
            printf("\nNo entry name was specified\n");
			exit(EXIT_FAILURE);
        }

        configEvp();

        openDatabase();
		
		deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv,PBKDF2Iterations);

        /*Delete pass actually works by exclusion*/
        /*It writes all password entries except the one specified to a 3rd temporary file*/
        int deletePassResult = deletePass(entryName);

        if (deletePassResult == 0)
			writeDatabase();
			
    } else if (condition.updatingEntry == true) /*Update an entry name*/
    {

        if (condition.dbPassGivenasArg != true)
        {
            getPass("Enter database password: ", dbPass);
        }

        /*Get new entry*/
        if (condition.entryGiven == true) {
            strncpy(newEntry, entryName, UI_BUFFERS_SIZE);
        } else {
            /*If no new entry was specified then just update the password*/
            strncpy(newEntry, entryNameToFind, UI_BUFFERS_SIZE);
            condition.updatingEntryPass = true;
        }

        /*If entry password to update to was supplied by command line argument*/
        if (condition.entryPassGivenasArg == true)
            condition.updatingEntryPass = true;

        /*Get new pass*/
        if (condition.updatingEntryPass) {
            /*If entryPass supplied by command line, and generated randomly if it is 'gen'*/
            if (strcmp(entryPass, "gen") == 0) {
                if (condition.genPassLengthGiven == true) {
                    condition.generateEntryPass = true;
                    genPassWord(genPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                }
            } else if (strcmp(entryPass, "genalpha") == 0) {
                condition.generateEntryPassAlpha = true;
                if (condition.genPassLengthGiven == true) {
                    genPassWord(genPassLength);
                    /*Have to copy over passWord to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                }
            } else if (condition.entryPassGivenasArg != true)
            {
                getPass("Enter entry password to be saved: ", newEntryPass);

                /*If password retrieved by prompt was gen/genalpha generate a random password*/
                if (strcmp(newEntryPass, "gen") == 0) {
                    condition.generateEntryPass = true;
                    printf("\nGenerating a random password\n");
                    if (condition.genPassLengthGiven == true) {
                        genPassWord(genPassLength);
                        /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                        strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                    }
                } else if (strcmp(newEntryPass, "genalpha") == 0) {
                    condition.generateEntryPassAlpha = true;
                    printf("\nGenerating a random password\n");
                    if (condition.genPassLengthGiven == true) {
                        genPassWord(genPassLength);
                        /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                        strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                    } else {
                        genPassWord(DEFAULT_GENPASS_LENGTH);
                        strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                    }
                } else {
                    /*If retrieved password was not gen/genalpha verify it was not mistyped*/
                    getPass("Veryify password:", newEntryPassToVerify);
                    if (strcmp(newEntryPass, newEntryPassToVerify) != 0) {
                        printf("\nPasswords do not match.  Nothing done.\n\n");
                        cleanUpBuffers();
                        return 1;
                    }
                }
            } else if (condition.entryPassGivenasArg == true) /*This condition is true if the user DID supply a password but it isn't 'gen'*/
            {
                strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
            }
        }

        configEvp();

        openDatabase();
		
		deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv,PBKDF2Iterations);

        /*Works like deletePass() but instead of excluding matched entry, modfies its buffer values and then outputs to 3rd temp file*/
        int updateEntryResult = updateEntry(entryNameToFind);

        if (updateEntryResult == 0) {
			writeDatabase();
        }
    } else if (condition.updatingDbEnc == true)
    {
        if (condition.dbPassGivenasArg != true)
        {
            getPass("Enter current database password: ", dbPass);
        }

        openDatabase();

        /*Must store old EVP key data to decrypt database before new key material is generated*/
        strncpy(dbPassOld, dbPass, UI_BUFFERS_SIZE);
        memcpy(HMACKeyOld, HMACKey, sizeof(char) * SHA512_DIGEST_LENGTH);

        /*If -i was given along with nothing else*/
        if (condition.userChosePBKDF2Iterations == true && (condition.updatingEntryPass != true && condition.userChoseCipher != true && condition.userChoseDigest != true))
        {
			PBKDF2Iterations = PBKDF2IterationsStore;
			printf("PBKDF2 iterations changed to %i\n", PBKDF2Iterations);
		}
		/*If -U was given but neither -c or -H*/
        else if (condition.updatingDbEnc == true && (condition.userChoseCipher != true && condition.userChoseDigest != true)) {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassToVerify);
            if (strcmp(dbPass, dbPassToVerify) != 0) {
                printf("Passwords don't match, not changing.\n");
                /*If not changing, replace old dbPass back into dbPass*/
                strncpy(dbPass, dbPassOld, UI_BUFFERS_SIZE);
                cleanUpBuffers();
                return 1;
            } else {
                printf("Changed password.\n");
                deriveHMACKey();
                memcpy(HMACKeyNew, HMACKey, sizeof(char) * SHA512_DIGEST_LENGTH);
            }

            /*Change cipher and digest if specified*/
            if (condition.userChoseCipher == true) {
                strncpy(encCipherName, encCipherNameFromCmdLine, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherNameFromCmdLine);
            }
            if (condition.userChoseDigest == true) {
                strncpy(messageDigestName, messageDigestNameFromCmdLine, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestNameFromCmdLine);
            }
        }
        /*-U was given but not -P and -c and/or -H might be there*/
        else if (condition.updatingDbEnc == true && condition.updatingEntryPass != true) {
            if (condition.userChoseCipher == true) {
                strncpy(encCipherName, encCipherNameFromCmdLine, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherNameFromCmdLine);
            }
            if (condition.userChoseDigest == true) {
                strncpy(messageDigestName, messageDigestNameFromCmdLine, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestNameFromCmdLine);
            }
            memcpy(HMACKeyNew, HMACKey, sizeof(char) * SHA512_DIGEST_LENGTH);
        }
        /*If -P is given along with -c or -H*/
        else {
            /*Get new encryption password from user*/
            getPass("Enter new database password: ", dbPass);

            getPass("Verify password:", dbPassToVerify);
            if (strcmp(dbPass, dbPassToVerify) != 0) {
                printf("Passwords don't match, not changing.\n");
                strncpy(dbPass, dbPassOld, UI_BUFFERS_SIZE);
                exit(EXIT_FAILURE);
            } else {
                printf("Changed password.\n");
                deriveHMACKey();
                memcpy(HMACKeyNew, HMACKey, sizeof(char) * SHA512_DIGEST_LENGTH);
            }

            /*Change crypto settings*/
            if (condition.userChoseCipher == true) {
                strncpy(encCipherName, encCipherNameFromCmdLine, NAME_MAX);
                printf("Changing cipher to %s\n", encCipherNameFromCmdLine);
            }
            if (condition.userChoseDigest == true) {
                strncpy(messageDigestName, messageDigestNameFromCmdLine, NAME_MAX);
                printf("Changing digest to %s\n", messageDigestNameFromCmdLine);
            }
        }
        
        if(condition.userChosePBKDF2Iterations == true && (condition.updatingEntryPass == true || condition.userChoseCipher == true || condition.userChoseDigest == true))
        {
			PBKDF2Iterations = PBKDF2IterationsStore;
			printf("PBKDF2 iterations changed to %i\n", PBKDF2Iterations);
		}

        /*This will change to the cipher just specified*/
        configEvp();

        /*The updatingDbEnc function decrypts with the old key and cipher settings, re-encrypts with new key and/or cipher settings and writes to 3rd temp file*/
        int updateDbEncResult = updateDbEnc();

        if (updateDbEncResult == 0) {
            writeDatabase();
        }

    } else {
        printSyntax("passmanager"); /*Just in case something else happens...*/
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

void allocateBuffers()
{
	unsigned char *tmpBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
	if(tmpBuffer == NULL)
	{
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
	
    entryPass = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(entryPass == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(entryPass,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    entryPassToVerify = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(entryPassToVerify == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
	memcpy(entryPassToVerify,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    entryName = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(entryName == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(entryName,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    entryNameToFind = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(entryNameToFind == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(entryNameToFind,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    newEntry = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(newEntry == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(entryPass,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    newEntryPass = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(newEntryPass == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(newEntryPass,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    newEntryPassToVerify = calloc(sizeof(char), UI_BUFFERS_SIZE);
    if(newEntryPassToVerify == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(newEntryPassToVerify,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    dbPass = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(dbPass == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(dbPass,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    dbPassToVerify = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(dbPassToVerify == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(dbPassToVerify,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    dbPassOld = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(dbPassOld == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(tmpBuffer, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(dbPassOld,tmpBuffer,sizeof(unsigned char) * UI_BUFFERS_SIZE);

    HMACKey = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if(HMACKey == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(HMACKey, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    HMACKeyOld = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if(HMACKeyOld == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(HMACKeyOld, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    HMACKeyNew = calloc(sizeof(unsigned char), SHA512_DIGEST_LENGTH);
    if(HMACKeyNew == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    if (!RAND_bytes(HMACKeyNew, SHA512_DIGEST_LENGTH)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }

    evpSalt = calloc(sizeof(unsigned char), EVP_SALT_SIZE);
    if(evpSalt == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    
    free(tmpBuffer);
}

void genPassWord(int stringLength)
{
    unsigned char randomByte;
    char tempPassString[stringLength];
    int i = 0;

    /*Go until i has iterated over the length of the pass requested*/
    while (i < stringLength) {
        /*Gets a random byte from OpenSSL CSPRNG*/
        if (!RAND_bytes(&randomByte, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            exit(EXIT_FAILURE);
        }

        /*Tests that byte to be printable and not blank*/
        /*If it is it fills the temporary pass string buffer with that byte*/
        if (condition.generateEntryPass == true) {
            if ((isalnum(randomByte) != 0 || ispunct(randomByte) != 0) && isblank(randomByte) == 0) {
                tempPassString[i] = randomByte;
                i++;
            }
        }

        if (condition.generateEntryPassAlpha == true) {
            if ((isupper(randomByte) != 0 || islower(randomByte) != 0 || isdigit(randomByte) != 0) && isblank(randomByte) == 0) {
                tempPassString[i] = randomByte;
                i++;
            }
        }
    }

    /*Insert a null byte at the end of the random bytes since the buffer is padded*/
    /*Then send that to entryPass*/
    tempPassString[stringLength] = '\0';
    strncpy(entryPass, tempPassString, UI_BUFFERS_SIZE);
}

char* getPass(const char* prompt, char* paddedPass)
{
    size_t len = 0;
    int i;
    int passLength;
    char* pass = NULL;
    unsigned char *paddedPassTmp = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(paddedPassTmp == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}


    if (!RAND_bytes(paddedPassTmp, UI_BUFFERS_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        printf("\nPassword was too large\n");
        exit(EXIT_FAILURE);
    }
    memcpy(paddedPass,paddedPassTmp,sizeof(char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(paddedPassTmp, sizeof(char) * UI_BUFFERS_SIZE);
    free(paddedPassTmp);
    
    int nread;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr(fileno(stdin), &termisOld) != 0)
        exit(EXIT_FAILURE);
    termiosNew = termisOld;
    termiosNew.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0)
        exit(EXIT_FAILURE);

    /* Read the password. */
    printf("\n%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1)
        exit(EXIT_FAILURE);
    else if (nread > UI_BUFFERS_SIZE) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        OPENSSL_cleanse(pass, sizeof(char) * nread);
        free(pass);
        printf("\nPassword was too large\n");
        exit(EXIT_FAILURE);
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

int configEvp()
{
    /*If the user has specified a cipher to use*/
    if (condition.userChoseCipher == true) {
		
		if(!EVP_get_cipherbyname(encCipherName))
		{
			printf("Could not load cipher %s. Check that it is available with -c list\n", encCipherName);
			exit(EXIT_FAILURE);
		}
		else if (EVP_CIPHER_mode(EVP_get_cipherbyname(encCipherName)) == EVP_CIPH_GCM_MODE || EVP_CIPHER_mode(EVP_get_cipherbyname(encCipherName)) == EVP_CIPH_CCM_MODE)
		{
			printf("Program does not support GCM or CCM modes.\nAlready authenticates with HMAC-SHA512\n");
			exit(EXIT_FAILURE);
		}
		else if (EVP_CIPHER_mode(EVP_get_cipherbyname(encCipherName)) == EVP_CIPH_WRAP_MODE)
		{
			printf("Program does not support ciphers in wrap mode\n");
			exit(EXIT_FAILURE);
		}
		#ifdef EVP_CIPH_OCB_MODE
		else if (EVP_CIPHER_mode(EVP_get_cipherbyname(encCipherName)) == EVP_CIPH_OCB_MODE)
		{
			printf("Program does not support ciphers in OCB mode\n");
			exit(EXIT_FAILURE);
		}
		#endif
		else
			evpCipher = EVP_get_cipherbyname(encCipherName);

        /*If the cipher doesn't exists or there was a problem loading it return with error status*/
        if (!evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", encCipherName);
            exit(EXIT_FAILURE);
        }

    } else { /*If not default to aes-256-ctr*/
        strcpy(encCipherName, "aes-256-ctr");
        evpCipher = EVP_get_cipherbyname(encCipherName);
        if (!evpCipher) {
            fprintf(stderr, "Could not load cipher: %s\n", encCipherName);
            exit(EXIT_FAILURE);
        }
    }

    /*If the user has specified a digest to use*/
    if (condition.userChoseDigest == true) {
        evpDigest = EVP_get_digestbyname(messageDigestName);
        if (!evpDigest) {
            fprintf(stderr, "Could not load digest: %s Check if available with -H list\n", messageDigestName);
            exit(EXIT_FAILURE);
        }
    } else { /*If not default to sha512*/
        strcpy(messageDigestName, "sha512");
        evpDigest = EVP_get_digestbyname(messageDigestName);
        if (!evpDigest) {
            fprintf(stderr, "Could not load digest: %s Check if available with -H list\n", messageDigestName);
            exit(EXIT_FAILURE);
        }
    }
   
	return 0;
}

void genEvpSalt()
{

    unsigned char randomByte;
    int i = 0;

    while (i < EVP_SALT_SIZE) {
        if (!RAND_bytes(&randomByte, 1)) {
            printf("Failure: CSPRNG bytes could not be made unpredictable\n");
            exit(EXIT_FAILURE);
        }
        evpSalt[i] = randomByte;
        i++;
    }
}

int deriveHMACKey()
{

    int i;
    unsigned char hmacSalt[HMAC_SALT_SIZE];

    /*Derive a larger salt for HMAC from evpSalt*/
    /*Use a counter of 3 so this XOR doesn't undo last xor'd bytes*/
    for (i = 0; i < HMAC_SALT_SIZE; i++)
        hmacSalt[i] = evpSalt[i] ^ (i + 3);

    /*Generate a separate key to use for HMAC*/
    if(!PKCS5_PBKDF2_HMAC(dbPass, -1, hmacSalt, HMAC_SALT_SIZE, PBKDF2Iterations, EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, HMACKey))
    {
		printError("PBKDF2 deriveHmacKey Failed");
		exit(EXIT_FAILURE);
	}
	
	return 0;
}

int deriveEVPKey(char* dbPass, unsigned char* evpSalt, unsigned int saltLen,const EVP_CIPHER *evpCipher,const EVP_MD *evpDigest, unsigned char *evpKey, unsigned char *evpIv, int PBKDF2Iterations)
{
	/*First generate the key*/
	if (!PKCS5_PBKDF2_HMAC((char*)dbPass, strlen(dbPass),
		evpSalt, saltLen,
		PBKDF2Iterations,
		evpDigest,EVP_CIPHER_key_length(evpCipher),
		evpKey)) {
        printError("PBKDF2 failed\n");
        exit(EXIT_FAILURE);
    }
    
    /*If this cipher uses an IV, generate that as well*/
    if(EVP_CIPHER_iv_length(evpCipher) != 0) {
		if (!PKCS5_PBKDF2_HMAC((char*)dbPass, strlen(dbPass),
		    evpSalt, saltLen,
            PBKDF2Iterations,
            evpDigest,EVP_CIPHER_iv_length(evpCipher),
            evpIv)) {
        printError("PBKDF2 failed\n");
        exit(EXIT_FAILURE);
		}
	}
	
	return 0;
}

int writeDatabase()
{
    unsigned char *cryptoHeaderPadding = calloc(sizeof(unsigned char),CRYPTO_HEADER_SIZE);
    if(cryptoHeaderPadding == NULL)
    {
		printSysError(errno);
		return errno;
	}
    unsigned char *fileBuffer;
    int MACSize = SHA512_DIGEST_LENGTH;
    int fileSize = evpDataSize;
    
    if (!RAND_bytes(cryptoHeaderPadding, CRYPTO_HEADER_SIZE)) {
        printf("Failure: CSPRNG bytes could not be made unpredictable\n");
        exit(EXIT_FAILURE);
    }
    memcpy(cryptoHeader,cryptoHeaderPadding,sizeof(char) * CRYPTO_HEADER_SIZE);
    free(cryptoHeaderPadding);
    
    FILE *dbFile;
    
    dbFile = fopen(dbFileName, "wb");
    if (dbFile == NULL) {
        printFileError(dbFileName,errno);
        exit(EXIT_FAILURE);
    }

    /*Write crypto information as a header*/

    /*Write encCipherName:messageDigestName to cryptoHeader*/
    if(snprintf(cryptoHeader, CRYPTO_HEADER_SIZE, "%s:%s", encCipherName, messageDigestName) < 0)
    {
		printError("snprintf failed");
		exit(EXIT_FAILURE);
	}
    
    /*Append PBKDF2Iterations to end of cryptoHeader*/
    memcpy(cryptoHeader + (strlen(cryptoHeader) + 1), &PBKDF2Iterations, sizeof(PBKDF2Iterations));
	
    /*Write the salt*/
    if(fwriteWErrCheck(evpSalt, sizeof(unsigned char), EVP_SALT_SIZE, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}

    /*Write buffer pointed to by cryptoHeader*/
    if(fwriteWErrCheck(cryptoHeader, sizeof(unsigned char), CRYPTO_HEADER_SIZE, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    /*Copy data from temp file into what will be the password database*/
    fileBuffer = calloc(sizeof(char), fileSize);
    if(fileBuffer == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}

	if(condition.databaseBeingInitalized == true)
	{
		if(fwriteWErrCheck(dbInitBuffer, sizeof(char), fileSize, dbFile) != 0) {
			printSysError(returnVal);
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		if(fwriteWErrCheck(encryptedBuffer, sizeof(char), fileSize, dbFile) != 0) {
			printSysError(returnVal);
			exit(EXIT_FAILURE);
		}
	}

    fclose(dbFile);

    free(fileBuffer);
    
    /*Generate MAC from EVP data written to temp file*/
    dbFile = fopen(dbFileName, "rb");
    if (dbFile == NULL) {
        printFileError(dbFileName,errno);
        exit(EXIT_FAILURE);
    }
    chmod(dbFileName, S_IRUSR | S_IWUSR);
    
    fileBuffer = calloc(returnFileSize(dbFileName),sizeof(unsigned char));
    if(fileBuffer == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}

    if(freadWErrCheck(fileBuffer,sizeof(unsigned char),returnFileSize(dbFileName),dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    if(HMAC(EVP_sha512(), HMACKey, MACSize, fileBuffer, returnFileSize(dbFileName), MACdBFileGenerates, HMACLengthPtr) == NULL)
    {
		printError("HMAC falied");
		exit(EXIT_FAILURE);
	}
    free(fileBuffer);

    fclose(dbFile);
		
	/*Now append new generated MAC to end of the EVP data*/
    dbFile = fopen(dbFileName, "ab");
    if (dbFile == NULL)
    {
        printFileError(dbFileName,errno);
        exit(EXIT_FAILURE);
    }
    chmod(dbFileName, S_IRUSR | S_IWUSR);
    
    /*Append the MACs and close the file*/
    if(fwriteWErrCheck(MACdBFileGenerates, sizeof(unsigned char), MACSize, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    if(fwriteWErrCheck(MACcipherTextGenerates, sizeof(unsigned char), MACSize, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}

    fclose(dbFile);

    return 0;
}

int openDatabase()
{
    char* token;

    unsigned char* verificationBuffer;
    int MACSize = SHA512_DIGEST_LENGTH;
    int fileSize = returnFileSize(dbFileName);
    evpDataSize = fileSize - (EVP_SALT_SIZE + CRYPTO_HEADER_SIZE + (MACSize * 2));

    FILE *dbFile;

    dbFile = fopen(dbFileName, "rb");
    if (dbFile == NULL)
    {
        printFileError(dbFileName,errno);
        exit(EXIT_FAILURE);
    }

    /*Grab the crypto information from header*/
    /*Then an EVP_SALT_SIZE byte salt for evpSalt*/
    /*Then will be the cipher and the message digest names delimited with ':'*/

    /*fread overwrites any randomly generated salt with the one read from file*/
    if(freadWErrCheck(evpSalt, sizeof(char), EVP_SALT_SIZE, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}

    /*Read the cipher and message digest information in*/
    if(freadWErrCheck(cryptoHeader, sizeof(char), CRYPTO_HEADER_SIZE, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    /*Read PBKDF2Iterations from end of cryptoHeader*/
    memcpy(&PBKDF2Iterations, cryptoHeader + (strlen(cryptoHeader) + 1), sizeof(int));
    
    /*Generate a separate salt and key for HMAC authentication*/
    deriveHMACKey();
    
    /*Copy all of the file minus the MACs but including the salt and cryptoHeader into a buffer for verification*/
    verificationBuffer = calloc(fileSize - (MACSize * 2),sizeof(unsigned char));
    if(verificationBuffer == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    
    /*Reset to beginning since reading in the salt and cryptoHeader have advanced the file position*/
    if(fseek(dbFile,0L,SEEK_SET) != 0)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    
    /*Read in the size of the file minus the size of the two MACs i.e. MACSize * 2*/
    if(freadWErrCheck(verificationBuffer,sizeof(unsigned char),fileSize - (MACSize * 2),dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    /*Set the file position to the beginning of the first MAC*/
    if(fseek(dbFile,fileSize - (MACSize * 2),SEEK_SET) != 0)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    
	if(freadWErrCheck(MACdBFileSignedWith, sizeof(unsigned char), MACSize, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    if(freadWErrCheck(MACcipherTextSignedWith, sizeof(unsigned char), MACSize, dbFile) != 0) {
		printSysError(returnVal);
		exit(EXIT_FAILURE);
	}
    
    if(HMAC(EVP_sha512(), HMACKey, MACSize, verificationBuffer, fileSize - (MACSize * 2), MACdBFileGenerates, HMACLengthPtr) == NULL)
    {
		printError("HMAC failed");
		exit(EXIT_FAILURE);
	}
    
    /*Verify authenticity of database*/
    if (compareMAC(MACdBFileSignedWith, MACdBFileGenerates, MACSize) != 0) {
		/*Return error status before proceeding and clean up sensitive data*/
        printMACErrMessage(0);

		fclose(dbFile);
		free(verificationBuffer);
        exit(EXIT_FAILURE);
    }
    
    /*Copy verificationBuffer to encryptedBuffer without the header information or MACs*/
    encryptedBuffer = calloc(sizeof(char), evpDataSize);
    if(encryptedBuffer == NULL)
    {
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    memcpy(encryptedBuffer, verificationBuffer + EVP_SALT_SIZE + CRYPTO_HEADER_SIZE, evpDataSize);

	fclose(dbFile);
	free(verificationBuffer);

    /*Use strtok to parse the strings delimited by ':'*/

    /*First the cipher*/
    token = strtok(cryptoHeader, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        exit(EXIT_FAILURE);
    }
    strncpy(encCipherName, token, NAME_MAX);

    token = strtok(NULL, ":");
    if (token == NULL) {
        printf("Could not parse header.\nIs %s a password file?\n", dbFileName);
        exit(EXIT_FAILURE);
    }

    /*Then the message digest*/
    strncpy(messageDigestName, token, NAME_MAX);

    /*Check the strings read are valid cipher and digest names*/
    evpCipher = EVP_get_cipherbyname(encCipherName);
    /*If the cipher doesn't exists or there was a problem loading it return with error status*/
    if (!evpCipher) {
        fprintf(stderr, "Could not load cipher %s. Is it installed? Use -c list to list available ciphers\n", encCipherName);
        exit(EXIT_FAILURE);
    }

    evpDigest = EVP_get_digestbyname(messageDigestName);
    if (!evpDigest) {
        fprintf(stderr, "Could not load digest %s. Is it installed? Use -c list to list available ciphers\n", messageDigestName);
        exit(EXIT_FAILURE);
    }

    if (condition.updatingDbEnc) {
        /*Copy old evpCipher to evpCipherOld and generate evpKeyOld based on this*/
        /*This needs to be done in openDatabase() before cipher and digest parameters are changed later on */
        evpCipherOld = evpCipher;
        PBKDF2IterationsOld = PBKDF2Iterations;
		
		deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKeyOld,evpIvOld,PBKDF2IterationsOld);
    }

    return 0;
}

int writePass()
{
    int i;
    long fileSize = evpDataSize, newFileSize, oldFileSize;

    int evpOutputLength;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    /*entryPass and entryName are both copied into infoBuffer, which is then encrypted*/
    unsigned char* infoBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE * 2);
    if(infoBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}
    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
    if(decryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    /*Copy bufers entryName and entryPass into infoBuffer, splitting the UI_BUFFERS_SIZE * 2 chars between the two*/
    for (i = 0; i < UI_BUFFERS_SIZE; i++)
        infoBuffer[i] = entryName[i];
    for (i = 0; i < UI_BUFFERS_SIZE; i++)
        infoBuffer[i + UI_BUFFERS_SIZE] = entryPass[i];

    if (condition.databaseBeingInitalized != true) {

		/*Verify authenticity of ciphertext loaded into encryptedBuffer*/
        if (verifyCiphertext(EVP_CIPHER_iv_length(evpCipher), fileSize, encryptedBuffer, HMACKey, evpIv) != 0) {
			/*Return error status before proceeding and clean up sensitive data*/
            printMACErrMessage(1);
            OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);

            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            return 1;
        }

        EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

        /*Decrypt file and store into decryptedBuffer*/
        if(evpDecrypt(ctx,fileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
		{
			printError("evpDecrypt failed");
			
	        OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
            free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);
	        
	        return 1;
	    }

        EVP_CIPHER_CTX_cleanup(ctx);
    }

    if (condition.databaseBeingInitalized == true) {
        EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);

		if(evpEncrypt(ctx,UI_BUFFERS_SIZE * 2,&evpOutputLength,dbInitBuffer,infoBuffer) != 0)
		{
			printError("evpEncrypt failed");
			free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);
	        
	        return 1;
		}
        
        EVP_CIPHER_CTX_cleanup(ctx);

        /*Clear out sensitive information in infoBuffer ASAP*/
        OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);
        
        /*Sign new ciphertext*/
        if(signCiphertext(EVP_CIPHER_iv_length(evpCipher), evpOutputLength, dbInitBuffer) != 0)
			return 1;
        
        evpDataSize = evpOutputLength;

    } else {

        EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);

        OPENSSL_cleanse(encryptedBuffer, sizeof(unsigned char) * fileSize);
        free(encryptedBuffer);
        encryptedBuffer = calloc(sizeof(unsigned char), evpOutputLength + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
        if(encryptedBuffer == NULL)
        {
			printSysError(errno);
			return errno;
		}

        for (i = 0; i < UI_BUFFERS_SIZE * 2; i++) {
            decryptedBuffer[evpOutputLength + i] = infoBuffer[i];
        }

        OPENSSL_cleanse(infoBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE * 2);

        oldFileSize = evpOutputLength;
        
        if(evpEncrypt(ctx,evpOutputLength + (UI_BUFFERS_SIZE * 2),&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
		{
			printError("evpEncrypt falied");
			free(infoBuffer);
            free(decryptedBuffer);
            free(encryptedBuffer);
            free(ctx);
	        
	        return 1;
		}
        
        EVP_CIPHER_CTX_cleanup(ctx);
        
        newFileSize = evpOutputLength;

        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize + (UI_BUFFERS_SIZE * 2) + EVP_MAX_BLOCK_LENGTH);
        
        /*Sign new ciphertext*/
        if(signCiphertext(EVP_CIPHER_iv_length(evpCipher), newFileSize, encryptedBuffer) != 0)
			return 1;
        
        evpDataSize = newFileSize;

    }
    
    printf("Added \"%s\" to database.\n", entryName);

	if (condition.sendToClipboard == true) {
		if(sendToClipboard(entryPass) == 0)
		{
			printf("New password sent to clipboard. Paste with middle-click.\n");
			printf("%i seconds before password is cleared from clipboard\n", xclipClearTimeSeconds);
		}
	}
	
    free(infoBuffer);
    free(decryptedBuffer);
    free(ctx);

    return 0;
}

int printPasses(char* searchString)
{
    int i, ii;
    int entriesMatched = 0;
    
    char entryName[UI_BUFFERS_SIZE];

    int evpOutputLength;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    long fileSize = evpDataSize;

    unsigned char* entryBuffer = calloc(sizeof(char), UI_BUFFERS_SIZE);
    unsigned char* passBuffer = calloc(sizeof(char), UI_BUFFERS_SIZE);
    unsigned char* decryptedBuffer = calloc(sizeof(char), fileSize + EVP_MAX_BLOCK_LENGTH);
    
    /*Verify authenticity of ciphertext loaded into encryptedBuffer*/
    if (verifyCiphertext(EVP_CIPHER_iv_length(evpCipher), fileSize, encryptedBuffer, HMACKey, evpIv) != 0) {
		/*Return error status before proceeding and clean up sensitive data*/
        printMACErrMessage(1);

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        return 1;
    }
    
    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);
    
    if(evpDecrypt(ctx,fileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
    {
			printError("evpDecrypt failed\n");
			free(entryBuffer);
	        free(passBuffer);
	        free(encryptedBuffer);
	        free(decryptedBuffer);
	        free(ctx);
	        
	        return 1;
	}
	
	EVP_CIPHER_CTX_cleanup(ctx);
	
    /*Loop to process the file.*/
    for (ii = 0; ii < evpOutputLength; ii += (UI_BUFFERS_SIZE * 2)) {

        /*Copy the decrypted information into entryBuffer and passBuffer*/
        for (i = 0; i < UI_BUFFERS_SIZE; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + UI_BUFFERS_SIZE];
        }
        
        memcpy(entryName,entryBuffer,UI_BUFFERS_SIZE);

        if (searchString != NULL)
        {
            /*Use strncmp and search the first n elements of entryBuffer, where n is the length of the search string*/
            /*This will allow the search of partial matches, or an exact match to be printed*/
            if (strncmp(searchString, entryName, strlen(searchString)) == 0) {
				entriesMatched++;
                if (condition.sendToClipboard == true) {
						printf("Matched \"%s\" to \"%s\"\n", searchString, entryBuffer);
					if (entriesMatched == 1 && condition.sendToClipboard == true)
					{
						if(sendToClipboard(passBuffer) == 0)
						{
							if(strcmp(searchString, entryName) == 0)
							{
								printf("Sent the entry's password to clipboard. Paste with middle-click.\n");
								printf("%i seconds before password is cleared from clipboard\n", xclipClearTimeSeconds);
							}
							else
							{
								printf("Sent the first matched entry's password to clipboard. Paste with middle-click.\n(Note: There may be more entries that matched your search string)\n");
								printf("%i seconds before password is cleared from clipboard\n", xclipClearTimeSeconds);
							}
				        }
				        break;
				    }
                } else {
                    printf("%s : %s\n", entryBuffer, passBuffer);
                }
            }
        } else /*If an entry name wasn't specified, print them all*/
            printf("%s : %s\n", entryBuffer, passBuffer);
    }

    if (entriesMatched == 0 && searchString != NULL)
        printf("Nothing matched \"%s\"\n", searchString);

    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpOutputLength + EVP_MAX_BLOCK_LENGTH);

	
    free(entryBuffer);
    free(passBuffer);
    free(decryptedBuffer);
    free(ctx);

    return 0;
}
int deletePass(char* searchString)
{	
	int i, ii = 0, iii = 0;
    int lastCheck = 0;
    int entriesMatched = 0;
    
    char entryName[UI_BUFFERS_SIZE];

    int evpOutputLength;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    unsigned char* fileBuffer;
    unsigned char* fileBufferOld;

    unsigned char* entryBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(entryBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}
    unsigned char* passBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(passBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    long fileSize = evpDataSize, oldFileSize, newFileSize;

    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if(decryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    /*Verify authenticity of ciphertext loaded into encryptedBuffer*/
    if (verifyCiphertext(EVP_CIPHER_iv_length(evpCipher), fileSize, encryptedBuffer, HMACKey, evpIv) != 0) {
		/*Return error status before proceeding and clean up sensitive data*/
        printMACErrMessage(1);

        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);
        return 1;
    }

    /*Now make a buffer for the file.  Reallocate later if we find a match to delete*/
    fileBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if(fileBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

    /*Decrypt file and store into temp buffer*/
    if(evpDecrypt(ctx,fileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
    {
		printError("evpDecrypt failed");
		
        free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
		free(ctx);
        
        return 1;
	}
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    oldFileSize = evpOutputLength;

    for (ii = 0; ii < oldFileSize; ii += (UI_BUFFERS_SIZE * 2)) {

        for (i = 0; i < UI_BUFFERS_SIZE; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + UI_BUFFERS_SIZE];
        }
        
        memcpy(entryName,entryBuffer,UI_BUFFERS_SIZE);

        /*Use strcmp to match the exact entry here*/
        if ((lastCheck = strncmp(searchString, entryName, strlen(searchString))) == 0)
        {
            if (ii == (oldFileSize - (UI_BUFFERS_SIZE * 2))) /*If ii is one entry short of fileSize*/
            {
                if (entriesMatched < 1) /*If entry was matched we need to shrink the file buffer*/
                {
                    /*Re-size the buffer to reflect deleted passwords*/
                    /*Not using realloc() because it will leak and prevent wiping sensitive information*/
                    fileBufferOld = calloc(sizeof(unsigned char), oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    if(fileBufferOld == NULL)
                    {
						printSysError(errno);
						return errno;
					}
                    memcpy(fileBufferOld, fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    free(fileBuffer);

                    fileBuffer = calloc(sizeof(unsigned char), oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    if(fileBuffer == NULL)
                    {
						printSysError(errno);
						return errno;
					}
                    memcpy(fileBuffer, fileBufferOld, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    OPENSSL_cleanse(fileBufferOld, sizeof(unsigned char) * oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched));
                    free(fileBufferOld);
                    
                    }
            }
            printf("Matched \"%s\" to \"%s\" (Deleting)...\n", searchString, entryBuffer);
            entriesMatched++;
        } else {
            for (i = 0; i < UI_BUFFERS_SIZE * 2; i++) {
                if (i < UI_BUFFERS_SIZE)
                    fileBuffer[iii + i] = entryBuffer[i];
                else
                    fileBuffer[(iii + UI_BUFFERS_SIZE) + (i - UI_BUFFERS_SIZE)] = passBuffer[i - UI_BUFFERS_SIZE];
            }
            iii += UI_BUFFERS_SIZE * 2;
        }
    }
    
    if(entriesMatched >= 1)
		newFileSize = oldFileSize - ((UI_BUFFERS_SIZE * 2) * entriesMatched);
	else
		newFileSize = oldFileSize;

    /*Clear out sensitive information ASAP*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize);

    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), (newFileSize + EVP_MAX_BLOCK_LENGTH));
    if(encryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    
    if(evpEncrypt(ctx,newFileSize,&evpOutputLength,encryptedBuffer,fileBuffer) != 0)
    {
		printError("evpEncrypt failed");
		free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
		free(ctx);
        
        return 1;
	}
    
    EVP_CIPHER_CTX_cleanup(ctx);

    /*Clear out sensitive information in fileBuffer ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * newFileSize);
    
    newFileSize = evpOutputLength;
    evpDataSize = newFileSize;

	/*Sign new ciphertext*/
	if(signCiphertext(EVP_CIPHER_iv_length(evpCipher), newFileSize, encryptedBuffer) != 0)
		return 1;

    if (entriesMatched < 1) {
        printf("Nothing matched that exactly.\n");
    } else {
        printf("If you deleted more than you intended to, restore from %s.autobak\n", dbFileName);
    }

	
    free(entryBuffer);
    free(passBuffer);
    free(decryptedBuffer);
    free(fileBuffer);
    free(ctx);

    return 0;
}

int updateEntry(char* searchString)
{
    int i, ii = 0;
    int entriesMatched = 0;
    int passLength;
        
    char entryName[UI_BUFFERS_SIZE];
    char passWord[UI_BUFFERS_SIZE];

    int evpOutputLength;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    int numberOfSymbols = 0;

    unsigned char* fileBuffer;

    unsigned char* entryBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(entryBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}
    unsigned char* passBuffer = calloc(sizeof(unsigned char), UI_BUFFERS_SIZE);
    if(passBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    long fileSize = evpDataSize, oldFileSize, newFileSize;

    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if(decryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    /*Verify authenticity of ciphertext loaded into encryptedBuffer*/
    if (verifyCiphertext(EVP_CIPHER_iv_length(evpCipher), fileSize, encryptedBuffer, HMACKey, evpIv) != 0) {
		/*Return error status before proceeding and clean up sensitive data*/
        printMACErrMessage(1);

		OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * UI_BUFFERS_SIZE);

		free(newEntryPass);
        free(entryBuffer);
        free(passBuffer);
        free(encryptedBuffer);
        free(decryptedBuffer);

        return 1;
    }

    fileBuffer = calloc(sizeof(unsigned char), fileSize);
    if(fileBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    EVP_DecryptInit(ctx, evpCipher, evpKey, evpIv);

    /*Decrypt file and store into decryptedBuffer*/
    if(evpDecrypt(ctx,fileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
    {
		printError("evpDecrypt failed");
		
		OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * UI_BUFFERS_SIZE);

		free(newEntryPass);
        free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
		free(ctx);
        
        return 1;
	}
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    oldFileSize = evpOutputLength;

    for (ii = 0; ii < oldFileSize; ii += (UI_BUFFERS_SIZE * 2)) {

        for (i = 0; i < UI_BUFFERS_SIZE; i++) {
            entryBuffer[i] = decryptedBuffer[i + ii];
            passBuffer[i] = decryptedBuffer[i + ii + UI_BUFFERS_SIZE];
        }
        
        memcpy(entryName,entryBuffer,UI_BUFFERS_SIZE);
        memcpy(passWord,passBuffer,UI_BUFFERS_SIZE);

        /*If an entry matched searchString or allpasses was specified*/
        if (strncmp(searchString, entryName, strlen(searchString)) == 0 || condition.updateAllPasses == true) {

            entriesMatched++;
            
            if (condition.sendToClipboard == true && condition.updateAllPasses == false && entriesMatched >= 1) {
				if(entriesMatched > 1)
					/*Need to skip to the writeBackLoop so updates aren't written to other matches, but those matches are written back unmodifed*/
					/*Do this after entriesMatched is greater than 1 so that only one password is sent to the clipboard*/
					goto writeBackLoop;
			}

            //Update content in entryName before encrypting back
            if (condition.entryGiven == true) {
                memcpy(entryBuffer, newEntry, UI_BUFFERS_SIZE);
            }

            /*This will preserve the alphanumeric nature of a password if it has no symbols*/
            if (condition.updateAllPasses == true) {
				passLength = strlen(passWord);
                for (i = 0; i < passLength; i++) {
                    if (isupper(passBuffer[i]) == 0 && islower(passBuffer[i]) == 0 && isdigit(passBuffer[i]) == 0)
                        numberOfSymbols++;
                }

                if (numberOfSymbols == 0) {
                    condition.generateEntryPassAlpha = true;
                    condition.generateEntryPass = false;
                } else {
                    condition.generateEntryPassAlpha = false;
                    condition.generateEntryPass = true;
                }
                numberOfSymbols = 0;
            }

            /*Generate random passwords if gen was given, and for all if allpasses was given*/
            /*If allpasses was given, they will be random regardless if gen is not set.*/
            if (condition.updatingEntryPass == true && (condition.generateEntryPass == true || condition.updateAllPasses == true)) {

                /*This will generate a new pass for each entry during a bulk update*/
                if (condition.genPassLengthGiven == true) {
                    genPassWord(genPassLength);
                    /*Have to copy over entryPass to newEntryPass since genPassWord() operates on entryPass buffer*/
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                }
                
                memcpy(passBuffer, newEntryPass, UI_BUFFERS_SIZE);
                /*Do the same as above but if an alphanumeric pass was specified*/
            } else if (condition.updatingEntryPass == true && (condition.generateEntryPassAlpha == true || condition.updateAllPasses == true)) {
                if (condition.genPassLengthGiven == true) {
                    genPassWord(genPassLength);
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                } else {
                    genPassWord(DEFAULT_GENPASS_LENGTH);
                    strncpy(newEntryPass, entryPass, UI_BUFFERS_SIZE);
                }
                
                memcpy(passBuffer, newEntryPass, UI_BUFFERS_SIZE);
            }
            
            if (condition.updatingEntryPass == true)
            {
                memcpy(passBuffer, newEntryPass, UI_BUFFERS_SIZE);
            }

            /*Copy the entryBuffer and passBuffer out to fileBuffer*/
            for (i = 0; i < UI_BUFFERS_SIZE * 2; i++) {
                if (i < UI_BUFFERS_SIZE)
                    fileBuffer[ii + i] = entryBuffer[i];
                else
                    fileBuffer[(ii + UI_BUFFERS_SIZE) + (i - UI_BUFFERS_SIZE)] = passBuffer[i - UI_BUFFERS_SIZE];
            }
            if (condition.entryGiven == true)
                printf("Updating \"%s\" to \"%s\" ...\n", searchString, entryBuffer);
            else
                printf("Matched \"%s\" to \"%s\" (Updating...)\n", searchString, entryBuffer);
                
        } else { /*Write back the original entry and pass if nothing matched searchString*/
			writeBackLoop:
            for (i = 0; i < UI_BUFFERS_SIZE * 2; i++) {
                if (i < UI_BUFFERS_SIZE)
                    fileBuffer[ii + i] = entryBuffer[i];
                else
                    fileBuffer[(ii + UI_BUFFERS_SIZE) + (i - UI_BUFFERS_SIZE)] = passBuffer[i - UI_BUFFERS_SIZE];
            }
        }
    }

    /*Clear out sensitive buffers ASAP*/
    OPENSSL_cleanse(entryBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(passBuffer, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    /*Don't cleanse newEntryPass yet if we're going to send it to the clipboard*/
    if(condition.sendToClipboard != true)
		OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * UI_BUFFERS_SIZE);
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize + EVP_MAX_BLOCK_LENGTH);
    OPENSSL_cleanse(passWord, sizeof(char) * UI_BUFFERS_SIZE);
    

    /*Clear the old encrypted information out to use encryptedBuffer to store cipher-text of modifications*/
    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), oldFileSize + EVP_MAX_BLOCK_LENGTH);
    if(encryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    
    if(evpEncrypt(ctx,oldFileSize,&evpOutputLength,encryptedBuffer,fileBuffer) != 0)
    {
		printError("evpEncrypt failed");
		
		OPENSSL_cleanse(newEntryPass, sizeof(unsigned char) * UI_BUFFERS_SIZE);

		free(newEntryPass);
		free(entryBuffer);
		free(passBuffer);
		free(encryptedBuffer);
		free(decryptedBuffer);
		free(fileBuffer);
		free(ctx);
        
        return 1;
	}
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    newFileSize = evpOutputLength;
    evpDataSize = newFileSize;

    /*Clear out fileBuffer ASAP*/
    OPENSSL_cleanse(fileBuffer, sizeof(unsigned char) * oldFileSize);

	/*Sign new ciphertext*/
    if(signCiphertext(EVP_CIPHER_iv_length(evpCipher), newFileSize, encryptedBuffer) != 0)
		return 1;

    /*Check if any entries were updated*/
    if (entriesMatched < 1) {
        printf("Nothing matched the entry specified, nothing was updated.\n");
    } else
    {
        printf("If you updated more than you intended to, restore from %s.autobak\n", dbFileName);
	}
	if(condition.sendToClipboard == true)
	{
		if(sendToClipboard(newEntryPass) == 0)
		{
			printf("\nSent new password to clipboard. Paste with middle-click.\n");
			printf("%i seconds before password is cleared from clipboard\n", xclipClearTimeSeconds);
			if(entriesMatched > 1)
				printf("(Note: Multiple entries matched, only updated and sent fist entry's password to clipboard)\n");
		}
	}
	OPENSSL_cleanse(newEntryPass, sizeof(char) * UI_BUFFERS_SIZE);
	
    free(entryBuffer);
    free(passBuffer);
    free(decryptedBuffer);
    free(fileBuffer);
    free(ctx);

    return 0;
}

int updateDbEnc()
{
    int evpOutputLength;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    long fileSize = evpDataSize, oldFileSize, newFileSize;

    unsigned char* decryptedBuffer = calloc(sizeof(unsigned char), fileSize + EVP_MAX_BLOCK_LENGTH);
    if(decryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}
    
	/*Verify authenticity of ciphertext loaded into encryptedBuffer*/
    if (verifyCiphertext(EVP_CIPHER_iv_length(evpCipherOld),fileSize,encryptedBuffer,HMACKeyOld, evpIvOld) != 0) {
		/*Return error status before proceeding and clean up sensitive data*/
        printMACErrMessage(1);

        free(decryptedBuffer);
        free(encryptedBuffer);
        return 1;
    }

    memcpy(HMACKey, HMACKeyOld, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);

    EVP_DecryptInit(ctx, evpCipherOld, evpKeyOld, evpIvOld);

    /*Decrypted the data into decryptedBuffer*/   
    if(evpDecrypt(ctx,fileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
    {
		printError("evpDecrypt");
		
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(ctx);
        
        return 1;
	}
	
    EVP_CIPHER_CTX_cleanup(ctx);
    
    oldFileSize = evpOutputLength;
	
	if(deriveEVPKey(dbPass, evpSalt, EVP_SALT_SIZE,evpCipher,evpDigest,evpKey,evpIv,PBKDF2Iterations) != 0) {
			return 1;
	}

    memcpy(HMACKey, HMACKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);
    
    free(encryptedBuffer);
    encryptedBuffer = calloc(sizeof(unsigned char), oldFileSize + EVP_MAX_BLOCK_LENGTH);
    if(encryptedBuffer == NULL)
    {
		printSysError(errno);
		return errno;
	}

    EVP_EncryptInit_ex(ctx, evpCipher, NULL, evpKey, evpIv);
    
    if(evpEncrypt(ctx,oldFileSize,&evpOutputLength,encryptedBuffer,decryptedBuffer) != 0)
    {
		printError("evpEncrypt failed");
		
        free(encryptedBuffer);
        free(decryptedBuffer);
        free(ctx);
        
        return 1;
	}

    EVP_CIPHER_CTX_cleanup(ctx);
    
    newFileSize = evpOutputLength;
    evpDataSize = newFileSize;

    /*Clear sensitive data from decryptedBuffer ASAP*/
    OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * oldFileSize);
    
    /*Must generate new key for HMAC in case PBKDF2Iterations was updated*/
    /*Not going to test conditional if PBKDF2Iterations were updated since it doesn't effect other parameters to update it anyway*/
    if(deriveHMACKey() != 0)
		return 1;
	
	/*Sign new ciphertext*/
	if(signCiphertext(EVP_CIPHER_iv_length(evpCipher), newFileSize, encryptedBuffer) != 0)
		return 1;
	
    free(decryptedBuffer);
    free(ctx);

    return 0;
}

int verifyCiphertext(unsigned int IvLength, unsigned int encryptedBufferLength, unsigned char *encryptedBuffer, unsigned char *HMACKey, unsigned char *evpIv)
{
	/*Generate MAC from both cipher-text and IV*/
	unsigned char *hmacBuffer = calloc(sizeof(unsigned char), encryptedBufferLength + IvLength);
	if(hmacBuffer == NULL)
	{
		printSysError(errno);
		return errno;
	}
	memcpy(hmacBuffer,evpIv,IvLength);
	memcpy(hmacBuffer + IvLength,encryptedBuffer,encryptedBufferLength);
    if(HMAC(EVP_sha512(), HMACKey, SHA512_DIGEST_LENGTH, hmacBuffer, encryptedBufferLength + IvLength, MACcipherTextGenerates, HMACLengthPtr) == NULL)
    {
		printError("verifyCipherText HMAC failure");
		return 1;
	}
    OPENSSL_cleanse(hmacBuffer,sizeof(char) * (encryptedBufferLength + IvLength));
    free(hmacBuffer);
    
    if(compareMAC(MACcipherTextSignedWith, MACcipherTextGenerates, SHA512_DIGEST_LENGTH) != 0)
		return 1;
	else
		return 0;
}

int signCiphertext(unsigned int IvLength, unsigned int encryptedBufferLength, unsigned char *encryptedBuffer)
{
	/*Generate MAC from both cipher-text and IV*/
	unsigned char *hmacBuffer = calloc(sizeof(unsigned char), encryptedBufferLength + IvLength);
	if(hmacBuffer == NULL)
	{
		printSysError(errno);
		exit(EXIT_FAILURE);
	}
    memcpy(hmacBuffer,evpIv,IvLength);
    memcpy(hmacBuffer + IvLength,encryptedBuffer,encryptedBufferLength);
    if(HMAC(EVP_sha512(), HMACKey, SHA512_DIGEST_LENGTH, hmacBuffer, encryptedBufferLength + IvLength, MACcipherTextGenerates, HMACLengthPtr) == NULL)
    {
		printError("signCipherText HMAC failure");
		return 1;
	}
    OPENSSL_cleanse(hmacBuffer,sizeof(char) * (encryptedBufferLength + IvLength));
    free(hmacBuffer);
    
    return 0;
}

int evpDecrypt(EVP_CIPHER_CTX* ctx, int evpInputLength, int* evpOutputLength, unsigned char *encryptedBuffer, unsigned char *decryptedBuffer)
{
	int evpLengthUpdate = 0;

    if (!EVP_DecryptUpdate(ctx, decryptedBuffer, evpOutputLength, encryptedBuffer, evpInputLength)) {
        printf("EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);
        
        return 1;
    }

    if (!EVP_DecryptFinal_ex(ctx, decryptedBuffer + *evpOutputLength, &evpLengthUpdate)) {
        printf("EVP_DecryptFinal_ex failed \n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);
        
        return 1;
    }
    *evpOutputLength += evpLengthUpdate;
    
    return 0;
}

int evpEncrypt(EVP_CIPHER_CTX* ctx, int evpInputLength, int* evpOutputLength, unsigned char *encryptedBuffer, unsigned char *decryptedBuffer)
{
	int evpLengthUpdate = 0;

    if (!EVP_EncryptUpdate(ctx, encryptedBuffer, evpOutputLength, decryptedBuffer, evpInputLength)) {
        printf("EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);

        return 1;
    }
    
    if (!EVP_EncryptFinal_ex(ctx, encryptedBuffer + *evpOutputLength, &evpLengthUpdate)) {
        printf("EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_cleanse(decryptedBuffer, sizeof(unsigned char) * evpInputLength + EVP_MAX_BLOCK_LENGTH);

        return 1;
    }
    *evpOutputLength += evpLengthUpdate;
    
    return 0;
}

int sendToClipboard(char* textToSend)
{
	int passLength = strlen(textToSend);
    char xclipCommand[] = "xclip -in";
    char wipeCommand[] = "xclip -in";
    char wipeOutBuffer[passLength];
    char passBuffer[passLength];

	/*Using openssl_cleanse instead of memset so optimization won't wipe it out*/
    OPENSSL_cleanse(wipeOutBuffer, passLength);
    
    FILE* xclipFile = popen(xclipCommand, "w");
    pid_t pid, sid;
    
    strncpy(passBuffer,textToSend,passLength);

    if (xclipFile == NULL) {
        printSysError(errno);
        return 1;
    }

    if(fwriteWErrCheck(passBuffer, sizeof(char), passLength, xclipFile) != 0) {
		printSysError(returnVal);
		return 1;
	}
		
    if (pclose(xclipFile) == -1) {
        printSysError(errno);
        return 1;
    }
    
    OPENSSL_cleanse(passBuffer,passLength);
    OPENSSL_cleanse(textToSend,passLength);

    /*Going to fork off the application into the background, and wait 30 seconds to send zeroes to the xclip clipboard*/

    /*Stops the parent process from waiting for child process to complete*/
    signal(SIGCHLD, SIG_IGN);
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        return 1;
    }
    /* If we got a good PID, then we can return the parent process to the calling function.*/
    if (pid > 0) {
		/*Do not change from 0 here or the parent process's calling function won't print information about what was sent to clipboard*/
        return 0;
    }

    /* At this point we are executing as the child process */
    /* Don't return 1 on error after this point*/

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        printSysError(errno);
    }

    /*Tells child process to ignore sighup so the child doesn't exit when the parent does*/
    signal(SIGHUP, SIG_IGN);

    sid = setsid();
        
    sleep(xclipClearTimeSeconds);
    
    FILE* wipeFile = popen(wipeCommand, "w");
    
    if (wipeFile == NULL) {
        printSysError(errno);
    }

    if(fwriteWErrCheck(wipeOutBuffer, sizeof(char), passLength, wipeFile) != 0) {
		printSysError(returnVal);
	}
	
	/*Use fclose instead of pclose because pclose will use wait4() and throw an error since SIG_ING is set*/
    fclose(wipeFile);
	
	/*Leave this as 1 otherwise messages about what was sent to clipboard will be repeated*/
	/*The child process will return to calling function, and a conditional tests if this function returns 0*/
	/*When this child process's version of the function returns 1, the information will not be printed again*/
	/*Don't simply exit otherwise sensitive buffers in the rest of the child process's calling function will not be cleared/freed*/
    return 1;
}

int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	if (fread(ptr, size, nmemb, stream) != nmemb / size) {
		if(feof(stream))
		{
			returnVal = EBADMSG;
			return EBADMSG;
		}
		else if(ferror(stream))
		{
			returnVal = errno;
			return errno;
		}
	}
	
    return 0;
}

int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
		if(feof(stream))
		{
			returnVal = EBADMSG;
			return EBADMSG;
		}
		else if(ferror(stream))
		{
			returnVal = errno;
			return errno;
		}
	}
            
    return 0;
}

int compareMAC(const void * in_a, const void * in_b, size_t len)
{
	/*This is CRYPTO_memcmp from cryptlib.c in OpenSSL 1.1.*/
	/*Added here for backward-compatability to OpenSSL 1.0.1*/
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

void cleanUpBuffers()
{
	/*OPENSSL_cleanse won't be optimized away by the compiler*/

    OPENSSL_cleanse(entryPass, sizeof(char) * UI_BUFFERS_SIZE);free(entryPass);
    OPENSSL_cleanse(entryName, sizeof(char) * UI_BUFFERS_SIZE);free(entryName);
    OPENSSL_cleanse(entryNameToFind, sizeof(char) * UI_BUFFERS_SIZE);free(entryNameToFind);
    OPENSSL_cleanse(entryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);free(entryPassToVerify);
    OPENSSL_cleanse(newEntry, sizeof(char) * UI_BUFFERS_SIZE);free(newEntry);
    OPENSSL_cleanse(newEntryPass, sizeof(char) * UI_BUFFERS_SIZE);free(newEntryPass);
    OPENSSL_cleanse(newEntryPassToVerify, sizeof(char) * UI_BUFFERS_SIZE);free(newEntryPassToVerify);
    OPENSSL_cleanse(dbPass, sizeof(unsigned char) * strlen(dbPass));free(dbPass);
    OPENSSL_cleanse(dbPassOld, sizeof(unsigned char) * UI_BUFFERS_SIZE);free(dbPassOld);
    OPENSSL_cleanse(dbPassToVerify, sizeof(unsigned char) * UI_BUFFERS_SIZE);free(dbPassToVerify);
    OPENSSL_cleanse(evpKey, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(evpIv, sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(evpKeyOld, sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(evpIvOld, sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    OPENSSL_cleanse(HMACKey, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);free(HMACKey);
    OPENSSL_cleanse(HMACKeyOld, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);free(HMACKeyOld);
    OPENSSL_cleanse(HMACKeyNew, sizeof(unsigned char) * SHA512_DIGEST_LENGTH);free(HMACKeyNew);

	free(evpSalt);
    free(encryptedBuffer);
}

bool fileNonExistant(const char* filename)
{
    struct stat st;
    int result = stat(filename, &st);
    return result;
}

int returnFileSize(const char* filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

void encListCallback(const OBJ_NAME* obj, void* arg)
{
	/*I don't want to use -Wno-unused-parameter to suppress compiler warnings*/
	/*So this does nothing with it to make gcc think it did something*/
	arg = arg;
	
    printf("Cipher: %s\n", obj->name);
}

void mdListCallback(const OBJ_NAME* obj, void* arg)
{
	arg = arg;
	
    printf("Digest: %s\n", obj->name);
}

void signalHandler(int signum)
{
    printf("\nCaught signal %d\n\nCleaning up buffers...\n", signum);
    // Cleanup and close up stuff here

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    // Terminate program
    exit(signum);
}

int printMACErrMessage(int errMessage)
{
	if(errMessage == 0)
		printf("Database Authentication Failed\nThis could mean the database file has been modified since the program last ran.\
				\nOr simply that you entered the wrong password.\n");
	else if(errMessage == 1)
		printf("Ciphertext Authentication Failed\
				\nThis means the content of the ciphertext or IV has been changed since loaded or generated from file.\
				\nThis definitely should not happen!\n");

    return 0;
}

int printSyntax(char* arg)
{
    printf("\
\nReccomend Syntax: \
\n\n%s passmanager  -a entry name | -r entry name | -d entry name | -u entry name | -U  [-n new name ] [-p new entry password] [-l random password length] [-c cipher] [-H digest] [-i iterations ] [ -P ] [-x database password] [ -C ] [ -s seconds ] -f database file\
\nOptions: \
\n-n new name - entry name up to 512 characters (can contain white space or special characters) \
\n-p new entry password - entry password up to 512 characters (don't call to be prompted instead) ('gen' will generate a random password, 'genalpha' will generate a random password with no symbols)\
\n-l random password length - makes 'gen' or 'genalpha' generate a password random password length digits long (defaults to 16 without this option) \
\n-c cipher - Specify 'list' for a list of methods available to OpenSSL. Default: aes-256-ctr. \
\n-H digest - Specify 'list' for a list of methods available to OpenSSL. Default: sha512. \
\n-i iterations - Specify amount of PBKDF2 to be iterations. Default: 500000\
\n-P - In Update entry or Update database mode (-u and -U respectively) this option enables updating the entry password or database password via prompt instead of as command line argument \
\n-C - end entry password directly to clipboard. Clipboard is cleared 30 seconds afterward. (needs xclip) \
\n-s seconds - clear clipboard seconds after instead of default 30 \
\n-x database password - To supply database password as command-line argument (not reccomended) \
\n-f - database file ( must be specified ) \
\n-h - Quick usage help \
\nEach functioning mode has a subset of applicable options \
\n-a - Add mode \
\n     \t-p 'password'\
\n     \t-l 'password length'\
\n     \t-x 'database password'\
\n     \t-c 'cipher' - Initializes a password database with encryption of 'cipher' \
\n     \t-H 'digest' - Derives keys for 'cipher' with digest 'digest'.\
\n     \t-i 'iterations' - Specify PBKDF2 iteration amount as iterations. \
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
\n     \t-i 'iterations' - Update iteration amount used by PBKDF2 to 'iterations'\
\nVersion 3.2.6\
\n\
",
        arg);
    printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return 1;
}
