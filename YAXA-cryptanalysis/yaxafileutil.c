/*A stripped-down demo of YAXA used to encrypt one file to another using a password*/
/*Encrypt a file of zeroes to produce a file which is just the keystream itself plus the header information*/

/*

  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

/*This is the highest number 'i' will be allowed to reach when referencing yaxaKey[i]*/
#define YAXA_KEY_LENGTH 1024

/*This buffer holds the yaxaKey and should be YAXA_KEY_LENGTH + 1*/
#define YAXA_KEYBUF_SIZE 1025

/*This is the highest number 'i' will be allowed to reach when reference yaxaNonce[i]*/
#define YAXA_NONCE_LENGTH 64

/*This buffer holds the yaxaNonce and should be YAXA_NONCE_LENGTH + 1*/
#define YAXA_NONCEBUF_SIZE 65

/*Define sizes of salts*/
#define YAXA_SALT_SIZE 16

/*Define size of tag*/
#define YAXA_TAG_SIZE 8

/*The default PBKDF2 and EVP_BytesToKey iteration count as per RFC 2889 reccomendation*/
/*The final iteration will differ from this depending on length of user pass and salts generated*/
#define PBKDF2_ITERATIONS 1000


/*Structs needed to hold termios info when resetting terminal echo'ing after taking password*/
struct termios termisOld, termiosNew;

int keyIterationFactor = 1000; /*Default reccomended amount of PBKDF2 iterations*/

unsigned char* userPass; /*Will hold the user-supplied password to derive yaxaKey from*/

/*YAXA variables*/
unsigned long long keyStreamGenByte = 0; /*This is the last byte XOR'd to form the keystream and is sequentially incremented to form  a key counter*/
unsigned char yaxaKeyArray[16][SHA512_DIGEST_LENGTH]; /*Two dimensional array is needed so that PBKDF2 can produce 16 strings, 64 bytes each, concatenated to form 1024 bytes*/
unsigned int originalPassLength; /*The original length of the user supplied password*/
unsigned char *yaxaNonce; /*A 65 byte array to be used as a nonce in YAXA*/
unsigned char* yaxaKeyChunk; /*Holds 64 bytes in yaxaKeyChunk before being concatenated to form yaxaKey*/
unsigned char* yaxaKey; /*Will hold the final yaxa key derived in yaxaKDF()*/
unsigned char* yaxaSalt; /*unique 8-byte salt prepended to each cipher text from which PBKDF2 derives the nonce and kye for yaxa*/

/*Prototype functions*/
int printSyntax(char* arg); /*Print program usage and help*/
int returnFileSize(const char* filename); /*Returns filesize using stat()*/
void allocateBuffers(); /*Allocates all the buffers used*/
void cleanUpBuffers(); /*Writes zeroes to all the buffers we used when done*/
void genYaxaSalt(); /*Generates YAXA salt*/
void yaxaKDF(); /*YAXA key deriving function*/
unsigned char yaxa(unsigned char messageByte, unsigned char keyByte, unsigned char nonceByte); /*YAXA encryption/decryption function*/
void signalHandler(int signum); /*Signal handler for Ctrl+C*/
char* getPass(const char* prompt); /*Function to retrive passwords with no echo*/

/*yaxaTag will be encrypted and prepended to head of cipher-text*/
/*can check if the user supplied password was correct by decrypting first 8 bytes after salt and checking it against this tag*/
/*This would be better done with MAC or HMAC but since this is just a demo program it will suffice*/
const unsigned char yaxaTag[] = "YAXAFILE"; /*Odds are pretty low the 2nd set of 8 bytes in a file will ever decode to this unless password was right*/
unsigned char yaxaTagTemp[YAXA_TAG_SIZE]; /*Array to store the bytes decrypted from file to test against yaxaTag*/
unsigned char fileChar; /*Need to hold the byte retrived from fgetc() to insert it into yaxaTagTemp without advancing file pos*/

int main(int argc, char* argv[])
{
    /*Print help if no arguments given*/
    if (argc == 1) {
        printSyntax(argv[0]);
        return 1;
    }
    
    if(strcmp(argv[1],"-e") != 0 && strcmp(argv[1],"-d") != 0) {
		printSyntax(argv[0]);
        return 1;
    }

	/*Allocates needed buffers and fills them with CSPRNG bytes*/
    allocateBuffers();

    /*This loads up all names of alogirithms for OpenSSL into an object structure so we can call them by name later*/
    OpenSSL_add_all_algorithms();
    
    FILE *inFile = fopen(argv[2],"rb");
    if(inFile == NULL)
	{
		perror(argv[2]);
		exit(1);
	}
    FILE *outFile = fopen(argv[3],"wb");
    if(outFile == NULL)
	{
			perror(argv[3]);
			exit(1);
	}
    
    /*Iterators*/
    int i, ii = 0;
    int n = 0;
    int x
    ;
    long fileSize;
    
	if(strcmp(argv[1],"-e") == 0)
	{
		/*Generate salt to be used in yaxaKDF() and prepended to head of cipher-text*/
		genYaxaSalt();

	if(argc == 4)
	{
		/*Recieve user password via prompt with no echo*/
		userPass = getPass("Enter password to encrypt with: ");
		
		/*Get the password again to verify it wasn't misspelled*/
	        if (strcmp(userPass, getPass("Verify password: ")) != 0) {
        	    printf("\nPasswords do not match.  Nothing done.\n\n");
	            cleanUpBuffers();
        	    return 1;
	        }
	}
	else if(argc == 5)
	{
		/*For testing purposes*/
		strcpy(userPass,argv[4]);
	}
        
        /*Now derive YAXA key and nonce using salt and user supplied password*/
        yaxaKDF();
       
		fileSize = returnFileSize(argv[2]);
		
		/*Prepend salt to head of file*/
		fwrite(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, outFile);
		
		/*Encrypt YAXATAG*/
		for (i = 0; i < YAXA_TAG_SIZE; i++) {
			
            yaxaTagTemp[i] = yaxa(yaxaTag[i], yaxaKey[ii], yaxaNonce[n]);
            
            if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
		}
		
		/*Now write encrypted yaxaTag to file*/
		fwrite(yaxaTagTemp, sizeof(unsigned char), YAXA_TAG_SIZE,outFile);
        
        /*Encrypt file and write it out*/
        for (i = 0; i < fileSize; i++) {
						
            fputc(yaxa(fgetc(inFile), yaxaKey[ii], yaxaNonce[n]), outFile);
            
            /*yaxaKey and yaxaNonce are allocated to 1025 and 65 bytes respectively*/
            /*See yaxaKDF() for details*/
			if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
        }
        fclose(outFile);
		fclose(inFile);
	}
	else if(strcmp(argv[1],"-d") == 0)
	{
		/*Read yaxaSalt from head of cipher-text*/
		fread(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, inFile);
	if(argc == 4)
		userPass = getPass("Enter password to decrypt with: ");
	else if(argc == 5)
		strcpy(userPass,argv[4]);

        yaxaKDF();

		/*Get the file size, minus the 16 bytes from salt and yaxaTag*/
		fileSize = returnFileSize(argv[2]) - (YAXA_SALT_SIZE + YAXA_TAG_SIZE);
		
		/*Decrypt 8 bytes after salt where yaxatag should be*/
		for (i = 0; i < YAXA_TAG_SIZE; i++) {
			fileChar = fgetc(inFile);
			
            yaxaTagTemp[i] = yaxa(fileChar, yaxaKey[ii], yaxaNonce[n]);
            
            if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
		}
        
        /*If what was read from file isn't equal to YAXAFILE then wrong password was used*/
        /*Otherwise garbage data would be output regardless if key was correct or not*/
        if(memcmp(yaxaTagTemp,yaxaTag,YAXA_TAG_SIZE) != 0)
		{
			printf("Wrong password\n");
			cleanUpBuffers();
			fclose(outFile);
			fclose(inFile);
			remove(argv[3]);
			exit(1);
		}
        
        for (i = 0; i < fileSize; i++) {
			
			fputc(yaxa(fgetc(inFile), yaxaKey[ii], yaxaNonce[n]), outFile);
                        
			if(ii < YAXA_KEY_LENGTH)
				ii++;
			else if(ii == YAXA_KEY_LENGTH)
				ii=0;
			if(n < YAXA_NONCE_LENGTH)
				n++;
			else if(n == YAXA_NONCE_LENGTH)
				n=0;
        }
        fclose(outFile);
		fclose(inFile);
	}

    cleanUpBuffers();
    return 0;
}

/*Use stat() to return the filesize of file given at filename*/
int returnFileSize(const char* filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

/*Allocate and randomize with OpenSSL's PRNG*/
void allocateBuffers()
{

	/*yaxaKey nees to be allocated to 1025 bytes so that yaxaKey[1024] can be validly accessed*/
    yaxaKey = malloc(sizeof(unsigned char) * YAXA_KEYBUF_SIZE);
    yaxaKey[YAXA_KEY_LENGTH] = 1;
    if (!RAND_bytes(yaxaKey, YAXA_KEY_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    userPass = malloc(sizeof(unsigned char) * YAXA_KEY_LENGTH);
    if (!RAND_bytes(userPass, YAXA_KEY_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaKeyChunk = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    if (!RAND_bytes(yaxaKeyChunk, YAXA_NONCE_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaNonce = malloc(sizeof(unsigned char) * YAXA_NONCEBUF_SIZE);
    yaxaNonce[YAXA_NONCE_LENGTH] = 1;
    if (!RAND_bytes(yaxaNonce, YAXA_NONCE_LENGTH))
        printf("Warning: CSPRNG bytes may not be unpredictable\n");

    yaxaSalt = malloc(sizeof(unsigned char) * YAXA_SALT_SIZE);
}

/*Fill up the buffers we stored the information in with 0's before exiting*/
void cleanUpBuffers()
{
    /*Fill each buffer with zeroes before exiting*/
    int i;

    for (i = 0; i < YAXA_KEYBUF_SIZE; i++)
        yaxaKey[i] = 0;

    for (i = 0; i < strlen(userPass); i++)
        userPass[i] = 0;

    for (i = 0; i < YAXA_NONCE_LENGTH; i++)
        yaxaKeyChunk[i] = 0;

    for (i = 0; i < YAXA_NONCEBUF_SIZE; i++)
        yaxaNonce[i] = 0;
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

/*Derive a cyrptographically secure key from the supplied database password*/
void yaxaKDF()
{

    int i;

    originalPassLength = strlen(userPass);

    /*Generate 512bit yaxa nonce*/
    /*Must generate +1 byte for iterators to reach 64th element*/
    /*Must be able to access yaxaNonce[64] because iterating only to 63 results in periodic keystream after only 262400 bytes*/
    PKCS5_PBKDF2_HMAC(userPass, -1, yaxaSalt, YAXA_SALT_SIZE, PBKDF2_ITERATIONS * originalPassLength, EVP_get_digestbyname("sha512"), YAXA_NONCEBUF_SIZE, yaxaNonce);

    /*Generate 8192 bit yaxa key*/
    for (i = 0; i < YAXA_SALT_SIZE; i++) {
        PKCS5_PBKDF2_HMAC(userPass, -1, yaxaSalt, YAXA_SALT_SIZE, PBKDF2_ITERATIONS * originalPassLength++ + yaxaSalt[i], EVP_get_digestbyname("sha512"), SHA512_DIGEST_LENGTH, yaxaKeyChunk);
        memcpy(yaxaKeyArray[i], yaxaKeyChunk, SHA512_DIGEST_LENGTH);
    }

    memcpy(yaxaKey, yaxaKeyArray, 1024);
    
    /*Generate a 1025th byte for yaxaKey, because the iterators need to be able to read yaxaKey[1024]*/
    /*If the iterators only reach yaxaKey[1023] the keystream generated in yaxa() will become periodic after only 262400 bytes*/
    /*If the iterators reach yaxaKey[1024] without this byte, it is always 0, but technically undefined behavior*/
    /*Going to generate 1 extra byte to prevent undefined behavior and predictability of that final byte*/
    yaxaKey[1024] = yaxaKey[1023] + yaxaKey[0];
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

	

    return keyStreamGenByte++  ^ nonceByte ^ keyByte ^ messageByte;
}

void signalHandler(int signum)
{
    printf("\nCaught signal %d\n\nCleaning up temp files...\nCleaning up buffers...\n", signum);
    // Cleanup and close up stuff here

    cleanUpBuffers();

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    // Terminate program
    exit(signum);
}

char* getPass(const char* prompt)
{
    size_t len = 0;
    char* pass = NULL;
    
    /*Pad the password with CSPRNG bytes*/
    /*This is mainly a remnant of this function's use in my password manager*/
    /*PBKDF2 will determine the length of the password at the first null byte*/
    /*In this program's use the padded bytes do not matter*/
    char* paddedPass = malloc(sizeof(unsigned char) * 512);
    paddedPass = malloc(sizeof(char) * 512);
    if (!RAND_bytes(paddedPass, 512))
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
    else if(nread > 512) {
		/* Restore terminal. */
		(void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
		for(int i = 0; i < nread; i++)
		pass[i] = 0;
		free(pass);
		cleanUpBuffers();
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
    
    /*Clean up pass and paddedPass contents in memory*/
    for (int i = 0; i < strlen(pass) + 1; i++)
        paddedPass[i] = pass[i];
    for(int i = 0; i < nread; i++)
		pass[i] = 0;
	free(pass);
    return paddedPass;
}

int printSyntax(char* arg)
{
    printf("\
\nUse: \
\n\n%s [-e|-d] infile outfile [pass]\
\n-e - encrypt infile to outfile\
\n-d - decrypt infile to outfile\
\n\
",
        arg);
        printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return 1;
}
