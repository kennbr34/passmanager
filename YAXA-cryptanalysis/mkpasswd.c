/*This program generates a password with no repeat characters, and allows the user to control the amount of each type of character in it*/
//Kenneth Brown
//2009

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h>

#define VALMAX 256

void printSyntax(char arg[]);
void stringGen(char *string, int stringLength);
int grepString(char *string, char byte);

struct optionStruct
{
        int LCase;
        int UCase;
        int Sym;
        int Dig;
        int Verbosity;
	int Amount;
        int Seed;
	int Repeats;
};

struct optionStruct options;

int main(int argc, char *argv[])
{
        /*Let's allocate a buffer to store our generated string*/
        /*Since we're seeking to avoid repeats, the longest pass we can create will be 256 bytes*/
        char *passStorage = malloc(VALMAX);
        char randomByte;
        int i, seed = 0;
        int passLength;
        int Verbosity = 0;
	int opt, errflg = 0;

	options.LCase = VALMAX;
        options.UCase = VALMAX;
        options.Dig = VALMAX;
        options.Sym = VALMAX;

        options.Seed = time(0);

	options.Amount = 1;

        if(argc == 1)
        {
                printSyntax(argv[0]);
                return 1;
        }

        /*Let's run through the command line options*/
	
	while ((opt = getopt(argc, argv, ":hvl:u:d:s:a:S:L:")) != -1)
        {
                switch(opt)
                {
			case 'v':
				options.Verbosity = 1;
			break;
			case 'h':
	                        printSyntax(argv[0]);
        	                return 1;
			break;
			case 'a':
				if(optarg[0] == '-')
				{
					printf("Option -a requires an operand\n");
					errflg++;
				}
				else
	        	                options.Amount = atoi(argv[2]);
			break;
			case 'r':
                	        options.Repeats = 1;
			break;
			case 's':
				if(optarg[0] == '-')
				{
					printf("Option -s requires an operand\n");
					errflg++;
				}
	                        else
        	                        options.Sym = atoi(optarg);
	                break;
			case 'd':
                	        if(optarg[0] == '-')
				{
					printf("Option -d requires an operand\n");
					errflg++;
				}
	                        else
        	                        options.Dig = atoi(optarg);
			break;
			case 'l':
	                        if(optarg[0] == '-')
				{
					printf("Option -l requires an operand\n");
					errflg++;
				}
                	        else
                        	        options.LCase = atoi(optarg);
			break;
			case 'u':
	                        if(optarg[0] == '-')
				{
					printf("Option -u requires an operand\n");
					errflg++;
				}
                	        else
                        	        options.UCase = atoi(optarg);
			break;
			case 'S':
				if(optarg[0] == '-')
				{
					printf("Option -S requires an operand\n");
					errflg++;
				}
				else
				{
		                        options.Seed = 0;
        		                for(i = 0; (unsigned)i < strlen(optarg); i++)
                		                options.Seed += optarg[i];
				}
			break;
			case 'L':
				if(optarg[0] == '-')
				{
					printf("Option -L requires an operand\n");
					errflg++;
				}
				else
		                        passLength = atoi(optarg);
			break;
                        case ':':
                                printf("Option -%c requires an operand\n", optopt);
                                errflg++;
                        break;
                        case '?':
                                printf("Unrecognized option: -%c\n", optopt);
                                errflg++;
                }
        }

        if(errflg)
        {
                printSyntax(argv[0]);
                return 1;
        }

        /*passLength = atoi(argv[0]);*/
        srand(options.Seed);

	for(i = 0; i < options.Amount; i++)
	{
	        /*Generate a password with enough entropy to be adequately secure*/
	        stringGen(passStorage, passLength);

	        /*Print a frequency analysis of password*/
        	if(options.Verbosity == 1)
	                freqAn(passStorage, passLength);
	        printf("%s\n", passStorage);
	}

        return 0;
}

int freqAn(char *string, int stringLength)
{
        int ByteValue[VALMAX], Byte, i;
	int LCase = 0, UCase = 0, Dig = 0, Sym = 0;
        double FileSize = stringLength;

        /*Initialize ByteValue amounts to 0*/

        for(i = 0; i < VALMAX; i++)
        {
                ByteValue[i] = 0;
        }

        for(i = 0; i < stringLength; i++)
        {

                ByteValue[string[i]]++;
		if(islower(string[i]) != 0)
			LCase++;
		if(isupper(string[i]) != 0)
			UCase++;
		if(isdigit(string[i]) != 0)
			Dig++;
		if(ispunct(string[i]) != 0)
			Sym++;

        }

        for(i = 0; i < VALMAX; i++)
        {
                if(ByteValue[i] != 0)
                {
                        if( ((ByteValue[i] / FileSize) * 100) >= 10)
                        {
                                fprintf(stderr,"%%%lf\t", (ByteValue[i] / FileSize) * 100);
                                fprintf(stderr,"%i / %i\tD:%i\tH:%x\tA:\'%c\'\n", ByteValue[i], (int)FileSize, i, i, (char)i);
                        }
                        else
                        {
                                fprintf(stderr,"%%0%lf\t", (ByteValue[i] / FileSize) * 100);
                                fprintf(stderr,"%i / %i\tD:%i\tH:%X\tA:\'%c\'\n", ByteValue[i], (int)FileSize, i, i, (char)i);
                        }
                }
        }

        printf("\n%i LCase %i UCase %i Digits %i Symbols\n\n", LCase, UCase, Dig, Sym);

}

void stringGen(char *string, int stringLength)
{
        char randomByte;
        int i = 0;

        /*We make a Lower Case, Upper Case, Number, and Symbol counter variable*/
        int low = 0, upp = 0, num = 0, sym = 0;

	/*Wipe out previous string*/
	for(i = 0; i < VALMAX; i++)
		string[i] = '\0';

if(options.Repeats == 0)
{

        for(i = 0; i < stringLength;)
        {
                /*Get a random byte*/
                randomByte = rand();

                if(grepString(string, randomByte) == 0)
                {
                        /*If randomByte does not already exist in string, is a printable character, and is not space*/
                        if(isprint(randomByte) != 0 && isspace(randomByte) == 0)
                        {
                                string[i] = randomByte;
                                i++;

                                if(islower(randomByte) != 0)
                                {
                                        if(low == options.LCase)
                                        {
                                                i--;
                                                string[i] = '\0';
                                        }
                                        else
                                                low++;
                                }
                                else if(isupper(randomByte) != 0)
                                {
                                        if(upp == options.UCase)
                                        {
                                                i--;
                                                string[i] = '\0';
                                        }
                                        else
                                                upp++;
                                }
                                else if(isdigit(randomByte) != 0)
                                {
                                        if(num == options.Dig)
                                        {
                                                i--;
                                                string[i] = '\0';
                                        }
                                        else
                                                num++;
                                }
                                else if(ispunct(randomByte) != 0)
                                {
                                        if(sym == options.Sym)
                                        {
                                                i--;
                                                string[i] = '\0';
                                        }
                                        else
                                                sym++;
                                }
                        }

			/*low, upp, num and sym are checked to see if they are less than desired value*/
                        if(upp < options.UCase)
                        {
                                /*This is looped until a desired character type is achieved*/
                                while(1)
                                {
                                        randomByte = rand();
                                        if(grepString(string, randomByte) == 0)
                                        {
                                                if(isupper(randomByte) != 0)
                                                {
                                                        string[i] = randomByte;
                                                        i++;
							upp++;
                                                        break;
                                                }
                                        }
                                }
                        }
                        if(low < options.LCase)
                        {
                                while(1)
                                {
                                        randomByte = rand();
                                        if(grepString(string, randomByte) == 0)
                                        {
                                                if(islower(randomByte) != 0)
                                                {
                                                        string[i] = randomByte;
                                                        i++;
							low++;
                                                        break;
                                                }
                                        }
                                }
                        }
                        if(num < options.Dig)
                        {
                                while(1)
                                {
                                        randomByte = rand();
                                        if(grepString(string, randomByte) == 0)
                                        {
                                                if(isdigit(randomByte) != 0)
                                                {
                                                        string[i] = randomByte;
							num++;
                                                        i++;
                                                        break;
                                                }
                                        }
                                }
                        }
                        if(sym < options.Sym)
                        {
                                while(1)
                                {
                                        randomByte = rand();
                                        /*We need to also make sure that the character is not a space when using isprint*/
                                        if(grepString(string, randomByte) == 0)
                                        {
                                                if(ispunct(randomByte) != 0 && isspace(randomByte) == 0)
                                                {
                                                        string[i] = randomByte;
							sym++;
                                                        i++;
                                                        break;
                                                }
                                        }
                                }
                        }
                }
        }
}
else
{
	for(i = 0; i < stringLength;)
        {                            
                /*Get a random byte*/
                randomByte = rand(); 

                                                      
                        /*If randomByte does not already exist in string, is a printable character, and is not space*/
                        if(isprint(randomByte) != 0 && isspace(randomByte) == 0)                                      
                        {                                                                                             
                                string[i] = randomByte;                                                               
                                i++;                                                                                  

                                if(islower(randomByte) != 0)
                                {                           
                                        if(low == options.LCase)
                                        {                       
                                                i--;            
                                                string[i] = '\0';
                                        }                        
                                        else                     
                                                low++;           
                                }                                
                                else if(isupper(randomByte) != 0)
                                {                                
                                        if(upp == options.UCase) 
                                        {                        
                                                i--;             
                                                string[i] = '\0';
                                        }                        
                                        else                     
                                                upp++;           
                                }                                
                                else if(isdigit(randomByte) != 0)
                                {                                
                                        if(num == options.Dig)   
                                        {                        
                                                i--;             
                                                string[i] = '\0';
                                        }                        
                                        else                     
                                                num++;           
                                }                                
                                else if(ispunct(randomByte) != 0)
                                {                                
                                        if(sym == options.Sym)   
                                        {                        
                                                i--;             
                                                string[i] = '\0';
                                        }                        
                                        else                     
                                                sym++;           
                                }                                
                        }                                        

                        /*low, upp, num and sym are checked to see if they are less than desired value*/
                        if(upp != options.UCase)                                                                
                        {                                                                                      
                                /*This is looped until a desired character type is achieved*/                  
                                while(1)                                                                       
                                {                                                                              
                                        randomByte = rand();                                                   
	                                	if(isupper(randomByte) != 0)                                   
						{
                                                        string[i] = randomByte;                                
                                                        i++;                                                   
                                                        upp++;                                                 
                                                        break;                                                 
                                                }                                                              
                                }                                                                              
                        }                                                                                      
                        if(low != options.LCase)                                                                
                        {                                                                                      
                                while(1)                                                                       
                                {                                                                              
                                        randomByte = rand();                                                   
                                                if(islower(randomByte) != 0)                                   
                                                {                                                              
                                                        string[i] = randomByte;                                
                                                        i++;                                                   
                                                        low++;                                                 
                                                        break;                                                 
                                                }                                                              
                                }                                                                              
                        }                                                                                      
                        if(num != options.Dig)                                                                  
                        {                                                                                      
                                while(1)                                                                       
                                {                                                                              
                                        randomByte = rand();                                                   
                                                if(isdigit(randomByte) != 0)                                   
                                                {                                                              
                                                        string[i] = randomByte;                                
                                                        num++;                                                 
                                                        i++;                                                   
                                                        break;                                                 
                                                }                                                              
                                }                                                                              
                        }                                                                                      
                        if(sym != options.Sym)                                                                  
                        {                                                                                      
                                while(1)                                                                       
                                {                                                                              
                                        randomByte = rand();                                                   
                                        /*We need to also make sure that the character is not a space when using isprint*/
                                                if(ispunct(randomByte) != 0 && isspace(randomByte) == 0)                  
                                                {                                                                         
                                                        string[i] = randomByte;                                           
                                                        sym++;                                                            
                                                        i++;                                                              
                                                        break;                                                            
                                        }                                                                                 
                                }                                                                                         
                        }                                                                                                 
        }                                                                                                                 

}

	/*Cut string off at stringLength because it might be one byte over*/
	string[stringLength] = '\0';

}

int grepString(char *string, char byte)
{
        int stringLength = 0;
        int i, boolean = 0;

        for(i = 0; string[i] != '\0'; i++)
                stringLength++;

        for(i = 0; i < stringLength; i++)
        {
                if(byte == string[i])
                boolean++;
        }

        return boolean;
}

void printSyntax(char arg[])
{
        printf("Usage:\t %s [-h | -v] [-a] [-r] [-S] [seed] [-l | -u | -d | -s ] -L passLength\n-h user for help\n-v for verbose \n-a for amount of passwords\n enable repeat characters\n-S use [seed] to seed prng\n -l -u -d -s\nlcase ucase digits and symbols respectively\nyou can specify a maximum occurrence of each\n\nfor example\n %s -a 1000 -s 3 -l 1 -u 1 -d 3 -v -L 8\nwill generate 1000 passwords 8 characters long comprised of 3 symbols 1 lcase 1 ucase 3 digits and showing analysis of each one\n %s -a 1000 -s 0 -L 8\nsimply generates 1000 passwords each 8 characters long with no symbols\nwhile\n %s -s 4 -L 16\ncreates a pass with at most 4 symbols\n", arg, arg, arg, arg);
}
