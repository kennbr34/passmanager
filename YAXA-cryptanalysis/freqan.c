//Kenneth Brown
//freqan: Frequency Analysis
/*
An array of 256 integers keeps track of the amount of Bytes with a specific value.

ByteValue[Byte]++

This increments the ByteValue amount according to the value of Byte.
The value corresponds to the array element, so if Byte is 248, ByteValue[248] is incremented to represent the amount of Byte with value 248.
*/

#define _FILE_OFFSET_BITS 64
#define VALMAX 256 /*The maximum value to test for*/
#include <errno.h>
#include <stdio.h>

int grepString(char string[], char byte);

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		 printf("Usage:\n%s file [option] [string]\n", argv[0]);
		 printf("-i processes only the values in string\n-v processes only the values not in string\n-d displays or does not display values based on -i and -v, instead of counting them in the statistics\n");
		 return 1;
	}
	FILE *in = stdin;

	if(argv[1][0] != '-')
		in = fopen(argv[1],"rb");

        if(in==NULL) {                                                                                                
                perror(argv[1]);                                                                                        
                printf("errno: %d\n", errno);                                                                           
                return errno;                                                                                           
        }

	int ByteValue[VALMAX], Byte, i;
	double FileSize = 0;

	/*Initialize ByteValue amounts to 0*/

	for(i = 0; i < VALMAX; i++)
	{
		ByteValue[i] = 0;
	}

	Byte = fgetc(in);

	while(!feof(in))
	{
		if(!feof(in))
		{

			if(argc == 2)
			{
				ByteValue[Byte]++;
				FileSize++;
			}
			else
			{
				if(grepString(argv[2],'v') != 0) /*if 'v' is not found in argv[2]*/
				{
					if(grepString(argv[2],'d') != 0)
					{
						if(grepString(argv[3],Byte) == 0)
						{
							ByteValue[Byte]++;
						}
						FileSize++;
					}
					else
					{
						if(grepString(argv[3],Byte) == 0)
                	                        {
                        	                        ByteValue[Byte]++;
	                        	                FileSize++;
						}
					}
				}

				else if(grepString(argv[2],'i') != 0)
				{
					if(grepString(argv[2],'d') != 0)
                        	        {
                                	        if(grepString(argv[3],Byte) != 0)
                                        	{
                                                	ByteValue[Byte]++;
	                                        }
        	                                FileSize++;
                	                }
                        	        else
                                	{
	                                        if(grepString(argv[3],Byte) != 0)
        	                                {
                	                                ByteValue[Byte]++;
                        	                        FileSize++;
                                	        }
	                        	}
				}
			}
	
		}

		Byte = fgetc(in);
	}

	for(i = 0; i < VALMAX; i++)
	{
		if(ByteValue[i] != 0)
		{
			if( ((ByteValue[i] / FileSize) * 100) >= 10)
			{
				printf("%%%lf\t", (ByteValue[i] / FileSize) * 100);
				printf("%i / %i\tD:%i\tH:%x\tA:\'%c\'\n", ByteValue[i], (int)FileSize, i, i, (char)i);
			}
			else
			{
				printf("%%0%lf\t", (ByteValue[i] / FileSize) * 100);
                	        printf("%i / %i\tD:%i\tH:%X\tA:\'%c\'\n", ByteValue[i], (int)FileSize, i, i, (char)i);
			}
		}
	}

	printf("\n");

	fclose(in);
	return 0;
}

int grepString(char string[], char byte)
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
