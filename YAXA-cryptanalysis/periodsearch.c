/*Searches a keystream produced with pxorc or running yaxafileutil against a file of zeroes
Will recursively search for a second byte-sequence of a specified length to find
the beginning of a periodic key. If no period is found the keystream is a one-time-pad*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
	FILE *patternFile = fopen(argv[1],"rb");
	FILE *patternFileOpen;
	if(patternFile == NULL)
	{
		perror(argv[1]);
		exit(1);
	}

	if(argc < 3)
	{
		printf("Specify a length of bytes to search\n");
		exit(1);
	}

	unsigned int byteSequenceLength = atoi(argv[2]);
	unsigned char *byteSequence = malloc(sizeof(unsigned char) * byteSequenceLength);
	unsigned char *byteSequenceStore = malloc(sizeof(unsigned char) * byteSequenceLength);
	unsigned int byteSequencesSearched = 0;

	while(!feof(patternFile))
	{

		fread(byteSequence,sizeof(unsigned char),byteSequenceLength,patternFile);
		printf("Searching for: ");
		for(int i=0; i < byteSequenceLength; i++)
			printf("%x", byteSequence[i] & 0xff);
		printf("\n");
		byteSequencesSearched++;

		patternFileOpen = fopen(argv[1],"rb");

		fseek(patternFileOpen,ftell(patternFile),SEEK_SET);

		while(!feof(patternFileOpen))
		{

			fread(byteSequenceStore,sizeof(unsigned char),byteSequenceLength,patternFileOpen);
			if(memcmp(byteSequence,byteSequenceStore,byteSequenceLength) == 0 && ftell(patternFileOpen) - (byteSequenceLength * byteSequencesSearched) > 0)
			{
				printf("Periodic key begins at file offset %i and ends at file offset %ld\nKey period is %ld bytes\n", (byteSequenceLength * byteSequencesSearched) - byteSequenceLength, ftell(patternFileOpen) - byteSequenceLength, ftell(patternFileOpen) - (byteSequenceLength * byteSequencesSearched));
				exit(1);
			}
		}
		fclose(patternFileOpen);
	}

	return 0;
}
