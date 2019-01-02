/*Removes the salt left form yaxafileutil so that the plain-text and cipher-text can be used in pxorc*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[])
{

	if(argc == 1 || argc < 4) {
		printf("Use: %s infile outfile bytes\n", argv[0]);
		exit(1);
	}

	FILE *inFile = fopen(argv[1],"rb");
	if(inFile == NULL)
	{
		perror(argv[1]);
		exit(1);
	}
	FILE *outFile = fopen(argv[2],"wb");
	if(outFile == NULL)
	{
		perror(argv[2]);
		exit(1);
	}

	long fileSize;

	fseek(inFile,0L,SEEK_END);
	fileSize = ftell(inFile);
	fseek(inFile,atoi(argv[3]),SEEK_SET);

	for(int i=0; i < fileSize - atoi(argv[3]); i++)
		fputc(fgetc(inFile),outFile);

	fclose(inFile);
	fclose(outFile);

	return 0;
}
