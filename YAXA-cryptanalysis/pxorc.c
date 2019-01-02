/*XOR plain-text against cipher-text to reveal the keystream that was used to encrypt it*/

#include <stdio.h>
#include <stdlib.h>



int main(int argc, char *argv[])
{
	int i;
	long fileSize;
	unsigned char *pBuffer;
	unsigned char *cBuffer;

	if(argc != 3){
		printf("Use: %s plaintext-file ciphertext-file > keystream-file", argv[0]);
		exit(1);
	}

	FILE *pTextFile = fopen(argv[1],"rb"), *cTextFile = fopen(argv[2],"rb");

	fseek(pTextFile,0L,SEEK_END);

	fileSize = ftell(pTextFile);

	rewind(pTextFile);

	pBuffer = malloc(sizeof(unsigned char) * fileSize);
	cBuffer = malloc(sizeof(unsigned char) * fileSize);

	fread(pBuffer,sizeof(unsigned char),fileSize,pTextFile);
	fread(cBuffer,sizeof(unsigned char),fileSize,cTextFile);

	for(i=0; i < fileSize; i++)
		printf("%c", pBuffer[i] ^ cBuffer[i]);

	return 0;
}
