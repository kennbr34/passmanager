#include <stdio.h>

int main(int argc, char *argv[])
{
	int i, ii = 0;
	    int n = 0;
	    int x;
	unsigned char kc = 0;

	for (i = 0; i < 3411200 + 1; i++) {

			kc++;
			printf("M:%i yaxa(messageByte,yaxaKey[%i],yaxaNonce[%i]) KC = %i\n", i, ii, n, kc);

			if(ii < 1024)
				ii++;
			else if(ii == 1024)
			{
				printf("\'n\' when \'i\' @ %i = %i\n", i, n);
				ii=0;
			}
			if(n < 64)
				n++;
			else if(n == 64)
				n=0;
        }
}
