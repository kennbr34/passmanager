/* checkmem.c - checks for sufficient free memory */

/* Copyright 2020 Kenneth Brown */

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

#include "headers.h"

size_t checkFreeMem(void) 
{
    FILE *memInfoFile = fopen("/proc/meminfo", "r");
    if(memInfoFile == NULL) {
        perror("/proc/meminfo");
        fclose(memInfoFile);
        return 0;
    }

    char memInfoLine[256];
    while(fgets(memInfoLine, sizeof(memInfoLine), memInfoFile))
    {
        size_t freeMem;
        if(sscanf(memInfoLine, "MemAvailable: %lu kB", &freeMem) == 1)
        {
            fclose(memInfoFile);
            return freeMem * 1024;
        }
    }

    fclose(memInfoFile);
    
    return 0;
}

int checkNeededMem(struct cryptoVar *cryptoStructPtr) 
{
    
    /* Needed memory for work factors = 128*p*r + 128*(2+N)*r bytes*/
    size_t pFactor = (size_t)cryptoStructPtr->scryptPFactor;
    size_t rFactor = (size_t)cryptoStructPtr->scryptRFactor;
    size_t NFactor = (size_t)cryptoStructPtr->scryptNFactor;
    size_t memNeeded = 128*pFactor*rFactor + 128*(2+NFactor)*rFactor;
    size_t memFree = checkFreeMem();
    
    if(memFree == 0) {
        PRINT_ERROR("Could not read how much memory is free\n");
        return 1;
    } else if (memFree < memNeeded) {
        printf("scrypt needs more memory to work with specified work parameters\n");
        printf("N = %zu, r = %zu, p = %zu\nEstimated Memory required: %lu bytes\nMemory Free: %lu bytes\n",
        NFactor,
        rFactor,
        pFactor,
        memNeeded,
        memFree);
        return 1;
    }
    
    return 0;
}
