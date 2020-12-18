/* lockmemory.c - locks program memory to prevent sensitive data being sent to swap */

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

void lockMemory(void)
{
    /*Check for super user priveleges*/
    if (geteuid() != 0 && getuid() != 0) {
        fprintf(stderr, "euid: %i uid: %i\n", geteuid(), getuid());
        fprintf(stderr, "No priveleges to lock memory all memory. Your sensitive data might be swapped to disk. Proceed anyway? [Y/n]: ");
        if (getchar() != 'Y') {
            fprintf(stderr, "Aborting\n");
            exit(EXIT_FAILURE);
        }
    } else {

        /*Structure values for rlimits*/
        struct rlimit memlock;

        /*Set RLIMIT values to inifinity*/
        memlock.rlim_cur = RLIM_INFINITY;
        memlock.rlim_max = RLIM_INFINITY;

        /*Raise limit of locked memory to unlimited*/
        if (setrlimit(RLIMIT_MEMLOCK, &memlock) == -1) {
            PRINT_SYS_ERROR(errno);
            exit(EXIT_FAILURE);
        }

        /*Lock all current and future  memory from being swapped*/
        if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
            PRINT_SYS_ERROR(errno);
            exit(EXIT_FAILURE);
        }

        /*Drop root before executing the rest of the program*/
        if (geteuid() == 0 && getuid() != 0) { /*If executable was not started as root, but given root privelge through SETUID/SETGID bit*/
            if (seteuid(getuid())) {           /*Drop EUID back to the user who executed the binary*/
                PRINT_SYS_ERROR(errno);
                exit(EXIT_FAILURE);
            }
            if (setuid(getuid())) { /*Drop UID back to the privelges of the user who executed the binary*/
                PRINT_SYS_ERROR(errno);
                exit(EXIT_FAILURE);
            }
            if (getuid() == 0 || geteuid() == 0) { /*Fail if we could not drop root priveleges, unless started as root or with sudo*/
                fprintf(stderr, "Could not drop root\n");
                exit(EXIT_FAILURE);
            }
        }
    }
}
