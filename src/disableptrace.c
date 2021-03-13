/* disableptrace.c - disables ptrace and core dumping of passmanager process */

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

void disablePtrace(void)
{
#ifdef __linux__
    /*Set process core to not be dumpable*/
    /*Also prevents ptrace attaching to the process*/
    /*Disable if you need to debug*/
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
#elif defined __FreeBSD__
    /*If using FreeBSD procctl can do the same thing*/
    int procCtlArg = PROC_TRACE_CTL_DISABLE;
    if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &procCtlArg) == -1) {
        PRINT_SYS_ERROR(errno);
        exit(EXIT_FAILURE);
    }
#endif
}
