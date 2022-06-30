/* headers.h - header fies */

/* Copyright 2022 Kenneth Brown */

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

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#    include <sys/prctl.h>
#elif defined __FreeBSD__
#    include <sys/procctl.h>
#endif
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/time.h>
#ifdef HAVE_LIBX11
#    include <X11/Xatom.h>
#    include <X11/Xlib.h>
#endif

/*Do NOT change the order of these*/

/*Macro defintions*/
#include "macros.h"

/*Structure definitions*/
#include "structs.h"

/*Function prototypes*/
#include "prototypes.h"
