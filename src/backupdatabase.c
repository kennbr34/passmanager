/* writedatabase.c - backs up a password database */

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

#include "headers.h"

/* This will create a backup file of the database that the user can
 * restore from in case they made any inadvertant choices
 */
int backupDatabase(struct dbVar *dbStructPtr, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    char *backUpFileBuffer;

    /*Only backup if the database has actually been initialized, if not modifying the database, or if not just printing database information*/
    if (conditionsStruct->databaseBeingInitalized == false && conditionsStruct->readingPass == false && conditionsStruct->printingDbInfo == false) {

        /*Compose backup file name*/
        snprintf(dbStructPtr->backupFileName, NAME_MAX + BACKUP_FILE_EXT_LEN, "%s%s", dbStructPtr->dbFileName, dbStructPtr->backupFileExt);

        FILE *backUpFile = fopen(dbStructPtr->backupFileName, "w");

        /*Test if backup file could be created and give user option to proceed without*/
        if (backUpFile == NULL) {
            PRINT_FILE_ERROR(dbStructPtr->backupFileName, errno);
            fprintf(stderr, "Couldn't make a backup file. Proceed anyway? [Y/n]: ");
            if (getchar() != 'Y') {
                fprintf(stderr, "Aborting\n");
                return 1;
            }
        } else {

            /*Open database for reading*/
            FILE *copyFile = fopen(dbStructPtr->dbFileName, "r");

            /*Create buffer to load database into*/
            backUpFileBuffer = calloc(sizeof(char), returnFileSize(dbStructPtr->dbFileName));
            if (backUpFileBuffer == NULL) {
                PRINT_SYS_ERROR(errno);
                goto cleanup;
            }

            /*Read database into backUpFileBuffer*/
            if (freadWErrCheck(backUpFileBuffer, sizeof(char), returnFileSize(dbStructPtr->dbFileName), copyFile, miscStructPtr) != 0) {
                PRINT_SYS_ERROR(miscStructPtr->returnVal);
                goto cleanup;
            }

            /*Write backUpFileBuffer to backup file*/
            if (fwriteWErrCheck(backUpFileBuffer, sizeof(char), returnFileSize(dbStructPtr->dbFileName), backUpFile, miscStructPtr) != 0) {
                PRINT_SYS_ERROR(miscStructPtr->returnVal);
                goto cleanup;
            }

            /*Close both files*/
            if (fclose(copyFile) == EOF) {
                PRINT_FILE_ERROR(dbStructPtr->dbFileName, errno);
                goto cleanup;
            }
            if (fclose(backUpFile) == EOF) {
                PRINT_FILE_ERROR(dbStructPtr->backupFileName, errno);
                goto cleanup;
            }

            /*Cleanup*/
            free(backUpFileBuffer);
            backUpFileBuffer = NULL;
        }
    }

    return 0;

cleanup:
    free(backUpFileBuffer);
    backUpFileBuffer = NULL;
    return 1;
}
