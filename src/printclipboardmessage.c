/* printclipboardmessage.c - prints messages regarding how password was sent and managed by clipboard */

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

/* This function will give different instructions
 * and notificaitons to the user regarding how the password
 * was sent to the clipboard based on user selections and operation mode
 */
void printClipboardMessage(int entriesMatched, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    /*FIXME*/
    /*For some reason the timer method only works with the 'primary' selection*/
    /*The password would be cleared immediately regardless if the user pasted it*/
    /*Set selection to 'primary' instead and inform user*/
    if (conditionsStruct->selectionIsClipboard && miscStructPtr->clipboardClearTimeMiliSeconds <= 5000) {
        conditionsStruct->selectionIsClipboard = false;
        conditionsStruct->selectionIsPrimary = true;
        fprintf(stderr, "Using 'primary' selection instead because password will be cleared before being able to paste if using 'clipboard'\n");
    }

    if (conditionsStruct->addingPass == true) {
        fprintf(stderr, "New password sent to clipboard.");
        if (conditionsStruct->selectionGiven == false || conditionsStruct->selectionIsPrimary == true)
            fprintf(stderr, "\nPaste with middle-click\n");
        else if (conditionsStruct->selectionIsClipboard == true)
            fprintf(stderr, "\nPaste with Ctrl+V or Right-Click->Paste\n");
    } else if (conditionsStruct->readingPass == true) {
        if (entriesMatched == 1) {
            fprintf(stderr, "\nSent the entry's password to clipboard.");
        } else {
            fprintf(stderr, "\nSent the first matched entry's password to clipboard. (Note: There may be more entries that matched your search string)");
        }
        if (conditionsStruct->selectionGiven == false || conditionsStruct->selectionIsPrimary == true)
            fprintf(stderr, "\nPaste with middle-click\n");
        else if (conditionsStruct->selectionIsClipboard == true)
            fprintf(stderr, "\nPaste with Ctrl+V or Right-Click->Paste\n");
    } else if (conditionsStruct->updatingEntry == true) {
        fprintf(stderr, "\nSent new password to clipboard.");
        if (entriesMatched > 1)
            fprintf(stderr, " (Note: Multiple entries matched, only updated and sent fist entry's password to clipboard)");
        if (conditionsStruct->selectionGiven == false || conditionsStruct->selectionIsPrimary == true)
            fprintf(stderr, "\nPaste with middle-click\n");
        else if (conditionsStruct->selectionIsClipboard == true)
            fprintf(stderr, "\nPaste with Ctrl+V or Right-Click->Paste\n");
    }
#ifndef HAVE_LIBX11
    fprintf(stderr, "%.2f seconds before password is cleared\n", (float)miscStructPtr->clipboardClearTimeMiliSeconds / 1000);
#elif HAVE_LIBX11
    if (conditionsStruct->selectionIsClipboard == true)
        fprintf(stderr, "%.2f seconds before password is cleared\n", (float)miscStructPtr->clipboardClearTimeMiliSeconds / 1000);
    else {
        if (miscStructPtr->clipboardClearTimeMiliSeconds != 0)
            fprintf(stderr, "Password will be cleared %.2f seconds after it is pasted\n", (float)miscStructPtr->clipboardClearTimeMiliSeconds / 1000);
        else
            fprintf(stderr, "Password will be cleared immediately after it is pasted\n");
    }
#endif
}
