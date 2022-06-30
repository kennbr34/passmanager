/* sendwithclipboard.c - to send password to clipboard */

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

/*If compilation was configured with X11 libraries*/
#ifdef HAVE_LIBX11
int sendToClipboard(char *textToSend, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int passLength = strlen(textToSend);
    /*Use mmap to allocate passBuffer with shared memory so it can be properly sanitized in forked thread*/
    char *passBuffer = mmap(NULL, passLength, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    pid_t pid = getpid(), cid;

    cid = fork();
    if (cid == -1)
        PRINT_SYS_ERROR(errno);

    snprintf(passBuffer, passLength + 1, "%s", textToSend);

    if (getpid() != pid) {
        /*FIXME*/
        /*For some reason the timer method only works with the 'primary' selection*/
        /*The password would be cleared immediately regardless if the user pasted it*/
        /*Set selection to 'primary' instead*/
        if (conditionsStruct->selectionIsClipboard && miscStructPtr->clipboardClearTimeMiliSeconds <= 5000) {
            conditionsStruct->selectionIsClipboard = false;
            conditionsStruct->selectionIsPrimary = true;
        }
        sendWithXlib(passBuffer, passLength, miscStructPtr->clipboardClearTimeMiliSeconds, conditionsStruct);
        if (conditionsStruct->readingPass == true) {
            free(textToSend);
            textToSend = NULL;
        }
        return -1;
    }

    return 0;
}

int targetWinHandler(Display *xDisplay,
                     Window *targetWindow,
                     XEvent XAeventStruct,
                     Atom *windowProperty, Atom targetProperty, unsigned char *passToSend, unsigned long passLength)
{
    XEvent eventResponseStruct;
    static Atom targetsAtm;

    targetsAtm = XInternAtom(xDisplay, "TARGETS", False);

    /*Set the window and property that is being used*/
    *targetWindow = XAeventStruct.xselectionrequest.requestor;
    *windowProperty = XAeventStruct.xselectionrequest.property;

    if (XAeventStruct.xselectionrequest.target == targetsAtm) {
        Atom dataTypes[2] = {targetsAtm, targetProperty};

        /*Send pass with targets*/
        XChangeProperty(xDisplay,
                        *targetWindow,
                        *windowProperty,
                        XA_ATOM,
                        32, PropModeReplace, (unsigned char *)dataTypes,
                        (int)(sizeof(dataTypes) / sizeof(Atom)));
    } else {

        /*Send pass */
        XChangeProperty(xDisplay,
                        *targetWindow,
                        *windowProperty, targetProperty, 8, PropModeReplace, (unsigned char *)passToSend, (int)passLength);
    }

    /*Set values for the response event*/
    eventResponseStruct.xselection.property = *windowProperty;
    eventResponseStruct.xselection.type = SelectionNotify;
    eventResponseStruct.xselection.display = XAeventStruct.xselectionrequest.display;
    eventResponseStruct.xselection.requestor = *targetWindow;
    eventResponseStruct.xselection.selection = XAeventStruct.xselectionrequest.selection;
    eventResponseStruct.xselection.target = XAeventStruct.xselectionrequest.target;
    eventResponseStruct.xselection.time = XAeventStruct.xselectionrequest.time;

    /*Send the response event*/
    XSendEvent(xDisplay, XAeventStruct.xselectionrequest.requestor, 0, 0, &eventResponseStruct);
    XFlush(xDisplay);

    return 0;
}

int sendWithXlib(char *passToSend, int passLength, int clearTime, struct conditionBoolsStruct *conditionsStruct)
{

    Window rootWindow = 0;
    char *defaultDisplay = NULL;
    Display *xDisplay = XOpenDisplay(defaultDisplay);
    XEvent XAeventStruct;
    Atom selectionAtm = 0;
    if (conditionsStruct->selectionGiven == true && conditionsStruct->selectionIsClipboard == true)
        selectionAtm = XInternAtom(xDisplay, "CLIPBOARD", False);
    else if (conditionsStruct->selectionGiven == false || conditionsStruct->selectionIsPrimary == true)
        selectionAtm = XA_PRIMARY;
    Atom targetAtm = XA_STRING;
    int X11fileDescriptor; /*File descriptor on which XEvents appear*/
    fd_set inputFileDescriptors;
    struct timeval timeVariable;

    rootWindow = XCreateSimpleWindow(xDisplay, DefaultRootWindow(xDisplay), 0, 0, 1, 1, 0, 0, 0);
    XSetSelectionOwner(xDisplay, selectionAtm, rootWindow, CurrentTime);

    X11fileDescriptor = ConnectionNumber(xDisplay);

    /*At this point we are executing as the child process*/
    for (;;) {
        static Window targetWindow = 0;
        static Atom windowProperty = 0;

        XNextEvent(xDisplay, &XAeventStruct);

        targetWinHandler(xDisplay, &targetWindow, XAeventStruct, &windowProperty, targetAtm, (unsigned char *)passToSend, passLength);

        if (XAeventStruct.type == SelectionClear) {
            OPENSSL_cleanse(passToSend, sizeof(char) * passLength); /*Zero out password if selection was cleared and return out of loop*/
            return EXIT_SUCCESS;
        }

        /*Clear selection 'clearTime' seconds after it has been pasted*/
        if (!XPending(xDisplay)) {
            timeVariable.tv_sec = clearTime / 1000;
            timeVariable.tv_usec = (clearTime % 1000) * 1000;

            /*Build file descriptors*/
            FD_ZERO(&inputFileDescriptors);
            FD_SET(X11fileDescriptor, &inputFileDescriptors);
            if (!select(X11fileDescriptor + 1, &inputFileDescriptors, 0, 0, &timeVariable)) {
                OPENSSL_cleanse(passToSend, sizeof(char) * passLength);
                munmap(passToSend, passLength);
                XCloseDisplay(xDisplay);
                return EXIT_SUCCESS;
            }
        }
    }
}
#endif

/*If compilation was configured without X11 libraries*/
#ifndef HAVE_LIBX11
int sendToClipboard(char *textToSend, struct miscVar *miscStructPtr, struct conditionBoolsStruct *conditionsStruct)
{
    int passLength = strlen(textToSend);
    char xselCommand[27] = {0};
    char wipeCommand[27] = {0};
    if (conditionsStruct->selectionGiven == false || conditionsStruct->selectionIsPrimary == true) {
        strcpy(xselCommand, "xsel");
        strcpy(wipeCommand, "xsel -c");
    } else if (conditionsStruct->selectionGiven == true && conditionsStruct->selectionIsClipboard == true) {
        strcpy(xselCommand, "xsel -b");
        strcpy(wipeCommand, "xsel -b -c");
    }

    char passBuffer[passLength];
    memset(passBuffer, 0, passLength);

    FILE *xselFile = popen(xselCommand, "w");
    pid_t pid = 0;

    snprintf(passBuffer, passLength + 1, "%s", textToSend);

    if (xselFile == NULL) {
        PRINT_SYS_ERROR(errno);
        return -1;
    }

    if (fwriteWErrCheck(passBuffer, sizeof(char), passLength, xselFile, miscStructPtr) != 0) {
        PRINT_SYS_ERROR(miscStructPtr->returnVal);
        return -1;
    }

    if (pclose(xselFile) == -1) {
        PRINT_SYS_ERROR(errno);
        return 1;
    }

    OPENSSL_cleanse(passBuffer, passLength);
    OPENSSL_cleanse(textToSend, passLength);

    /*Going to fork off the application into the background, and wait 30 seconds to send zeroes to the xsel clipboard*/

    /*Stops the child process from exiting when the parent does*/
    if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        PRINT_SYS_ERROR(errno);
        return -1;
    }

    /*Fork off the parent process and check for error*/
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    /*If we got a good PID, then we can return the parent process to the calling function.*/
    else if (pid > 0) {
        /*Do not change from 0 here or the parent process's calling function won't print information about what was sent to clipboard*/
        return 0;
    }

    /*At this point we are executing as the child process*/
    /*Don't return 1 on error after this point*/

    struct timespec ts;

    ts.tv_sec = miscStructPtr->clipboardClearTimeMiliSeconds / 1000;
    ts.tv_nsec = (miscStructPtr->clipboardClearTimeMiliSeconds % 1000) * 1000000;

    nanosleep(&ts, &ts);

    system(wipeCommand);

    /*Leave this as 1 otherwise messages about what was sent to clipboard will be repeated*/
    /*The child process will return to calling function, and a conditional tests if this function returns 0*/
    /*When this child process's version of the function returns 1, the information will not be printed again*/
    /*Don't simply exit otherwise sensitive buffers in the rest of the child process's calling function will not be cleared/freed*/
    return 1;
}
#endif
