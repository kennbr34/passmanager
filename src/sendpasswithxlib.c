/* Copyright 2019 Kenneth Brown */

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

#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

/*These are defined here so including and linking Xmu.h/Atoms.h is not needed*/
/*If problems arise just comment out and include and link Xmu/Atoms.h*/
#define XA_PRIMARY 1 /*Paste with middle click, and erase with selection*/
#define XA_STRING 31
#define XA_ATOM 4

int passSentCount;
int passSendLimit = 1;


int targetWinHandler(Display *xDisplay,
         Window *targetWindow,
         XEvent XAeventStruct,
         Atom *windowProperty, Atom targetProperty, unsigned char *passToSend, unsigned long passLength)
{
    XEvent eventResponseStruct;
    static Atom targetsAtm;

	targetsAtm = XInternAtom(xDisplay, "TARGETS", False);

	/* Set the window and property that is being used */
	*targetWindow = XAeventStruct.xselectionrequest.requestor;
	*windowProperty = XAeventStruct.xselectionrequest.property;
	
	if (XAeventStruct.xselectionrequest.target == targetsAtm) {
	    Atom dataTypes[2] = { targetsAtm, targetProperty };

	    /* Send pass with targets */
	    XChangeProperty(xDisplay,
			    *targetWindow,
			    *windowProperty,
			    XA_ATOM,
			    32, PropModeReplace, (unsigned char *) dataTypes,
			    (int) (sizeof(dataTypes) / sizeof(Atom))
		);
	}
	else {
	
		/* Send pass  */
		XChangeProperty(xDisplay,
						*targetWindow,
						*windowProperty, targetProperty, 8, PropModeReplace, (unsigned char *)passToSend, (int)passLength);
        /*Only increment the passSentCount once we get here because some windows will use the targets method first*/
        passSentCount++;
	}

	/* Set values for the response event */
	eventResponseStruct.xselection.property = *windowProperty;
	eventResponseStruct.xselection.type = SelectionNotify;
	eventResponseStruct.xselection.display = XAeventStruct.xselectionrequest.display;
	eventResponseStruct.xselection.requestor = *targetWindow;
	eventResponseStruct.xselection.selection = XAeventStruct.xselectionrequest.selection;
	eventResponseStruct.xselection.target = XAeventStruct.xselectionrequest.target;
	eventResponseStruct.xselection.time = XAeventStruct.xselectionrequest.time;

	/* Send the response event */
	XSendEvent(xDisplay, XAeventStruct.xselectionrequest.requestor, 0, 0, &eventResponseStruct);
	XFlush(xDisplay);

    return 0;
}

int sendWithXlib(char *passToSend, int passLength)
{

    Window rootWindow;
    Display *xDisplay;
    XEvent XAeventStruct;
    Atom selectionAtm = XA_PRIMARY;
    Atom targetAtm = XA_STRING;
    pid_t pid;

    char *defaultDisplay = NULL;

    xDisplay = XOpenDisplay(defaultDisplay);
    rootWindow = XCreateSimpleWindow(xDisplay, DefaultRootWindow(xDisplay), 0, 0, 1, 1, 0, 0, 0);
    XSetSelectionOwner(xDisplay, selectionAtm, rootWindow, CurrentTime);
    
    pid = fork();
	/* Exit the parent process; */
	if (pid) {
		memset(passToSend,0,passLength); /*Zero out memory where password was stored*/
	    exit(EXIT_SUCCESS);
    }

    /* At this point we are executing as the child process */
    for(;;)
    {
        static Window targetWindow;
        static Atom windowProperty;

        XNextEvent(xDisplay, &XAeventStruct);
            
        targetWinHandler(xDisplay, &targetWindow, XAeventStruct, &windowProperty, targetAtm, (unsigned char *)passToSend, passLength);
            
        if (XAeventStruct.type == SelectionClear) {
            OPENSSL_cleanse(passToSend, sizeof(char) * passLength); /*Zero out password if selection was cleared and return out of loop*/
            return EXIT_SUCCESS;
        }			

        if(passSentCount == passSendLimit)
            break;
    }

	OPENSSL_cleanse(passToSend, sizeof(char) * passLength);

    XCloseDisplay(xDisplay);

    exit(EXIT_SUCCESS);
}
