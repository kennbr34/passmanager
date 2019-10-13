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

#define DO_TARGET_METHOD 1

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
	
	if (XAeventStruct.xselectionrequest.target == targetsAtm) {
	    return DO_TARGET_METHOD;
	}
	
	passSentCount++;

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
		    int targetWinHandleResult;
	
		    XNextEvent(xDisplay, &XAeventStruct);
	
		    targetWinHandleResult = targetWinHandler(xDisplay, &targetWindow, XAeventStruct, &windowProperty, targetAtm, (unsigned char *)passToSend, passLength);
				
			if (XAeventStruct.type == SelectionClear) {
				OPENSSL_cleanse(passToSend, sizeof(char) * passLength); /*Zero out password if selection was cleared and return out of loop*/
				return EXIT_SUCCESS;
			}
			
			if(targetWinHandleResult == DO_TARGET_METHOD) {
				if(passSentCount > passSendLimit)
					break;
			}
			else {
				if(passSentCount >= passSendLimit)
					break;
			}
		}

	OPENSSL_cleanse(passToSend, sizeof(char) * passLength);

    XCloseDisplay(xDisplay);

    exit(EXIT_SUCCESS);
}
