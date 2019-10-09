/*
 *  
 * 
 *  xclip.c - command line interface to X server selections 
 *  Copyright (C) 2001 Kim Saunders
 *  Copyright (C) 2007-2008 Peter Åstrand
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#define XCLIB_XCIN_NONE 0
#define XCLIB_XCIN_INCR 2
#define XA_PRIMARY 1
#define XA_STRING 31
#define XA_ATOM 4

void errmalloc(void)
{
    fprintf(stderr, "Error: Could not allocate memory.\n");
    exit(EXIT_FAILURE);
}

struct requestor
{
    Window cwin;
    Atom pty;
    unsigned int context;
    struct requestor *next;
};

static struct requestor *requestors;

static struct requestor *get_requestor(Window win)
{
    struct requestor *requestor;

    if (requestors)
    {
        for (requestor = requestors; requestor != NULL; requestor = requestor->next)
        {
            if (requestor->cwin == win)
            {
                return requestor;
            }
        }
    }

    requestor = (struct requestor *)calloc(1, sizeof(struct requestor));
    if (!requestor)
    {
        errmalloc();
    }
    else
    {
        requestor->context = XCLIB_XCIN_NONE;
    }

    if (!requestors)
    {
        requestors = requestor;
    }
    else
    {
        requestor->next = requestors;
        requestors = requestor;
    }

    return requestor;
}

static void del_requestor(struct requestor *requestor)
{
    struct requestor *reqitr;

    if (!requestor)
    {
        return;
    }

    if (requestors == requestor)
    {
        requestors = requestors->next;
    }
    else
    {
        for (reqitr = requestors; reqitr != NULL; reqitr = reqitr->next)
        {
            if (reqitr->next == requestor)
            {
                reqitr->next = reqitr->next->next;
                break;
            }
        }
    }

    free(requestor);
}

int xcin(Display *dpy,
         Window *win,
         XEvent evt,
         Atom *pty, Atom target, unsigned char *txt, unsigned long len)
{
    XEvent res;              /* response to event */

	/* set the window and property that is being used */
	*win = evt.xselectionrequest.requestor;
	*pty = evt.xselectionrequest.property;
	
	/* send data  */
	XChangeProperty(dpy,
					*win,
					*pty, target, 8, PropModeReplace, (unsigned char *)txt, (int)len);

	/* set values for the response event */
	res.xselection.property = *pty;
	res.xselection.type = SelectionNotify;
	res.xselection.display = evt.xselectionrequest.display;
	res.xselection.requestor = *win;
	res.xselection.selection = evt.xselectionrequest.selection;
	res.xselection.target = evt.xselectionrequest.target;
	res.xselection.time = evt.xselectionrequest.time;

	/* send the response event */
	XSendEvent(dpy, evt.xselectionrequest.requestor, 0, 0, &res);
	XFlush(dpy);

    return 1;
}

int sendWithXclip(char *textToSend)
{

    Window win;
    Display *dpy;
    pid_t pid, sid;
    XEvent evt;
    Atom sseln = XA_PRIMARY;
    Atom target = XA_STRING;

    char *displayString = NULL;

    dpy = XOpenDisplay(displayString);
    win = XCreateSimpleWindow(dpy, DefaultRootWindow(dpy), 0, 0, 1, 1, 0, 0, 0);
    XSelectInput(dpy, win, PropertyChangeMask);
    XSetSelectionOwner(dpy, sseln, win, CurrentTime);
    
    /*Stops the parent process from waiting for child process to complete*/
    signal(SIGCHLD, SIG_IGN);

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(1);
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        return 0;
    }

    /* At this point we are executing as the child process */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(1);
    }

    struct requestor *requestor;
    int finished;

    XNextEvent(dpy, &evt);

	requestor = get_requestor(evt.xselectionrequest.requestor);
    
    finished = xcin(dpy, &(requestor->cwin), evt, &(requestor->pty), target, (unsigned char *)textToSend, strlen(textToSend));
    
    if (finished)
    {
        del_requestor(requestor);
    }

    XCloseDisplay(dpy);
        
    exit(EXIT_SUCCESS);
}
