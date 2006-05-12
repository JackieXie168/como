/*
 * Copyright (c) 2004 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: util-process.c,v 1.2 2006/05/07 22:46:19 iannak1 Exp $
 *
 */
#include <sys/wait.h>	/* wait3() */
#include <err.h>	/* errx */
#include <errno.h>      /* errno */
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "ipc.h"

/* global state */
extern como_t map; 


/* 
 * This file contains utilities to manage the process tags. 
 * Each process tag is a 32 bit value made of three components: 
 * 
 *   . parent name, 8 bits; 
 *   . child name, 8 bits; 
 *   . process id, 16 bits; 
 * 
 * The parent name and child name are chosen among five predefined 
 * names (SUPERVISOR, CAPTURE, EXPORT, STORAGE, QUERY) while the 
 * process id is used to make the tag unique. 
 * 
 * We define a set of functions to build tags, process tags and 
 * convert tags to human readable strings. 
 */ 

/* 
 * aliases for process class names 
 */ 
static struct {
    char * shortname;
    char * fullname; 
} procalias[] = { 
    {"??", "NONE"}, 
    {"su", "SUPERVISOR"}, 
    {"ca", "CAPTURE"}, 
    {"ex", "EXPORT"},
    {"st", "STORAGE"}, 
    {"qu", "QUERY"},
};


#define GETPROCPARENT(x) 	(((x) >> 24) & 0xff) 
#define GETPROCCHILD(x) 	(((x) >> 16) & 0xff) 
#define GETPROCID(x)		((x) & 0xffff)
#define GETPROC(x)		GETPROCCHILD(x)

#define SETPROC(x, y, a) 	(((x) << 8) | (y) | (a)) 
#define SETPROCSIBLING(x, a) 	(((x) & 0xff000000) | (a) | GETPROCID(x))
#define SETPROCCHILD(x, a, n) 	((GETPROC(x) << 24) | (a) | (n))

/* 
 * -- getprocname 
 * 
 * this function returns a short name for a process made of 
 * parent-id-child (e.g., qu-1-ca). if id and child are equal 
 * to zero they are not shown. 
 *
 */
char * 
getprocname(procname_t who)
{
    static char name[256]; 
    uint p, c, x; 

    p = GETPROCPARENT(who); 
    c = GETPROCCHILD(who); 
    x = GETPROCID(who); 
    if (p == 0) 
	sprintf(name, "%s", procalias[c].shortname);
    else 
	sprintf(name, "%s-%d-%s", 
		procalias[p].shortname, x, procalias[c].shortname); 

    return name;
}


/* 
 * -- getprocfullname
 * 
 * return the full name instead of the short one. same as 
 * getprocname for the rest.  
 *
 */ 
char * 
getprocfullname(procname_t who)
{
    static char name[256]; 
    int p, c, x; 

    p = GETPROCPARENT(who); 
    c = GETPROCCHILD(who); 
    x = GETPROCID(who); 
    if (p == 0) 
	sprintf(name, "%s", procalias[c].fullname);
    else 
	sprintf(name, "%s-%d-%s", 
		procalias[p].fullname, x, procalias[c].fullname); 

    return name;
}


/* 
 * -- sibling
 * 
 * returns the name of the sibling process by just 
 * using its class. 
 */
procname_t 
sibling(procname_t who)
{
    return SETPROCSIBLING(map.whoami, who); 
}


/* 
 * -- child
 * 
 * it reconstruct the tag of a child process
 */
procname_t 
child(procname_t who, int id)
{
    return SETPROCCHILD(map.whoami, who, id); 
}

/* 
 * -- buildtag
 * 
 * build a tag from all its components 
 */
procname_t 
buildtag(procname_t parent, procname_t who, int id)
{
    return SETPROC(parent, who, id); 
}

/* 
 * -- getprocclass
 * 
 * it extracts the process class of a child process. 
 * it returns 0 if the tag does not map any known processes. 
 */
procname_t 
getprocclass(procname_t who)
{
    procname_t x; 

    x = (GETPROCCHILD(who) << 16); 
    return (x >= SUPERVISOR && x <= QUERY)? x : 0;
}

/* 
 * -- getprocid
 * 
 * it extracts the process id. 
 */
int 
getprocid(procname_t who)
{
    return GETPROCID(who); 
}


/* 
 * -- isvalidproc
 * 
 * it returns 0 if the tag does not map any known processes. 
 */
int 
isvalidproc(procname_t who)
{
    procname_t x = (GETPROCCHILD(who) << 16); 
    return (x >= SUPERVISOR && x <= QUERY); 
}


/*
 * -- start_child 
 * 
 * fork a child with the given function and process name.
 * If 'procname' is NULL then don't fork, as this is the supervisor.
 * The last argument is an optional fd to be passed to the program.
 */
pid_t
start_child(procname_t who, int mem_type, 
	    mainloop_fn mainloop, int in_fd,
	    child_info_t *children, int children_count)
{
    pid_t pid;
    int i;

    /* find a slot for the child */
    for (i = 0; i < children_count; i++)
	if (!isvalidproc(children[i].who))
	    break;
    if (i == children_count) 
	errx(EXIT_FAILURE, 
	     "--- cannot create child %s, no more slots\n", 
	     getprocfullname(who));

    children[i].who = who;

    /* ok, fork a regular process and return pid to the caller. */
    pid = fork();
    if (pid == 0) {	/* child */
	char *buf;
	int out_fd, idx;
	
	signal(SIGHUP, SIG_IGN);        /* ignore SIGHUP */

	/* XXX TODO: close unneeded sockets */
	// fclose(stdout); // XXX
	// fclose(stderr); // XXX

	/*
	 * every new process has to set its name, specify the type of memory 
	 * the modules will be able to allocate and use, and change the 
	 * process name accordingly.  
	 */
	map.parent = map.whoami;
	map.whoami = who;
	map.mem_type = mem_type;

	/*
	 * remove all modules in the map (it will
	 * receive the proper information from SUPERVISOR)
	 *
	 * XXX this is not that great but no other workaround comes
	 *     to mind. the problem is when an IPC_MODULE_ADD message
	 *     comes we don't want to waste time figuring out if we
	 *     already have that module somewhere or not. And those
	 *     messages may come when we are doing something important,
	 *     while this is done at the very beginning.
	 *
	 */
	for (idx = 0; idx < map.module_max; idx++)
	    if (map.modules[idx].status != MDL_UNUSED) 
		remove_module(&map, &map.modules[idx]);
	assert(map.module_used == 0); 
	assert(map.module_last == -1);

	/* connect to SUPERVISOR */
        out_fd = ipc_connect(map.parent);
        assert(out_fd > 0);

	asprintf(&buf, "%s", getprocfullname(who));
	setproctitle(buf);
	free(buf);

	logmsg(V_LOGWARN, "starting process %-20s pid %d\n", 
	       getprocfullname(who), getpid()); 

	mainloop(in_fd, out_fd);
	exit(0);
    }
    children[i].who = who;
    children[i].pid = pid;
    
    return pid;
}


/* 
 * -- handle_children
 * 
 * Waits for children that have terminate and reports on the 
 * exit status. 
 */
void
handle_children(child_info_t *children, int children_count)
{
    int j;
    procname_t who = 0;
    pid_t pid;
    int statbuf;

    pid = wait3(&statbuf, WNOHANG, NULL);
    if (pid <= 0)
	return;
    for (j = 0; j < children_count; j++) {
	if (children[j].pid == pid) {
	    who = children[j].who;
	    break;
	}
    }

//    assert(j < children_count);
    if (j == children_count)
	return;

    if (WIFEXITED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (status: %d)\n",
	    pid, getprocfullname(who), WEXITSTATUS(statbuf)); 
    else if (WIFSIGNALED(statbuf)) 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (signal: %d)\n",
	    pid, getprocfullname(who), WTERMSIG(statbuf));
    else 
	logmsg(LOGWARN, "WARNING!! process %d (%s) terminated (unknown!!)\n", 
	    pid, getprocfullname(who)); 
	    
    children[j].pid = -1;
    children[j].who = 0;
}

