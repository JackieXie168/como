/*
 * Copyright (c) 2004-2006, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 * * Neither the name of Intel Corporation nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include <err.h>	/* errx */
#include <errno.h>      /* errno */
#include <assert.h>
#include <unistd.h> 	/* fork */
#include <sys/types.h>  /* fork */
#include <sys/wait.h>	/* wait3() */

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
} s_procalias[] = { 
    {"??", "NONE"}, 
    {"su", "SUPERVISOR"}, 
    {"ca", "CAPTURE"}, 
    {"ex", "EXPORT"},
    {"st", "STORAGE"}, 
    {"qu", "QUERY"},
};


/* 
 * children process information 
 * (both children of SUPERVISOR and QUERY for 
 * on-demand queries)
 */ 
#define MAX_CHILDREN		256
static struct { 
    procname_t who;
    pid_t pid;
} s_child_info[MAX_CHILDREN];

static int s_children = 0; 


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
	sprintf(name, "%s", s_procalias[c].shortname);
    else 
	sprintf(name, "%s-%d-%s", 
		s_procalias[p].shortname, x, s_procalias[c].shortname); 

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
	sprintf(name, "%s", s_procalias[c].fullname);
    else 
	sprintf(name, "%s-%d-%s", 
		s_procalias[p].fullname, x, s_procalias[c].fullname); 

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
start_child(procname_t who, int mem_type, mainloop_fn mainloop, 
	int in_fd, int id)
{
    pid_t pid;
    int i;

    if (s_children == 0) { 
	/* initialize the s_child_info array */ 
	bzero(s_child_info, sizeof(s_child_info)); 
    } 

    /* find a slot for the child */
    for (i = 0; i < MAX_CHILDREN; i++)
	if (!isvalidproc(s_child_info[i].who))
	    break;
    if (i == MAX_CHILDREN) { 
	logmsg(LOGWARN, "cannot create child %s, no more slots\n", 
	     getprocfullname(who));
	return -1; 
    } 

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
	 * the modules with status MDL_ACTIVE_REPLAY are not removed
	 * because they can be used in CAPTURE to replay records
	 * from inside sniffer-ondemand which require the module to
	 * be available when sniffer_start is called
	 *
	 * XXX this is not that great but no other workaround comes
	 *     to mind. the problem is when an IPC_MODULE_ADD message
	 *     comes we don't want to waste time figuring out if we
	 *     already have that module somewhere or not. And those
	 *     messages may come when we are doing something important,
	 *     while this is done at the very beginning.
	 *
	 */
	for (idx = 0; idx < map.module_max; idx++) {
	    if (map.modules[idx].status != MDL_UNUSED &&
		map.modules[idx].status != MDL_ACTIVE_REPLAY) {
		remove_module(&map, &map.modules[idx]);
	    }
	}

	/* connect to SUPERVISOR */
        out_fd = ipc_connect(map.parent);
        assert(out_fd > 0);

	asprintf(&buf, "%s", getprocfullname(who));
	setproctitle(buf);
	free(buf);

	logmsg(V_LOGWARN, "starting process %-20s pid %d\n", 
	       getprocfullname(who), getpid()); 

	mainloop(in_fd, out_fd, id);
	exit(0);
    }

    s_child_info[i].who = who;
    s_child_info[i].pid = pid;
    s_children++;
    
    return pid;
}


/* 
 * -- handle_children
 * 
 * Waits for children that have terminate and reports on the 
 * exit status with logmsg and returning 1 if the process didn't
 * terminate with an EXIT_SUCCESS and 0 otherwise. 
 */
int
handle_children()
{
    int j;
    procname_t who = 0;
    pid_t pid;
    int statbuf;

    pid = wait3(&statbuf, WNOHANG, NULL);
    if (pid <= 0) {
	return 0;
    } 

    for (j = 0; j < s_children; j++) {
	if (s_child_info[j].pid == pid) {
	    who = s_child_info[j].who;
	    break;
	}
    }

    if (j == s_children) {
	/* don't bother about unknown children */
	return 0;
    }

    s_child_info[j].pid = 0;
    s_child_info[j].who = 0;

    if (WIFEXITED(statbuf)) {
	if (WEXITSTATUS(statbuf) == EXIT_SUCCESS) { 
	    logmsg(V_LOGWARN, 
		   "%s (pid %d) completed successfully\n", 
		   getprocfullname(who), pid); 
	    return 0; 
	} else { 
	    logmsg(V_LOGWARN, 
		   "WARNING!! %s (pid %d) terminated (status: %d)\n",
	           getprocfullname(who), pid, WEXITSTATUS(statbuf)); 
	    return 1; 
	} 
    } 

    if (WIFSIGNALED(statbuf)) {
	logmsg(LOGWARN, 
	       "WARNING!! %s (pid %d) terminated (signal: %d)\n",
	       getprocfullname(who), pid, WTERMSIG(statbuf));
	return 1; 
    } 

    /* this would really be weird if it happened... */
    logmsg(LOGWARN, 
           "WEIRD WARNING!! %s (pid %d) terminated but nobody knows why!?!?\n",
	   getprocfullname(who), pid); 
    return 1; 
}

