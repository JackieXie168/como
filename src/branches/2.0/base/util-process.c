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

/* 
 * children process information 
 * (both children of SUPERVISOR and QUERY for 
 * on-demand queries)
 */ 
#define MAX_CHILDREN		256
static struct { 
    ipc_peer_full_t *who;
    pid_t pid;
} s_child_info[MAX_CHILDREN];

static int s_children = 0; 


/*
 * -- start_child 
 * 
 * fork a child with the given function and process name.
 * If 'procname' is NULL then don't fork, as this is the supervisor.
 * The last argument is an optional fd to be passed to the program.
 */
pid_t
start_child(ipc_peer_full_t * child, mainloop_fn mainloop,
	    memmap_t * shmemmap, int client_fd, como_node_t * node)
{
    pid_t pid;
    int i;
    ipc_peer_t * who = (ipc_peer_t *) child;

    /* find a slot for the child */
    for (i = 0; i < MAX_CHILDREN; i++) {
	if (s_child_info[i].who == NULL)
	    break;
    }
    if (i == MAX_CHILDREN) { 
	warn("cannot create child, no more slots\n");
	return -1; 
    } 

    /* ok, fork a regular process and return pid to the caller. */
    pid = fork();
    if (pid == 0) {	/* child */
	int supervisor_fd;
	
#ifdef ENABLE_PROFILING
	enable_profiling();
#endif
	//DEBUGGER_WAIT_ATTACH(child);
	signal(SIGHUP, SIG_IGN);        /* ignore SIGHUP */

	/* initialize the s_child_info array */ 
	bzero(s_child_info, sizeof(s_child_info)); 

	/* XXX TODO: close unneeded sockets */
	// fclose(stdout); // XXX
	// fclose(stderr); // XXX

	ipc_finish(FALSE);
	ipc_init(child, NULL, NULL);
	
	/* connect to SUPERVISOR */
        supervisor_fd = ipc_connect(COMO_SU);
        assert(supervisor_fd != -1);

	setproctitle("%s", ipc_peer_get_name(who));

	notice("starting process %s pid %d\n",
	       ipc_peer_get_name(who), getpid());

	mainloop(child, (ipc_peer_t *) COMO_SU, shmemmap, client_fd, node);
	exit(0);
    }

    s_child_info[i].who = child;
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
    ipc_peer_t * who = NULL;
    pid_t pid;
    int statbuf;

    pid = wait3(&statbuf, WNOHANG, NULL);
    if (pid <= 0) {
	return 0;
    } 

    for (j = 0; j < s_children; j++) {
	if (s_child_info[j].pid == pid) {
	    who = (ipc_peer_t *) s_child_info[j].who;
	    break;
	}
    }

    if (j == s_children) {
	/* don't bother about unknown children */
	return 0;
    }
    
    s_child_info[j].pid = 0;
    s_child_info[j].who = NULL;

    if (j == s_children - 1) {
	/* recompute s_children */
	int i;
	for (i = j - 1; i >=0; i--) {
	    if (s_child_info[i].who != NULL)
		break;
	}
	s_children = i + 1;
    }


    if (WIFEXITED(statbuf)) {
	if (WEXITSTATUS(statbuf) == EXIT_SUCCESS) { 
	    notice("%s (pid %d) completed successfully\n",
		   ipc_peer_get_name(who), pid);
	    return 0; 
	} else { 
	    warn("%s (pid %d) terminated (status: %d)\n",
	         ipc_peer_get_name(who), pid, WEXITSTATUS(statbuf));
	    return 1; 
	} 
    } 

    if (WIFSIGNALED(statbuf)) {
	warn("%s (pid %d) terminated (signal: %d)\n",
	     ipc_peer_get_name(who), pid, WTERMSIG(statbuf));
	return 1; 
    } 

    /* this would really be weird if it happened... */
    warn("%s (pid %d) terminated for unknown reason\n",
	 ipc_peer_get_name(who), pid);
    return 1; 
}


pid_t
spawn_child(ipc_peer_full_t * child, const char * path, ...)
{
    pid_t pid;
    va_list va;
    int argc = 1;
    const char *arg;
    int i;
    
    va_start(va, path);
    arg = va_arg(va, const char *);
    while (arg != NULL) {
        arg = va_arg(va, const char *);
	argc++;
    }
    va_end(va);
    
    pid = fork();
    if (pid == -1) {
	warn("fork() failed: %s\n", strerror(errno));
	return -1;
    }
    if (pid == 0) {
	/* child process */
	char * argv[argc + 1];

        argv[0] = (char *)path;
	i = 1;
	va_start(va, path);
	while (i < argc) {
	    argv[i] = va_arg(va, char *);
	    i++;
	}
	va_end(va);
	argv[i] = NULL;
	
	i = execv(path, argv);
	assert(i == -1);
	error("Can't execute %s: %s\n", path, strerror(errno));
    }

    i = s_children;
    s_child_info[i].who = child;
    s_child_info[i].pid = pid;
    s_children++;

    return pid;
}


