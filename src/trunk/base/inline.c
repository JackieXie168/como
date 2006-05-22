/*
 * Copyright (c) 2006, Intel Corporation
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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     /* mkstemp */
#include <sys/wait.h>	/* wait3() */
#include <string.h>     /* bzero */
#include <errno.h>      /* errno */
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "ipc.h"

/* global state */
extern struct _como map;


/* 
 * -- inline_mainloop
 * 
 * Running in inline mode. 
 * 
 */
void
inline_mainloop(int accept_fd)
{
    module_t * mdl;
    fd_set valid_fds;
    int max_fd;
    
    logmsg(V_LOGWARN, "inline mode with %s\n", map.inline_mdl->name);
    
    FD_ZERO(&valid_fds);
    max_fd = 0;
    max_fd = add_fd(accept_fd, &valid_fds, max_fd);
    
    /* initialize all modules */ 
    mdl = map.inline_mdl;
    assert(mdl->status == MDL_LOADING);
    
    if (activate_module(mdl, map.libdir)) {
	logmsg(LOGWARN, "cannot start module %s\n", mdl->name);
	remove_module(&map, mdl);
	exit(1);
    }
    
    if (init_module(mdl)) {
	logmsg(LOGWARN, "cannot initialize module %s\n", mdl->name);
	remove_module(&map, mdl);
	exit(1);
    }
    
    map.stats->modules_active++;
    
    for (;;) {
	fd_set r;
    	int i, n_ready;
    	
	r = valid_fds;
	n_ready = select(max_fd, &r, NULL, NULL, NULL);
	for (i = 0; n_ready > 0 && i < max_fd; i++) {
	    int ipcr; 

	    if (!FD_ISSET(i, &r))
		continue;
	    
	    n_ready--;
	    if (i == accept_fd) {
		int x;
		x = accept(i, NULL, NULL);
		if (x < 0) {
		    logmsg(LOGWARN, "accept fd[%d] got %d (%s)\n",
			   i, x, strerror(errno));
		} else {
		    max_fd = add_fd(x, &valid_fds, max_fd);
		}
		continue;
	    }
	    ipcr = ipc_handle(i);
	    switch (ipcr) {
	    case IPC_ERR:
		/* an error. close the socket */
		logmsg(LOGWARN, "error on IPC handle from %d\n", i);
	    case IPC_EOF:
		close(i);
		max_fd = del_fd(i, &valid_fds, max_fd);
		break;
	    }
	}
    }
}

