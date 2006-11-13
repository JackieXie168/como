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
 *
 */

#include <string.h>
#include <sys/select.h>
#include <errno.h>

#include "como.h"

void
event_loop_init(event_loop_t * el)
{
    memset(el, 0, sizeof(event_loop_t));
    FD_ZERO(&el->fds);
}


/*
 * -- event_loop_add
 *
 * add a file descriptor to the interesting range;
 * return max_fd value or -1 if failed.
 */ 
int
event_loop_add(event_loop_t * el, int i)
{
    if (i < 0)
	return -1;

    FD_SET(i, &el->fds);
    el->max_fd = (i >= el->max_fd) ? i + 1 : el->max_fd;
    
    return el->max_fd;
}


/*
 * -- event_loop_del
 *
 * delete a file descriptor to the interesting range;
 * return max_fd value or -1 if failed.
 */ 
int
event_loop_del(event_loop_t * el, int i)
{
    if (i < 0) 
	return -1; 

    FD_CLR(i, &el->fds);
    if (i < el->max_fd - 1)
        return el->max_fd;

    /* we deleted the highest fd, so need to recompute the max */
    for (i = el->max_fd - 1; i >= 0; i--)
        if (FD_ISSET(i, &el->fds))
            break;
    el->max_fd = i + 1;

    return el->max_fd;
}



void
event_loop_set_timeout(event_loop_t * el, struct timeval * timeout)
{
    el->timeout = *timeout;
    el->timeoutptr = &el->timeout;
}


int
event_loop_select(event_loop_t * el, fd_set * ready)
{
    int n;

    *ready = el->fds;
    n = select(el->max_fd, ready, NULL, NULL, el->timeoutptr);
    if (n < 0 && errno != EINTR) {
	error("Failed on select(): %s\n", strerror(errno));
    }
    el->timeoutptr = NULL;
    
    return n;
}

