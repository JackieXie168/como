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

#include <sys/types.h>		/* fork */
#include <unistd.h>		/* fork */
#include <sys/types.h>          /* wait */
#include <sys/wait.h>           /* wait */
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <err.h>
#include <errno.h>

#include "como.h"
#include "comopriv.h"
#include "query.h"

void 
query_ondemand(UNUSED int fd, UNUSED qreq_t * req, UNUSED int node_id) 
{
    extern como_config_t *como_config;
    pid_t pid, p;
    int st;

    switch ((pid = fork())) {
        case -1:
            warn("could not fork como inline to attend query!\n");
            /* TODO return an error msg? */

        case 0:
            error("this is the child process, should run "
                    "como -i -D %s -L %s -t %s "
                    "-s como,http://localhost:%d/%s?format=como"
                    "%s \n",
                    como_config->db_path, como_config->libdir,
                    como_config->storage_path, como_config->query_port,
                    req->mdl, req->source);

        default:
            warn("como inline launched\n");
            break;
    }
    
    warn("waiting for pid %d\n", pid);
    do {
        p = waitpid(pid, &st, 0);
        warn("ret %d\n", p);
    } while (p < 0);

    sleep(5);
}
