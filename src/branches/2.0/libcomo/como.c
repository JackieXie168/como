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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>		/* strlen strcpy strncat memset */

/* Required for symlink deletion */
#include <errno.h>
#include <signal.h>	// signal... 
#include <unistd.h>

#include "como.h"
#include "comopriv.h"
#include "storage.h"	// mainloop
#include "ipc.h"	// ipc_listen()

/*
 * the "map" is the root of the data. it contains all the
 * config parameters that are set before spawning the processes.
 * it is needed by all processes that will use their local copy.
 */
struct _como map;


/*
 * Data structure containing all the configuration parameters
 * loaded from the default config file(s) and the command line.
 * This data structure will contain the information about all the
 * modules and classifiers as well.
 */



ipc_peer_full_t *COMO_SU;
ipc_peer_full_t *COMO_CA;
ipc_peer_full_t *COMO_EX;
ipc_peer_full_t *COMO_ST;
ipc_peer_full_t *COMO_QU;


void
como_init(int argc, char ** argv)
{
#if defined(linux) || defined(__APPLE__)
    /* linux/Mac OS X does not support setproctitle. we have our own. */
    setproctitle_init(argc, argv);
#endif

    COMO_SU = ipc_peer_new(COMO_SU_CLASS, "su", "SUPERVISOR");
    COMO_CA = ipc_peer_new(COMO_CA_CLASS, "ca", "CAPTURE");
    COMO_EX = ipc_peer_new(COMO_EX_CLASS, "ex", "EXPORT");
    COMO_ST = ipc_peer_new(COMO_EX_CLASS, "st", "STORAGE");
    COMO_QU = ipc_peer_new(COMO_QU_CLASS, "qu", "QUERY");
}

#if 0


#endif
