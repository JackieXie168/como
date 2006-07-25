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
 * -- main
 *
 * set up the data structures. basically open the config file,
 * parse the options and dynamically link in the modules. it
 * spawns the CAPTURE, EXPORT, QUERY and STORAGE processes and 
 * then sits there (SUPERVISOR) monitoring the other processes.
 *
 */
int
main(int argc, char *argv[])
{
    pid_t pid;
    int supervisor_fd, capture_fd, storage_fd;

#ifdef linux
    /* linux does not support setproctitle. we have our own. */
    setproctitle_init(argc, argv);
#endif

    /* set default values */
    init_map(&map); 

    /* write welcome message */ 
    logmsg(LOGUI, "----------------------------------------------------\n");
    logmsg(LOGUI, "  CoMo v%s (built %s %s)\n",
			COMO_VERSION, __DATE__, __TIME__ ); 
    logmsg(LOGUI, "  Copyright (c) 2004-2005, Intel Corporation\n"); 
    logmsg(LOGUI, "  All rights reserved.\n"); 
    logmsg(LOGUI, "----------------------------------------------------\n");
    logmsg(V_LOGUI, "... workdir %s\n", map.workdir);

    /*
     * parse command line and configuration files
     */
    map.ac = argc;              /* save argc and argv for later */
    map.av = argv; 
    configure(&map, argc, argv);

    logmsg(V_LOGUI, "log level: %s\n", loglevel_name(map.logflags)); 

    /*
     * Initialize the shared memory region.
     * All processes will be able to see it.
     */
    memory_init(map.mem_size);

    /* 
     * before forking processes, create a data structure in shared 
     * memory to allow CAPTURE, EXPORT, STORAGE, etc to share some 
     * statistics with SUPERVISOR. 
     * We do not have any locking mechanisms on the counters. 
     * They are written by one process and read by SUPERVISOR. They 
     * do not need to be 100% reliable. 
     */
    map.stats = mem_calloc(1, sizeof(stats_t)); 
    gettimeofday(&map.stats->start, NULL); 
    map.stats->first_ts = ~0;

    /* prepare the SUPERVISOR. STORAGE and CAPTURE sockets */
    supervisor_fd = ipc_listen(SUPERVISOR); 
    storage_fd = ipc_listen(STORAGE); 
    capture_fd = ipc_listen(CAPTURE); 

    /* 
     * start the processes. Note that the order is important given 
     * that the data flow is from CAPTURE to EXPORT to STORAGE we 
     * want to start the processes (and the relevant IPC calls) in 
     * the reverse order. 
     */

    /* start the STORAGE process */
    pid = start_child(STORAGE,COMO_PRIVATE_MEM,storage_mainloop,storage_fd,0);

    /* start the EXPORT process */
    pid = start_child(EXPORT, COMO_PRIVATE_MEM, export_mainloop, -1, 0); 

    /* start the CAPTURE process */
    pid = start_child(CAPTURE,COMO_SHARED_MEM,capture_mainloop,capture_fd,0); 

    /* move to the SUPERVISOR process (we don't fork here) */
    map.whoami = SUPERVISOR; 
    map.mem_type = COMO_SHARED_MEM; 
    setproctitle("%s", getprocfullname(map.whoami));
    supervisor_mainloop(supervisor_fd);
    return EXIT_SUCCESS; 
}
