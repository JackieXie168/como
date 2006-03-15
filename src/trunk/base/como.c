/*
 * Copyright (c) 2004, Intel Corporation
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
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>		/* strlen strcpy strncat memset */

#ifdef linux
#include <mcheck.h>
#else 
#define mcheck(x)
#endif

/* Required for symlink deletion */
#include <errno.h>
#include <signal.h>	// signal... 
#include <unistd.h>

#include "como.h"
#include "storage.h"	// mainloop

/*
 * the "map" is the root of the data. it contains all the
 * config parameters that are set before spawning the processes.
 * it is needed by all processes that will use their local copy.
 */
struct _como map;

/*
 * cleanup() called at termination time to
 * remove the byproducts of the compilation.
 * The function is registered with atexit(), which does not provide
 * a way to unregister the function itself. So we have to check which
 * process died (through map.procname) and determine what to do accordingly.
 */
static void
cleanup()
{
    char *cmd;

    if (map.whoami != SUPERVISOR) { 
	logmsg(V_LOGWARN, "terminating normally\n");
	return;
    }
    logmsg(LOGUI, "\n\n\n--- about to exit... remove work directory %s\n",
	map.workdir);
    asprintf(&cmd, "rm -rf %s\n", map.workdir);
    system(cmd);
    logmsg(LOGUI, "--- done, thank you for using como\n");
}


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
    int capture_fd; 
    int storage_fd;
    int supervisor_fd;

    mcheck(NULL); 	

#ifdef linux
    /* linux does not support setproctitle. we have our own. */
    init_setproctitle(argc, argv);
#endif

    /* set default values */
    memset(&map, 0, sizeof(map));
    map.whoami = SUPERVISOR; 
    map.supervisor_fd = -1;
    map.logflags = DEFAULT_LOGFLAGS; 
    map.mem_size = DEFAULT_MEMORY; 
    map.maxfilesize = DEFAULT_FILESIZE; 
    map.module_max = DEFAULT_MODULE_MAX; 
    map.modules = safe_calloc(map.module_max, sizeof(module_t)); 
    map.workdir = mkdtemp(strdup("/tmp/comoXXXXXX"));
    map.node.name = strdup("CoMo Node"); 
    map.node.location = strdup("Unknown"); 
    map.node.type = strdup("Unknown");
    map.node.query_port = DEFAULT_QUERY_PORT; 

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
    configure(argc, argv);

    logmsg(V_LOGUI, "log level: %s\n", loglevel_name(map.logflags)); 

    /*
     * Initialize the shared memory region.
     * All processes will be able to see it.
     */
    memory_init(map.mem_size);

    /* 
     * Before forking processes, create a data structure in shared 
     * memory to allow CAPTURE, EXPORT, STORAGE, etc to share some 
     * statistics with SUPERVISOR. 
     * We do not have any locking mechanisms on the counters. 
     * They are written by one process and read by SUPERVISOR. They 
     * do not need to be 100% reliable. 
     */
    map.stats = mem_alloc(sizeof(stats_t)); 
    bzero(map.stats, sizeof(stats_t)); 
    map.stats->mdl_stats = mem_alloc(map.module_max * sizeof(mdl_stats_t));
    gettimeofday(&map.stats->start, NULL); 
    map.stats->modules_active = map.module_count; 
    map.stats->first_ts = ~0;

    /*
     * Prepare to start processes.
     * Create unix-domain socket for storage and capture (they will be
     * inherited by the children), and for the supervisor (that is what 
     * this process will become).
     */
    capture_fd = create_socket("S:capture.sock", NULL); 
    storage_fd = create_socket("S:storage.sock", NULL);
    supervisor_fd = create_socket("S:supervisor.sock", NULL);

    /* start the CAPTURE process */
    pid = start_child(CAPTURE, COMO_SHARED_MEM, capture_mainloop, capture_fd); 

    /* start the STORAGE process */
    pid = start_child(STORAGE, COMO_PRIVATE_MEM, storage_mainloop, storage_fd);

    /*
     * Start the remaining processes.
     * SUPERVISOR is not really forked, so right before going to it
     * we call 'atexit' to register a handler.
     */
    pid = start_child(EXPORT, COMO_PRIVATE_MEM, export_mainloop, -1); 

    signal(SIGINT, exit);
    atexit(cleanup);
    pid = start_child(SUPERVISOR, COMO_SHARED_MEM|COMO_PERSISTENT_MEM, 
	supervisor_mainloop, supervisor_fd);

    return EXIT_SUCCESS; 
}
