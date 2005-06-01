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
   /* XXX what does this do?
    *     anyway it works only for linux
    *     -gianluca
    */
#include <mcheck.h>
#else 
#define mcheck(x)
#endif

/* Required for symlink deletion */
#include <errno.h>
#include <signal.h>	// signal... 
#include <unistd.h>

#include "query.h"	// mainloop...
#include "storage.h"
#include "como.h"

/*
 * the "map" is the root of the data. it contains all the
 * config parameters that are set before spawning the processes.
 * it is needed by all processes that will use their local copy.
 */
struct _como map;

extern char template[];	/* dynamically filled */
extern char stdpkt[];	/* dynamically filled */
static char * 
create_filter_template()
{
    char * filename;
    FILE * fp;
#define	DEF_TEMPLATE	"template.c"

    /* create file in our work directory */
    asprintf(&filename, "%s/stdpkt.h", map.workdir);
    fp = fopen(filename, "w");
    if (fp == NULL)
	panic("cannot create stdpkt.h %s\n", filename);
    fprintf(fp, stdpkt);
    fclose(fp);
    free(filename);

    asprintf(&filename, "%s/%s", map.workdir, DEF_TEMPLATE);
    fp = fopen(filename, "w");
    if (fp == NULL)
	panic("cannot create filter template %s\n", filename);
    fprintf(fp, template);
    fclose(fp);
    free(filename);

    return DEF_TEMPLATE;	/* relative filename is good */
}


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

    if (strcmp(map.procname, "su")) {
	logmsg(LOGUI, "cleanup: %s, just dying\n", map.procname);
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
    int storage_fd;
    int supervisor_fd;
    int ca_ex[2];	/* socketpairs for capture-export */

    mcheck(NULL); 	

#ifdef linux
    /* linux does not support setproctitle. we have our own. */
    init_setproctitle(argc, argv);
#endif

    /* set default values */
    memset(&map, 0, sizeof(map));
    map.procname = "su";    		/* supervisor */
    map.logflags = DEFAULT_LOGFLAGS; 
    map.mem_size = DEFAULT_MEMORY; 
    map.maxfilesize = DEFAULT_FILESIZE; 
    map.query_port = DEFAULT_QUERY_PORT; 
    map.module_max = DEFAULT_MODULE_MAX; 
    map.modules = safe_calloc(map.module_max, sizeof(module_t)); 
    map.workdir = mkdtemp(strdup("/tmp/comoXXXXXX"));

    /* create the filter template file */
    /* XXX check that we use the user-defined template */
    map.template = create_filter_template(); 

    /* write welcome message */ 
    logmsg(LOGUI, "----------------------------------------------------\n");
    logmsg(LOGUI, "  CoMo v%s (built %s %s)\n",
			COMO_VERSION, __DATE__, __TIME__ ); 
    logmsg(LOGUI, "  Copyright (c) 2004-2005, Intel Corporation\n"); 
    logmsg(LOGUI, "  All rights reserved.\n"); 
    logmsg(LOGUI, "----------------------------------------------------\n");
    logmsg(LOGUI, "-- Workdir is %s ---\n", map.workdir);
    logmsg(LOGUI, "-- Loading configuration:\n\n"); 

    parse_cmdline(argc, argv);

    logmsg(V_LOGUI, "log level: %s\n", loglevel_name(map.logflags)); 

    /*
     * Initialize the shared memory region that will be
     * used by CAPTURE and EXPORT (owned by CAPTURE)
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
    map.stats = new_mem(NULL, sizeof(stats_t), "stats data");

    /* initialize some stast */
    bzero(map.stats, sizeof(stats_t)); 
    gettimeofday(&map.stats->start, NULL); 
    map.stats->modules_active = map.module_count; 

    /*
     * Prepare to start processes.
     * First create unix-domain socket for storage (which will be
     * inherited by the children) and for the supervisor.
     * Then create a socketpair to connect capture-export.
     */
    storage_fd = create_socket("S:storage.sock", NULL);
    supervisor_fd = create_socket("S:supervisor.sock", NULL);

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ca_ex))
	panic("error creating socket pair\n");

    /* now start the CAPTURE process */
    pid = start_child("CAPTURE", "ca", capture_mainloop, ca_ex[0]);

    /* 
     * memory map not needed any more, get rid of it. 
     * this destroys only the map not the actual region of shared 
     * memory. CAPTURE is now in charge of allocating and freeing memory
     * in the shared memory region. however, all processes can still see,
     * read, and write in the shared memory if CAPTURE tell them where 
     * to look.... 
     */
    memory_clear();

    /* now start the STORAGE process */
    pid = start_child("STORAGE", "st", storage_mainloop, storage_fd);

    /*
     * Start the remaining processes.
     * SUPERVISOR is not really forked, so right before going to it
     * we call 'atexit' to register a handler.
     */
    pid = start_child("EXPORT", "ex", export_mainloop, ca_ex[1]);

    signal(SIGINT, exit);
    atexit(cleanup);
    pid = start_child("SUPERVISOR", NULL, supervisor_mainloop, supervisor_fd);

    return EXIT_SUCCESS; 
}
