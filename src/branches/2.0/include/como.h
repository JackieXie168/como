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

#ifndef _COMO_COMO_H
#define _COMO_COMO_H

#include <stdio.h>
#include <sys/time.h>   /* struct timeval */

#define HAS_COMO_BUILD
#ifdef HAS_COMO_BUILD
#include "como-build.h"
#endif

#ifdef __GNUC__
#define PACKED			__attribute__ ((packed))
#define UNUSED			__attribute__ ((unused))
#define DEPREC			__attribute__ ((deprecated))
#define WARN_UNUSED_RESULT	__attribute__ ((warn_unused_result))
#else
#define PACKED
#define UNUSED
#define DEPREC
#define WARN_UNUSED_RESULT
#endif

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

#define ALIGN(size, boundary) \
    (((size) + ((boundary) - 1)) & ~((boundary) - 1))
#define ALIGN_DEFAULT(size) ALIGN(size, 8)

#define SWAP32(x) x = (uint32_t)((x >> 24 & 0xff) | (x >> 8 & 0xff00) | \
		      (x << 8 & 0xff0000) | (x << 24 & 0xff000000))
#define SWAP16(x) x = (uint16_t)((x << 8 & 0xff00) | (x >> 8 & 0xff))

#define ROUND_32(n) (((n) + 3) & ~3)

#include "sniffers.h"
#include "comotypes.h"
#include "ipc.h"
#include "comofunc.h"
#include "log.h"
#include "eventloop.h"
#include "pool.h"
#include "shmem.h"




void setproctitle_init(int argc, char **argv);
void setproctitle(const char *format, ...);




#if 0
    
/*
 * Data structure containing all the configuration parameters
 * loaded from the default config file(s) and the command line.
 * This data structure will contain the information about all the
 * modules and classifiers as well.
 */
struct _como {
    procname_t	whoami;		/* process using this instance */
    procname_t	parent;		/* parent process */
    runmode_t	runmode;	/* mode of operation */

    int		ac;		/* command line arguments */
    char **	av;		/* command line arguments */

    char *	workdir;		/* work directory for templates etc. */
    char *	dbdir; 	    	/* database directory for output files */
    char *	libdir;		/* base directory for modules */
    int		logflags;       /* log flags (i.e., what to log) */
    FILE *	logfile;	/* log file */
    char *	asnfile;	/* routing table file giving AS identities */

    size_t	mem_size;	/* memory size for capture/export (MB) */
    int		mem_type;	/* defines how to allocate memory */
#define COMO_PRIVATE_MEM 	0x01
#define COMO_SHARED_MEM 	0x02

    como_node_t *	node;		/* node information */
    int		node_count;	/* no. of nodes */

    stats_t *	stats; 		/* statistic counters */

    source_t *	sources;	/* list of input data feeds (sniffers) */
    int		source_count;

    module_t *	modules; 	/* array of modules */ 
    int		module_max;  	/* max no. of modules */
    int		module_used;   	/* number of used entries */
    int		module_last;  	/* last used entry in modules array */

    alias_t *	aliases; 	/* module aliases */ 

    size_t	maxfilesize; 	/* max file size in one bytestream */

    int		debug;		/* debug mode */
    int		debug_sleep;	/* how many secs to sleep */

    timestamp_t	live_thresh;	/* threshold used to synchronize multiple
				   sniffers */

    module_t *	inline_mdl;	/* module that runs in inline mode */
    int		inline_fd;	/* descriptor of inline client */

    int		exit_when_done; /* when set causes capture to send IPC_DONE
				   message to its parent process when all
				   the sniffers have terminated */
    struct {
	int	done_flag:1;
	int	dbdir_set:1;
	int	libdir_set:1;
	int	query_port_set:1;
	int	mem_size_set:1;
	int	logflags_set:1;
    } cli_args;			/* flags set when the corresponding command
				   line arguments are set to prevent
				   overwriting the values set from from the
				   command line */
};

#endif

/*
 * default values 
 */
#define DEFAULT_STREAMSIZE 	(1024*1024*1024)/* bytestream size */
#define DEFAULT_FILESIZE 	(128*1024*1024)	/* single file size in stream */
#define DEFAULT_BLOCKSIZE 	4096		/* block size */
#define DEFAULT_MODULE_MAX	128		/* max no. modules */
#define DEFAULT_LOGFLAGS	(LOGUI|LOGWARN) /* log messages */
#define DEFAULT_MEMORY		64		/* memory capture/export */
#define DEFAULT_QUERY_PORT	44444		/* query port */
#define DEFAULT_CAPTURE_IVL	TIME2TS(1,0)    /* capture flush interval */
#define DEFAULT_REPLAY_BUFSIZE	(1024*1024)	/* replay packet trace buffer */


#define DEBUG_SLEEP	20 /* how many seconds */
#define DEBUGGER_WAIT_ATTACH(code) do {		\
    const char *debug = getenv("COMO_DEBUG");	\
    if (debug && strstr(debug, code) != NULL) {		\
	msg("waiting %ds for the debugger to attach on pid %d\n", \
	    DEBUG_SLEEP, getpid()); \
	sleep(DEBUG_SLEEP);			\
	msg("wakeup, ready to work\n");		\
    }						\
} while(0)


/* The "memory" bit is a gcc-ism saying that any pending writes to
   memory presently held in registers need to be flushed, and any
   previously loaded values which have been cached somewhere need to
   be discarded.  Processor re-ordering is inhibited by any locked
   instruction which actually touches memory; addl $0,0(%%esp) is the
   cheapest such instruction which has no side effects and which is
   guaranteed to be present on all x86 processors from 486 on.

   mfence would also work, but isn't actually that much faster and
   isn't available on all processors. */
#ifndef BUILD_FOR_ARM
#define mb() asm volatile ("lock;addl $0,0(%%esp)\n":::"memory")
#else 
#define mb()
#endif

#endif /* _COMO_COMO_H */
