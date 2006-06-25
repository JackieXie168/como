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

#include "comotypes.h"
#include "comofunc.h"
#include "sniffers.h"

/* 
 * this structure contains the node specific 
 * information (name, location, etc.). It is a 
 * list given that one can define multiple virtual 
 * nodes to run in parallel. They will run the same 
 * modules and respond on different to query on 
 * different port. a virtual node may apply a filter on 
 * all packets before the module process them. 
 */
struct _node { 
    int id;			/* virtual node id (starts from 1) */
    char * name; 
    char * location; 
    char * type; 
    char * comment;
    int query_port;		/* port for incoming queries */
    char * filter_str;          /* filter expression */
    char ** args;               /* parameters for the modules */
    struct _node * next; 	/* next node */
};

typedef struct _node	node_t; 

    
/*
 * Data structure containing all the configuration parameters
 * loaded from the default config file(s) and the command line.
 * This data structure will contain the information about all the
 * modules and classifiers as well.
 */
struct _como {
    procname_t whoami; 		/* process using this instance */
    procname_t parent; 		/* parent process */
    runmodes_t running;         /* mode of operation */ 

    int ac;			/* command line arguments */
    char **av;			/* command line arguments */

    char * workdir;		/* work directory for templates etc. */
    char * dbdir; 	    	/* database directory for output files */
    char * libdir;		/* base directory for modules */
    int logflags;       	/* log flags (i.e., what to log) */
    FILE * logfile;		/* log file */

    size_t mem_size;    	/* memory size for capture/export (MB) */
    int mem_type;		/* defines how to allocate memory */
#define COMO_PRIVATE_MEM 	0x01
#define COMO_SHARED_MEM 	0x02

    node_t * node;		/* node information */
    int node_count;		/* no. of nodes */

    stats_t * stats; 		/* statistic counters */

    source_t *sources;		/* list of input data feeds (sniffers) */

    module_t * modules; 	/* array of modules */ 
    int module_max;  		/* max no. of modules */
    int module_used; 	  	/* number of used entries */
    int module_last;  		/* last used entry in modules array */

    alias_t * aliases; 		/* module aliases */ 

    size_t maxfilesize; 	/* max file size in one bytestream */
    int maxqueries;

    char *debug;		/* debug mode */
	/*
	 * here we simply store a malloced copy of the string
	 * passed as -x from the command line, then each
	 * process decides what to do with it, with some string
	 * matching function.
	 */

    module_t * inline_mdl;	/* module that needs to be run in inline
				 * mode
				 */
    int inline_fd;		/* fd of inline client */
};


/*
 * standard names for master processes.
 * no parent and no id
 */
#define SUPERVISOR      0x00010000
#define CAPTURE         0x00020000
#define EXPORT          0x00030000
#define STORAGE         0x00040000
#define QUERY           0x00050000


/* log flags. The high bits are only set for verbose logging */
#define	LOGUI		0x0001	/* normal warning msgs			*/
#define	LOGWARN		0x0002	/* normal warning msgs			*/
#define	LOGMEM		0x0004	/* memory.c debugging			*/
#define	LOGCONFIG	0x0008	/* config.c debugging			*/
#define	LOGCAPTURE	0x0010
#define	LOGEXPORT	0x0020
#define	LOGSTORAGE	0x0040
#define	LOGQUERY	0x0080
#define	LOGSNIFFER	0x0100	/* sniffers debugging 			*/
#define LOGTIMER	0x0200	/* print timing information 		*/
#define LOGMODULE	0x0400	/* modules */
#define LOGIPC		0x0800	/* IPC */
#define	LOGALL		(LOGUI|LOGWARN|LOGMEM|LOGCONFIG|LOGCAPTURE| \
				LOGEXPORT|LOGSTORAGE|LOGQUERY|LOGSNIFFER| \
				LOGTIMER|LOGMODULE|LOGIPC)

#define	V_LOGUI		(LOGUI << 16) 
#define	V_LOGWARN	(LOGWARN << 16)
#define	V_LOGMEM	(LOGMEM << 16)
#define	V_LOGCONFIG	(LOGCONFIG << 16)
#define	V_LOGCAPTURE	(LOGCAPTURE << 16)
#define	V_LOGEXPORT	(LOGEXPORT << 16)
#define	V_LOGSTORAGE	(LOGSTORAGE << 16)
#define	V_LOGQUERY	(LOGQUERY << 16)
#define	V_LOGSNIFFER	(LOGSNIFFER << 16)
#define	V_LOGTIMER	(LOGTIMER << 16)
#define	V_LOGMODULE	(LOGMODULE << 16)
#define	V_LOGIPC	(LOGIPC << 16)

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
