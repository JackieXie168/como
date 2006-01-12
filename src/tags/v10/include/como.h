/*
 * Copyright (c) 2004 Intel Corporation
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

#ifndef _COMO_COMO_H
#define _COMO_COMO_H

#include <sys/time.h>   /* struct timeval */

#include "comotypes.h"
#include "comofunc.h"
#include "sniffers.h"

/*
 * Data structure containing all the configuration parameters
 * loaded from the default config file(s) and the command line.
 * This data structure will contain the information about all the
 * modules and classifiers as well.
 */
struct _como {
    char * procname;    /* process using this instance */
    char * basedir;     /* base directory for output files */
    char * libdir;      /* base directory for classifiers */
    char * workdir;	/* work directory for templates etc. */
    size_t mem_size;    /* memory size for capture/export (MB) */
    int logflags;       /* log flags (i.e., what to log) */

    stats_t * stats; 	/* statistic counters */

    source_t *sources;	/* list of input data feeds */

    module_t * modules; /* array of modules */ 
    int module_max;  	/* max no. of modules */
    int module_count;   /* current no. of modules */

    size_t maxfilesize; /* max file size in one bytestream */

    int maxqueries;
    int query_port;

    int supervisor_fd;	/* util routines etc */

    char *debug;		/* debug mode */
	/*
	 * here we simply store a malloced copy of the string
	 * passed as -x from the command line, then each
	 * process decides what to do with it, with some string
	 * matching function.
	 */

    /* node information */
    char * name; 
    char * location; 
    char * linkspeed; 
    char * comment;

    int il_mode;            /* tells whether CoMo has been started in
                             * inline mode */
    module_t * il_module;   /* module that needs to be run in inline mode */
    char * il_qargs;        /* query args for the inline mode */
    int il_inquery;         /* tells whether we are printing the results of
                             * the query while in inline mode */
};



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
#define LOGMODULE	0x0400	/* modules debugging 			*/
#define	LOGDEBUG	0x8000
#define	LOGALL		(LOGUI|LOGWARN|LOGMEM|LOGCONFIG|LOGCAPTURE| \
				LOGEXPORT|LOGSTORAGE|LOGQUERY|LOGDEBUG| \
				LOGSNIFFER|LOGTIMER|LOGMODULE)

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
#define	V_LOGDEBUG	(LOGDEBUG << 16)

/*
 * default values 
 */
#define DEFAULT_CFGFILE 	"como.conf"	/* configuration file */
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
