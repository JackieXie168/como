/*-
 * Copyright (c) 2004 - Intel Corporation 
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

#ifndef _COMO_STORAGE_H_
#define _COMO_STORAGE_H_

/*
 * Data structure definitions for Como Storage module.
 * The preferred prefix for all entries here is 'cs' for Como Storage.
 *
 */
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>

#define CS_MAXCLIENTS   	500            	/* max no. of clients/files */
#define CS_OPTIMALSIZE		(1024*1024)	/* size for mmap() */
#define CS_DEFAULT_TIMEOUT	TIME2TS(60,0)	/* readers' timeout */

/*
 * Modes for opening a bytestream.
 * We voluntarily use some weird values to catch errors.
 */
#define CS_READER		0xff12	/* read mode */
#define CS_READER_NOBLOCK	0xdfde	/* read mode (non blocking) */
#define CS_WRITER		0x0437	/* write mode */

/*
 * file name format 
 */
#define FILE_NAMELEN    16 /* filenames are 16 decimal digits */
#define FILE_NAMEFMT    "%s/%016llx" /* format used to print */

/*
 * Message exchanged between STORAGE and its clients.
 */
typedef struct {
    int id; 
    int arg;			/* seek method, open mode, error code */ 
    off_t ofs;			/* requested offset */
    off_t size;			/* requested/granted block size (or filesize) */
    char name[FILENAME_MAX];	/* file name (only for OPEN messages) */
} csmsg_t;

typedef enum {
    CS_SEEK_NONE,		/* error */
    CS_SEEK_FILE_NEXT,		/* goto next file */
    CS_SEEK_FILE_PREV,		/* goto prev file */

#if 0	/* XXX unimplemented */
    CS_SEEK_SET,		/* seek from the first byte */
    CS_SEEK_CUR,		/* seek from the current byte */
    CS_SEEK_END,		/* seek from the last byte */
    CS_SEEK_FILE_SET,	/* seek from the first file */
    CS_SEEK_FILE_CUR,	/* seek from the current file */
    CS_SEEK_FILE_END,	/* seek from the last file */
    CS_SEEK_TIME_SET,	/* seek from the first timestamp */
    CS_SEEK_TIME_CUR,	/* seek from the current timestamp */
    CS_SEEK_TIME_END,	/* seek from the last timestamp */
#endif
} csmethod_t;

/* 
 * Function prototypes 
 */
void storage_mainloop();
int csopen(const char * name, int mode, off_t size, int sd);
off_t csgetofs(int fd);
void *csmap(int fd, off_t ofs, ssize_t * sz);
void cscommit(int fd, off_t ofs);
off_t csseek(int fd, csmethod_t wh);
void csclose(int fd, off_t ofs);


#ifdef _COMO_STORAGE_SERVER

/*
 * This part of the file contains the internal data structures
 * of the server side of the storage process.

Information is stored in entities called 'bytestreams', whose internal
representation is opaque to the client.
In practice, this code implements a bytestream as a directory
with multiple actual files in it, each one of a given maximum size.
The name of each file is the offset of the file itself within the
bytestream.


The server concurrently handles requests for multiple bytestreams,
up to a maximum of CS_MAXFILES. Each bytestream is described by
an object of type csinternal_t, and these are accessed through
the array cs_state.csdesc[]

For each bytestream we can have multiple clients attached to it.
Each client is described by an object of type csclient_t,
and the clients for the same bytestream are in a doubly-linked list
hanging off the csinternal_t.

For each client, we can have multiple mapped regions, linked in
a list hanging off the csclient_t. There is at most one regions that
is active, i.e. one on which the client side is operating, and this
is the first one in the list.

XXX writer: we need an explicit unmap or a parameter on the close
to record how much of the last region has actually been used.

 *
 */

typedef struct _csregion csregion_t;
typedef struct _csclient csclient_t;
typedef struct _csfile csfile_t;
typedef struct _csbytestream csbytestream_t;
typedef struct _csblocked csblocked_t;

/*
 * Region descriptor
 *
 * This data structure contains the state of each region currently
 * handled (i.e. mmapped) by the STORAGE process.
 * NOTE: we do not store the 'fd' here because it is not used in
 * the munmap, which is all we do with this information.
 * Regions can be linked to a csfile_t or a csclient_t
 * depending on who is controlling them.
 */
struct _csregion {
    csregion_t * next;		/* link field */
    off_t bs_offset;            /* bytestream offset of the region */
    void * addr;                /* memory address of the mapped region  */
    size_t reg_size;            /* size of the mapped region */
    int wfd;			/* fd if we need to close(), -1 otherwise */
    csfile_t *file; 		/* the file this region is from */
};


/* 
 * Client descriptor.
 * At any given time, the client has only one open file in the bytestream.
 * All clients for the same file in the bytestream are linked in a list
 * hanging off the csfile_t
 */
struct _csclient { 
    csclient_t * next;		/* next client */
    int id; 			/* client id */
    int mode;			/* access mode */
    int blocked; 		/* set if blocked waiting for a write */
    csbytestream_t *bs;		/* the bytestream */
    csfile_t *file;		/* the current file (readers only) */
    csregion_t *region; 	/* the memory mapped region */
    timestamp_t timeout; 	/* watchdog timeout for broken clients */
};


/*
 * File descriptor, one for each file in a bytestream.
 * Because there can be only one writer for a bytestream, and it
 * MUST operate on the last file, we store the relevant info in the
 * bytestream descriptor.
 */
struct _csfile {
    csfile_t *next;		/* next file in the bytestream */
    int	rfd;			/* reader fd */
    csbytestream_t *bs;		/* the bytestream */
    off_t bs_offset;		/* bytestream offset (used as filename too) */
    size_t cf_size;		/* file size, updated on each write request */
    csclient_t *clients;	/* list of clients working on this file */
};


/* 
 * Blocked client list element. It contains the 
 * information needed to wake up the client and try the
 * request again. 
 */
struct _csblocked { 
    csblocked_t *next;		/* next blocked client */
    csclient_t *client; 	/* reader descriptor */	   
    csmsg_t msg; 		/* request message */
    int sock; 			/* whom to reply to */
};

    
/*
 * Bytestream descriptor. Active bytestreams are linked in a list
 * for use by the server.
 */
struct _csbytestream {
    csbytestream_t *next;	/* link field */
    char * name;                /* bytestream name (i.e., directory name) */
    off_t size;                 /* bytestream size (available to readers) */
    off_t sizelimit;		/* max allowed bytestream size */
    csfile_t *file_first;	/* head of list of files */
    csfile_t *file_last;	/* tail of list of files */
    int client_count;           /* clients active on this stream */
    int wfd;			/* writer fd, if there is a writer */
    csclient_t *the_writer;	/* writer client */
    csregion_t *wb_head; 	/* head of write buffer */
    csregion_t *wb_tail;	/* tail of write buffer */
    csblocked_t *blocked; 	/* list of blocked readers */
};


/*       
 * The entire state of the storage 
 * process is described by this data structure.
 */
struct _cs_state {
    csbytestream_t *bs;         /* the list of bytestreams */
    csregion_t *reg_freelist;   /* region free list */
    int client_count;           /* how many in use */
    csclient_t *clients[CS_MAXCLIENTS];
};


#endif  /* _COMO_STORAGE_SERVER */
#endif	/* _COMO_STORAGE_H_ */
