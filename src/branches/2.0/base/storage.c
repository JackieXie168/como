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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>	/* AF_UNIX sockets */

#define LOG_DISABLE
#include "como.h"
#include "comopriv.h"

#include "storagepriv.h"


/*
 * STORAGE
 * -------
 * 
 * This code implements the core of the storage module in como.
 * Note that we use global variables to store state.
 *
 * The server handles a maximum of CS_MAXFILES different 'bytestreams'.
 * On each of these we can have zero or one writer (in append mode
 * only) and an unlimited number of readers.
 *
 * The S_OPEN RPC returns an opaque descriptor used as a handle for
 * the subsequent transactions.
 *
 * ---------------------
 */

/*
 * This part of the file contains the internal data structures
 * of the server side of the storage process.
 * Information is stored in entities called 'bytestreams', whose internal
 * representation is opaque to the client.
 * In practice, this code implements a bytestream as a directory
 * with multiple actual files in it, each one of a given maximum size.
 * The name of each file is the offset of the file itself within the
 * bytestream.
 * 
 * 
 * The server concurrently handles requests for multiple bytestreams,
 * up to a maximum of CS_MAXFILES. Each bytestream is described by
 * an object of type csinternal_t, and these are accessed through
 * the array como_st.csdesc[]
 * 
 * For each bytestream we can have multiple clients attached to it.
 * Each client is described by an object of type csclient_t,
 * and the clients for the same bytestream are in a doubly-linked list
 * hanging off the csinternal_t.
 * 
 * For each client, we can have multiple mapped regions, linked in
 * a list hanging off the csclient_t. There is at most one regions that
 * is active, i.e. one on which the client side is operating, and this
 * is the first one in the list.
 * 
 * XXX writer: we need an explicit unmap or a parameter on the close
 * to record how much of the last region has actually been used.
 * 
 */

typedef struct csregion csregion_t;
typedef struct csclient csclient_t;
typedef struct csfile csfile_t;
typedef struct csbytestream csbytestream_t;
typedef struct csblocked csblocked_t;

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
struct csregion {
    csregion_t *next;		/* link field */
    off_t	bs_offset;	/* bytestream offset of the region */
    void *	addr;		/* memory address of the mapped region  */
    size_t	reg_size;	/* size of the mapped region */
    int		wfd;		/* fd if we need to close(), -1 otherwise */
    csfile_t *	file;		/* the file this region is from */
};


/* 
 * Client descriptor.
 * At any given time, the client has only one open file in the bytestream.
 * All clients for the same file in the bytestream are linked in a list
 * hanging off the csfile_t
 */
struct csclient { 
    csclient_t *	next;		/* next client */
    int			id;		/* client id */
    int			mode;		/* access mode */
    int			blocked;	/* set if blocked waiting to write */
    csbytestream_t *	bs;		/* the bytestream */
    csfile_t *		file;		/* the current file (readers only) */
    csregion_t *	region;		/* the memory mapped region */
    timestamp_t		timeout;	/* watchdog timeout for broken
					   clients */
};


/*
 * File descriptor, one for each file in a bytestream.
 * Because there can be only one writer for a bytestream, and it
 * MUST operate on the last file, we store the relevant info in the
 * bytestream descriptor.
 */
struct csfile {
    csfile_t *		next;		/* next file in the bytestream */
    int			rfd;		/* reader fd */
    csbytestream_t *	bs;		/* the bytestream */
    off_t		bs_offset;	/* bytestream offset (used as filename
					   too) */
    size_t		cf_size;	/* file size, updated with S_INFORM */ 
    csclient_t *	clients;	/* list of clients working on this
					   file */
};


/* 
 * Blocked client list element. It contains the 
 * information needed to wake up the client and try the
 * request again. 
 */
struct csblocked { 
    csblocked_t *	next;		/* next blocked client */
    csclient_t *	client;		/* reader descriptor */	   
    csmsg_t		msg;		/* request message */
    ipc_peer_t *	peer;		/* whom to reply to */
};

    
/*
 * Bytestream descriptor. Active bytestreams are linked in a list
 * for use by the server.
 */
struct csbytestream {
    csbytestream_t *	next;		/* link field */
    char *		name;		/* bytestream name 
					   (i.e., directory name) */
    off_t		size;		/* bytestream size
					   (available to readers) */
    off_t		sizelimit;	/* max allowed bytestream size */
    csfile_t *		file_first;	/* head of list of files */
    csfile_t *		file_last;	/* tail of list of files */
    int			client_count;	/* clients active on this stream */
    int			wfd;		/* writer fd, if there is a writer */
    csclient_t *	the_writer;	/* writer client */
    csregion_t *	wb_head;	/* head of write buffer */
    csregion_t *	wb_tail;	/* tail of write buffer */
    csblocked_t *	blocked;	/* list of blocked readers */
};


/*       
 * The entire state of the storage 
 * process is described by this data structure.
 */
struct como_st {
    csbytestream_t *	bs;		/* the list of bytestreams */
    csregion_t *	reg_freelist;	/* region free list */
    int			client_count;	/* how many in use */
    csclient_t *	clients[CS_MAXCLIENTS];
    off_t		maxfilesize;
    int			supervisor_fd;
    int			accept_fd;
    event_loop_t	el;
};

/* 
 * state variables 
 */
static struct como_st s_como_st;


static void
assert_regionlist_acyclic(csregion_t *region)
{
    csregion_t *ptr1, *ptr2;

    ptr1 = ptr2 = region;
    while (ptr1 != NULL) {
	ptr1 = ptr1->next;
	if (ptr1 == NULL)
	    return;
	if (ptr1 == ptr2)
	    error("writebuffer cyclic");
	ptr2 = ptr2->next;
	ptr1 = ptr1->next;
    }
}

static void
assert_region_not_in_list(csregion_t *blk, csregion_t *list)
{
    while (list != NULL) {
	if (blk == list)
	    error("region unexpectedly in list");
	list = list->next;
    }
}

/**
 * -- new_csregion
 * 
 * allocates a new region (from the free list, if possible) 
 * and initializes it. 
 *
 */
static csregion_t *
new_csregion(off_t bs_offset, size_t reg_size)
{
    csregion_t *blk;

    blk = s_como_st.reg_freelist;
    if (blk == NULL)
	blk = como_new0(csregion_t);
    else 
	s_como_st.reg_freelist = blk->next;
    blk->next = NULL;
    blk->bs_offset = bs_offset;
    blk->addr = NULL; 
    blk->reg_size = reg_size;
    blk->wfd = -1;	/* signal the scheduler no need to close 
			 * the file after unmap() */
    return blk;
}


/** 
 * -- free_region
 * 
 * Frees csregion moving it to the free list. 
 *
 */
static void
free_region(csregion_t *blk)
{
    assert_region_not_in_list(blk, s_como_st.reg_freelist);
    assert_regionlist_acyclic(s_como_st.reg_freelist);
    blk->next = s_como_st.reg_freelist;
    s_como_st.reg_freelist = blk;
}


/**
 * -- new_csfile 
 * 
 * creates the descriptor and appends it to the bytestream 
 * in sorted order.
 * 
 * it returns a pointer to the new descriptor. 
 * this function never fails. 
 * 
 */
static csfile_t *
new_csfile(csbytestream_t *bs, off_t off_val, int size)
{
    csfile_t *x, *prev;
    csfile_t *cf; 

    cf = como_new0(csfile_t);
    cf->cf_size = size;
    cf->bs_offset = off_val;
    cf->bs = bs;
    cf->rfd = -1;	/* no active reader */

    /*
     * append to the list in sorted order 
     */
    for (x = bs->file_first, prev = NULL; x && x->bs_offset < off_val ;
		prev = x, x = x->next)
	;
    /* the file is after prev and before x */
    cf->next = x;
    if (prev == NULL)	/* goes to the head */
	bs->file_first = cf;
    else
	prev->next = cf;
    if (x == NULL)	/* this is the new tail */
	bs->file_last = cf;
    return cf;
}


/*
 * -- delete_csfile
 * 
 * deletes csfile updating the bytestream information 
 *
 */
static void
delete_csfile(csfile_t * cf)
{
    csbytestream_t * bs = cf->bs; 
    char * nm;

    bs->size -= cf->cf_size; 
    bs->file_first = cf->next; 
    if (bs->file_first == NULL) 
	error("reducing bytestream %s to zero size", bs->name); 

    if (cf->rfd >= 0)
	close(cf->rfd); 

    asprintf(&nm, FILE_NAMEFMT, bs->name, cf->bs_offset); 
    unlink(nm);
    free(nm);

    debug("resizing bytestream %s (from %lld to %lld)\n", 
	bs->name, bs->size + cf->cf_size, bs->size); 

    free(cf);
}


/**
 * -- open_file
 * 
 * opens the backing file for a given csfile_t with the desired mode.
 * update the descriptor in the csfile_t (a reader) or in csbytestream_t
 * (the writer, there is only one for the entire bytestream).
 *
 */
static int
open_file(csfile_t *cf, int mode)
{
    char *name;
    int flags;
    int fd;

    debug("open_file %016llx mode %s rfd %d wfd %d\n",
	cf->bs_offset, (mode == CS_WRITER ? "CS_WRITER" : "CS_READER"), 
	cf->rfd, cf->bs->wfd);

    /* 
     * easy if the file is already open. we just return the same OS 
     * file descriptor that has been used so far by all clients 
     * (remember that the file is always accessed via mmap, never read, 
     * write, lseek, etc., hence we can use one file descriptor for all 
     * clients). 
     */
    if ((mode == CS_READER || mode == CS_READER_NOBLOCK) && cf->rfd >= 0)
	return cf->rfd;
    else if (mode == CS_WRITER && cf->bs->wfd >= 0)
	return cf->bs->wfd;

    /* 
     * set the flags. in read mode we just want O_RDONLY, in write
     * mode instead we would like O_WRONLY|O_CREAT
     */
#ifdef linux	/* we need O_RDWR */
    flags = (mode == CS_WRITER)? O_RDWR|O_CREAT|O_APPEND : O_RDWR;
#else
    flags = (mode == CS_WRITER)? O_WRONLY|O_CREAT|O_APPEND : O_RDONLY;
#endif

    /* open the file */
    asprintf(&name, FILE_NAMEFMT, cf->bs->name, cf->bs_offset);
    fd = open(name, flags, 0666);
    if (fd < 0) 
        error("opening file %s: %s\n", name, strerror(errno));
    free(name);

    if (mode == CS_WRITER)
	cf->bs->wfd = fd;	/* writer info is in the csbytestream_t */
    else
	cf->rfd = fd;

    return fd;
}


/** 
 * -- get_fileinfo 
 * 
 * This function looks for meta information for a bytestreams.
 * Given that a bytestream in CoMo consists of a directory with a 
 * set of files used to emulate a circular buffer, this function goes 
 * in the directory and looks for the first file (the name of the files 
 * is the offset) and computes the total size of the bytestream as well. 
 * 
 * Return 0 on success, EINVAL/EACCES on error
 *
 * XXX ideally we would like to store more information about the
 *     bytestream (e.g., cumulative size, gaps in time, time index, etc.) 
 *     but that could reside in support files with names like .meta, .time, 
 *     etc.
 *     we will get there one day. 
 *
 */
static int 
get_fileinfo(csbytestream_t *bs, char *name, int mode)
{
    DIR * d;                    
    struct dirent *fp;         
    struct stat sb;
    int ret;

    debug("getting meta information for %s\n", name); 

    /* open the directory to see if it is there */
    d = opendir(name);
    if (d == NULL) {
        /*
         * The directory is not there (XXX or it is too big...).
         * If in read mode return an error. In write mode, we 
	 * assume O_CREAT by default so we create it empty.
         */
	if (mode != CS_WRITER) { 
	    warn("get_fileinfo: file %s does not exist\n", name); 
	    return EINVAL; 
	} 
	ret = mkdir(name, (mode_t) (S_IRWXU | S_IRWXG | S_IRWXO));
	if (ret < 0) { 
	    warn(
		"get_fileinfo: failed creating directory %s: %s\n",
		name, strerror(errno)); 
            return EACCES;
	}
	d = opendir(name);
    }

    /*
     * The directory exists. look for the file with the lowest offset.
     */
    while ((fp = readdir(d)) != NULL) {
	off_t off_val;
   	char *nm;
 
	/* check if the name is not as expected */
	if (_D_EXACT_NAMLEN(fp) != FILE_NAMELEN) 
	    continue; 

        off_val = (off_t) strtoll(fp->d_name, &nm, FILE_NAMELEN);
	if (fp->d_name + FILE_NAMELEN != nm)
	    continue;	/* invalid filename length */

	/* get the file size */
        asprintf(&nm, FILE_NAMEFMT, name, off_val); 
	stat(nm, &sb);
 	bs->size += sb.st_size;
	free(nm); 

	/* create the descriptor and append in sorted order */
	new_csfile(bs, off_val, sb.st_size);
    }

    debug("bytestream %s size %lld\n", bs->name, bs->size); 
    return 0;
} 


/**
 * -- senderr
 *
 * sends an error message. 
 *
 */
static void
senderr(ipc_peer_t * s, int id, int code)
{
    csmsg_t m;

    memset(&m, 0, sizeof(m));
    if (code == 0)
	error("storage failing a request without giving a reason");
    m.id = id;
    m.arg = code;
    if (ipc_send(s, S_ERROR, &m, sizeof(m)) != IPC_OK) {
	error("sending error message: %s\n", strerror(errno));
    }

    msg("out: ERROR - id: %d; code: %d;\n", id, code);
}


/**
 * -- sendack
 *
 * sends an acknowledgement 
 *
 */
static void
sendack(ipc_peer_t * s, int id, off_t ofs, size_t sz)
{
    csmsg_t m;

    memset(&m, 0, sizeof(m));
    m.id = id;
    m.ofs = ofs;
    m.size = sz;
    if (ipc_send(s, S_ACK, &m, sizeof(m)) != IPC_OK) {
	error("sending ack: %s\n", strerror(errno));
    }

    debug("out: ACK - id: %d, ofs: %12lld, sz: %8d\n",
		id, ofs, sz);
}


/**
 * -- new_bytestream 
 * 
 * create a new bytestream descriptor, fill the file info with
 * information from the filesystem (no. of files, their size, etc.), 
 * add the descriptor to the list of existing ones, return the pointer 
 * to the new bytestream descriptor.
 */
static csbytestream_t *
new_bytestream(csmsg_t *in)
{
    csbytestream_t *bs; 

    bs = como_new0(csbytestream_t);
    bs->wfd = -1;
    bs->name = strdup(in->name);
    bs->size = 0; 
    bs->sizelimit = in->size; 
    bs->file_first = bs->file_last = NULL;
    
    if (get_fileinfo(bs, in->name, in->arg) != 0) {
	free(bs->name);
	free(bs);
	return NULL;
    }

    if (in->arg == CS_WRITER) {
	/*
	 * Writes imply O_APPEND and also they always 
	 * start from a fresh file. So we open an file
	 * that starts at the last offset of the bytestream. 
	 */
	csfile_t * cf; 
	off_t startofs; 

	startofs = (bs->file_first != NULL)? bs->file_first->bs_offset : 0;
	cf = new_csfile(bs, startofs + bs->size, (size_t)0);
	open_file(cf, CS_WRITER); 
    }

    return bs;
}

/**
 * -- new_id 
 * 
 * hook the client in the array of clients, and return a unique id
 * 
 * XXX to be optimized later
 * 
 */
static int
new_id(csclient_t * cl)
{
    int i;

    for (i = 0; i < CS_MAXCLIENTS; i++)
	if (s_como_st.clients[i] == NULL)
	    break;
    if (i == CS_MAXCLIENTS)
	error("too many clients, should not happen!!!\n");
    s_como_st.clients[i] = cl;
    s_como_st.client_count++;
    return i;
}


/** 
 * -- new_csclient
 * 
 * creates a client descriptor, hooks it to the bytestream and 
 * in the array of clients (which also creates the ID)
 *
 */
static csclient_t *
new_csclient(csbytestream_t *bs, int mode)
{
    csclient_t * cl;

    cl = como_new0(csclient_t);
    cl->bs = bs;
    cl->mode = mode;
    cl->timeout = CS_DEFAULT_TIMEOUT; 
    cl->id = new_id(cl);
    bs->client_count++;
    return cl;
}


/**
 * -- append_to_wb 
 *
 * appends a region to the bytestream write buffer.
 * the scheduler will take care of it later on.
 *
 */
static void
append_to_wb(csregion_t *r, csbytestream_t *bs)
{
    if (r == NULL) {
        warn("region pointer is NULL. append failed\n");
        return;
    }

    if (bs->wb_head == NULL) 
        bs->wb_head = r;
    else 
        bs->wb_tail->next = r;
    bs->wb_tail = r;
    r->next = NULL;
}


/**
 * -- flush_wb
 *
 * flushed the write buffer, closing and truncating
 * the files if necessary.
 * 
 */
static void
flush_wb(csbytestream_t *bs)
{
    assert_regionlist_acyclic(s_como_st.reg_freelist);

    while (bs->wb_head != NULL) { 
	csregion_t * wr;
	int ret;

	assert_regionlist_acyclic(bs->wb_head);

	wr = bs->wb_head; 
        if (wr->addr == NULL)
            error("region in write buffer with addr == NULL\n");

	ret = munmap(wr->addr, wr->reg_size);
	if (ret < 0)
	    error("flush_wb unsuccessful: %s\n", strerror(errno));

        if (wr->wfd != -1) {
            /*
             * the writer is gone, we are left with the
             * descriptor to do the final cleanup (close and truncate 
	     * the file to its actual size). 
             *
             * XXX we close the file and then use truncate() (instead of
             *     ftruncate()) because the file was opened with the
             *     O_APPEND flag on and this seems to cause trouble.
             *
             */
            char * nm;

	    assert(wr->file != NULL); 
            close(wr->wfd);
            asprintf(&nm, FILE_NAMEFMT, bs->name, wr->file->bs_offset);
            truncate(nm, wr->file->cf_size);
            free(nm);
        }

	bs->wb_head = wr->next;
	free_region(wr);
    }

    bs->wb_tail = NULL;
    assert_regionlist_acyclic(s_como_st.reg_freelist);
}


/**
 * -- handle_open 
 * 
 * On the first request for a bytestream, compile a list of files.
 * Then do a bit of error checking, and hook the client to the
 * relevant file.
 * 
 */
static int
handle_open(ipc_peer_t * sender, csmsg_t * in,
	    UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    csbytestream_t *bs; 
    csclient_t *cl;
    off_t ofs_ack;

    debug("in: OPEN [%s] %s\n", in->name,
	    in->arg == CS_WRITER ? "CS_WRITER" : "CS_READER"); 

    /* 
     * first check if we have too many active clients. 
     */
    if (s_como_st.client_count == CS_MAXCLIENTS) { 
	warn("too many clients (%d)\n", s_como_st.client_count); 
	senderr(sender, in->id, EMFILE);
	return IPC_CLOSE;
    }
      
    /*
     * browse the list of open bytestreams to check if this one
     * is already open (likely the case when the
     * QUERY process asks for opening a bytestream). in that case 
     * we just add a client.
     */ 
    for (bs = s_como_st.bs; bs; bs = bs->next) {
	if (strcmp(bs->name, in->name) == 0) { 	/* found it */
	    msg("file [%s] found, clients %d, wfd %d\n", 
		   in->name, bs->client_count, bs->wfd); 
	    break;
        } 
    }

    if (bs == NULL) {	/* not found */
	bs = new_bytestream(in);
	if (bs == NULL) { 
	    warn("cannot allocate bytestream [%s]\n", in->name); 
	    senderr(sender, in->id, EMFILE);
	    return IPC_CLOSE; 
	}
	bs->next = s_como_st.bs;
	s_como_st.bs = bs;
    }

    /* 
     * if opened in write mode, fail if there is already a writer 
     */
    if (in->arg == CS_WRITER && bs->the_writer != NULL) {
	warn("two writers not allowed [%s]\n", in->name); 
	senderr(sender, in->id, EPERM);
	return IPC_CLOSE;
    }

    /*
     * create a client descriptor, hook it to the first or last file
     * depending on the mode (CS_READER or CS_WRITER respectively).
     * The id for the new client is generated in new_csclient();
     */
    cl = new_csclient(bs, in->arg);
    msg("new client for [%s], id %d\n", in->name, cl->id);

    /* 
     * if this is a writer, link it to the bytestream, 
     * flush the existing write buffer and update the 
     * offset for the acknowledgement. 
     */ 
    if (in->arg == CS_WRITER) {
	csfile_t * cf; 

	flush_wb(bs);
	bs->the_writer = cl;
	bs->sizelimit = in->size;
	cf = bs->file_last; 
	ofs_ack = cf? cf->bs_offset + cf->cf_size : 0; 
    } else { 
	if (bs->file_first == NULL)
	    ofs_ack = 0;
	else
	    ofs_ack = bs->file_first->bs_offset; 
    }

    /* send the ack */
    sendack(sender, cl->id, ofs_ack, 0); 
    return IPC_OK;
}


/**
 * -- client_unlink
 *
 * unlink the client from the parent csfile_t
 * unmapping the region.
 * Return the original pointer for use in CS_SEEK_FILE_NEXT;
 * XXX in the future we may want to keep them for 
 *     other clients and let the scheduler decide 
 *     when to munmap the regions.
 *
 */
static csfile_t *
client_unlink(csclient_t *cl)
{
    csfile_t *cf;
    csclient_t *prev, *x;

    cf = cl->file;
    if (cf == NULL)
        return NULL;

    /* remove ourselves from the list of clients interested in this file */
    for (prev = NULL, x = cf->clients; x != cl; prev = x, x = x->next)
        ;

    /* now cl is after prev, we unlink it */
    if (prev == NULL)       /* it was the head */
        cf->clients = x->next;
    else
        prev->next = x->next;

    if (cl->region != NULL) {
	if (cl->region->addr != NULL) 
	    munmap(cl->region->addr, cl->region->reg_size);
        free_region(cl->region);
        cl->region = NULL;
    }

    if (cf->clients == NULL) { 
	/* close the file descriptor if it is open */
	if (cf->rfd >= 0) { 
	    close(cf->rfd);  
	    cf->rfd = -1;
	} 
    } 

    cl->file = NULL;
    return cf;
}

/** 
 * -- handle_close 
 * 
 * destroys the client information. it does not close the 
 * bytestream because the scheduler is in charge of that 
 * (there may be pending write operations). 
 * moreover, this handler does not generate a reply to the
 * client because there is nothing to say.
 *
 * XXX this function does not signal to the scheduler if it 
 *     is the case to remove the bytestream. 
 *
 */
static int
handle_close(UNUSED ipc_peer_t * sender, csmsg_t * in,
	     UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    csbytestream_t * bs;
    csclient_t * cl;

    debug("CLOSE: %d %lld %d\n", in->id, in->ofs, in->size);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
	warn("close: invalid id (%d)\n", in->id); 
	return IPC_CLOSE;
    } 

    cl = s_como_st.clients[in->id];
    if (cl == NULL) { 
	warn("close: client does not exist (id: %d)\n", in->id); 
	return IPC_CLOSE; 
    } 

    /* remove client from array of clients */
    s_como_st.clients[in->id] = NULL;
    s_como_st.client_count--;
    bs = cl->bs;
    bs->client_count--;

    /*
     * If this client was a writer move its block to the write buffer,
     * otherwise move the reader block to the pending region list.
     */
    if (cl->mode == CS_WRITER) {

	/* 
	 * if the writer was actually doing something,
	 * record how much we actually used so that the 
	 * scheduler can truncate the file accordingly. 
	 * how much the writer used is explicitly specified 
	 * in the S_CLOSE message)
	 */
	if (cl->region) { 
	    off_t ofs = cl->region->bs_offset + in->ofs; 
	    csfile_t * cf = bs->file_last; 

	    /* update the file size to wake up readers */
	    cf->cf_size = ofs - cf->bs_offset; 
	    bs->size = ofs - bs->file_first->bs_offset;

	    /* 
	     * add this region to the write buffer and notify the 
	     * scheduler that it needs to close and truncate this file 
	     * by setting the wfd file descriptor value 
	     */
	    cl->region->wfd = bs->wfd;
	    cl->region->file = cf; /* XXX can be moved to new_csregion() */

	    append_to_wb(cl->region, bs);
	} else { 
	    /*
	     * this is a weird case. if the writer didn't have 
	     * any active region it means it hasn't done anything since
	     * the open. close the file but check if there is anything 
	     * in the write buffer. if so we panic. really weird!. 
	     */ 
	    if (bs->wb_head != NULL) 
		error("write buffer not empty but writer is inactive\n"); 
	    close(bs->wfd);
	} 

	msg("writer removed (bytestream: %x %s)", bs, bs->name);
	bs->wfd = -1;
	bs->the_writer = NULL;
	free(cl);
	return IPC_CLOSE; /* done! */
    } 

    /* 
     * just a reader. unlink the client from the 
     * file descriptor and free the client descriptor.  
     */ 
    client_unlink(cl);
    free(cl);
    return IPC_CLOSE;
}
    

/**
 * -- block_client
 * 
 * Clients issued a blocking request. This can only happen on 
 * the last file. link this client to the blocked list of the 
 * bytestream, and save the request in the client information. 
 * 
 */
static void
block_client(csclient_t *cl, csmsg_t *in, ipc_peer_t * s)
{ 
    csbytestream_t * bs; 
    csblocked_t * p; 

    /* remove this client from the file list. 
     * XXX we have to do this because we don't really know 
     *     what file this client will be linked once its 
     *     requested offset will be reached 
     */
    client_unlink(cl); 
    cl->blocked = 1; 

    /* create a new blocked element */
    p = como_new0(csblocked_t);
    p->client = cl; 
    p->msg = *in; 
    p->peer = s; 

    /* link this client to the list of blocked clients */
    bs = cl->bs; 
    p->next = bs->blocked; 
    bs->blocked = p;
   
    msg("client %d blocked on ofs: %12lld, sz: %8d\n", 
	in->id, in->ofs, in->size); 
}


/*
 * -- handle_seek
 * 
 * S_SEEK messages are used to navigate the files of a 
 * bytestream. It supports moving one file forward or backward. 
 * Writers cannot seek. Moving after the last file or moving to 
 * an empty file (because the writer has not yet committed the 
 * latest writes) causes an ENODATA error. This is necessary to 
 * avoid the reader to receive an error message later or to block. 
 *
 */
static int
handle_seek(ipc_peer_t * sender, csmsg_t * in,
	    UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    csfile_t * cf;
    csclient_t * cl;

    debug("seek: id %d, arg %d, ofs %lld\n", 
	   in->id, in->arg, in->ofs);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
	warn("close: invalid id (%d)\n", in->id); 
        senderr(sender, in->id, EINVAL);
	return IPC_CLOSE;
    } 

    cl = s_como_st.clients[in->id];
    if (cl == NULL) { 
	warn("seek: client does not exist (id: %d)\n", in->id); 
        senderr(sender, in->id, EINVAL);
	return IPC_CLOSE;
    } 
    if (cl->mode == CS_WRITER) {
	warn("seek: writers should not seek (id: %d)\n", in->id); 
        senderr(sender, in->id, EINVAL);
	return IPC_CLOSE;
    }
    cf = client_unlink(cl);
    cl->timeout = CS_DEFAULT_TIMEOUT; 

    switch (in->arg) {	/* determine where to seek */
    default:
	warn("invalid argument %d\n", in->arg);
	return IPC_CLOSE;
	break;

    case CS_SEEK_FILE_NEXT:
	if (cf == NULL) /* never did a map or seek, get the first file */
	    cf = cl->bs->file_first;
	else
	    cf = cf->next;
	break;

    case CS_SEEK_FILE_PREV:
	if (cf == NULL) { 
	    /* never did a map or seek, get the last file */
	    cf = cl->bs->file_last;
	} else { 
	    csfile_t *p, *q;

	    /* find the file before the current one */
	    p = NULL;
	    q = cl->bs->file_first;
	    while (q && q != cf) {
		p = q; 
		q = q->next;
	    }
	    cf = p; 
	} 
	break;
    }

    if (cf == NULL) { 
	/* we have gone beyond the bytestream size */
	msg("id: %d,%s; seek reached the end of file\n", 
	    in->id, cl->bs->name); 
	senderr(sender, in->id, ENODATA);
	return IPC_OK;
    }

    /* append this client to the list of clients */
    cl->file = cf;
    cl->next = cf->clients;
    cf->clients = cl;
    open_file(cl->file, cl->mode);
    sendack(sender, in->id, cf->bs_offset, in->size);
    return IPC_OK;
}

/** 
 * -- region_read
 * 
 * handles all read operations. it may result in mmapping a new 
 * region, returning EOF or blocking the client to wait for new 
 * data from the writer. 
 *
 */ 
static int
region_read(ipc_peer_t * sender, csmsg_t * in, csclient_t *cl)
{
    csbytestream_t *bs;
    csfile_t *cf;
    int diff;

    /* 
     * we verify if the request can be satisfied looking
     * into the cumulative file (to make sure we have the requested 
     * block somewhere), the current client file (to see if we need to 
     * close the current file), and the current region (to see if we 
     * have already prefetched the requested region). 
     * 
     * the operation can result in closing the current file, 
     * opening a new one and mmapping a block.   
     * 
     * We have the following possible cases:
     *
     *		DATA	WRITER		WHERE		result
     *		-------------------------------------------------
     *		no	no		*		EOF
     *		no	yes		*		PANIC
     * (these two are easy to handle). Afterwards:
     *
     *		yes	no		before		ENODATA
     *		yes	yes		before		ENODATA
     *		yes	no		in		ok
     *		yes	yes		in		ok
     *		yes	no		after		EOF
     *		yes	yes		after		wait
     *  
     */

    bs = cl->bs;

    /* check the first two easy cases */
    if (bs->file_first == NULL) {	/* no files... */
	if (bs->the_writer != NULL)
	    error("impossible case in region_read\n");

	/* send an EOF */
	sendack(sender, in->id, (off_t)0, (size_t)0); 
	return IPC_OK;
    } 

    /* 
     * we have files, check request against available data 
     */
    if (in->ofs < bs->file_first->bs_offset) {
	/* before first byte */
	msg("id: %d, %s no data available\n", in->id, bs->name);
	senderr(sender, in->id, ENODATA); 
	return IPC_OK; 
    } else if (in->ofs >= bs->file_first->bs_offset + bs->size) { 
	/* 
	 * After current data; if a writer exists, wait for new data;
	 * otherwise return an ACK with size 0 to indicate end of file. 
	 */
	debug(
	    "S_REGION: bs %x (%s) want ofs %lld have ofs %lld writer %x\n",
	    bs, bs->name, in->ofs, 
	    bs->file_first->bs_offset + bs->size, bs->the_writer);

	if (bs->the_writer == NULL || cl->mode == CS_READER_NOBLOCK)
	    sendack(sender, in->id, (off_t)0, (size_t)0); 
	else 
	    block_client(cl, in, sender);
	return IPC_OK; 
    } 

    /*
     * We surely have the requested region, and need not to block.
     * Just figure out which file should we get.
     */

    /*
     * unmap the current region if any.
     * we do it here because it is open READ_ONLY so 
     * it won't touch the disk. 
     */
    if (cl->region != NULL) {
	munmap(cl->region->addr, cl->region->reg_size);
	free_region(cl->region);
	cl->region = NULL;
    }

    /* 
     * if we are linked to a file, see if we need to change file 
     */
    if (cl->file != NULL) {
	if (in->ofs < cl->file->bs_offset ||
		in->ofs >= cl->file->bs_offset + cl->file->cf_size) {
	    /* unlink from this file */
	    client_unlink(cl);
	}
    }

    /* 
     * if we are not linked to a file (or just got unlinked) 
     * scan the list of files to find the right one for us 
     */
    if (cl->file == NULL) {
	for (cf = cl->bs->file_first; cf ; cf = cf->next)
	    if (in->ofs < cf->bs_offset + cf->cf_size)
		break;
	if (cf == NULL)
	    error("region not found for file %s off 0x%lld\n",
		cl->bs->name, in->ofs);

	/* found! append this client to the list of clients */
	cl->file = cf;
	cl->next = cf->clients;
	cf->clients = cl;
	open_file(cl->file, cl->mode);
    }

    cf = cl->file;

    /* 
     * check if we have enough byte to satisfy the request, 
     * otherwise adapt the requested size. 
     */
    if (in->ofs + in->size > cf->bs_offset + cf->cf_size) 
	in->size = cf->bs_offset + cf->cf_size - in->ofs; 


    /* now do the mmap. before doing so align the offset to 
     * the page size and adjust the size of the region accordingly.
     * we just 
     * 
     * NOTE: this is needed for Linux but FreeBSD seems to work 
     *       fine even with not-page-aligned offsets.
     */
    diff = (in->ofs - cf->bs_offset) % getpagesize(); 
    in->ofs -= diff; 
    cl->region = new_csregion(in->ofs, in->size + diff);

    cl->region->addr = mmap(0, in->size + diff, PROT_READ,
	MAP_SHARED, cf->rfd, in->ofs - cf->bs_offset);
    if (cl->region->addr == MAP_FAILED || cl->region->addr == NULL)
	error("mmap got NULL (%s)\n", strerror(errno));  

    /* acknowledge the request (cf->bs_offset really tells the file name!) */
    sendack(sender, in->id, cf->bs_offset, in->size);
    return IPC_OK;
}


/**
 * -- wakeup_clients
 *
 * the writer has committed more bytes in the bytestream. we
 * can go thru the entire list of blocked readers and wake all of
 * them up. to do that we just replay the S_REGION request.
 *        
 */ 
static void
wakeup_clients(csbytestream_t *bs)
{
    csblocked_t *waking;
    
    debug("waking up all clients (%x)\n", bs);

    /* remove the list from the bytestream. we are waking up
     * all clients but some of them may need to block again
     * (if the writer didn't reach their offset). so we need
     * to differentiate between newly blocked clients and old
     * ones.
     */
    waking = bs->blocked;
    bs->blocked = NULL;
        
    while (waking != NULL) {   
        csblocked_t *p = waking;
  
	debug("waking up id: %d\n", p->client->id); 
	p->client->blocked = 0; 
	p->client->timeout = CS_DEFAULT_TIMEOUT; 
        region_read(p->peer, &p->msg, p->client);
        
        /* free this element and move to next */
        waking = p->next;
        free(p);
    }
}


/**  
 * -- region_write
 *
 * handles all write operations, i.e. mmaps the region of
 * interest and resizes the file if needed. also, wakes up all
 * readers that were waiting for new data.
 *   
 */         
static int
region_write(ipc_peer_t * sender, csmsg_t * in, csclient_t *cl)   
{
    off_t bs_offset, want, have;
    size_t reg_size;
    csbytestream_t *bs; 
    csfile_t *cf;
    int diff;
     
    /*
     * the writer is always operating on the last
     * file of bytestream. if there are no files, create
     * one.
     */
    bs = cl->bs; 
    cf = bs->file_last;
    assert(cf != NULL); 

    /*
     * validate the parameters -- the new in->ofs must be within
     * or just after the current region (if any).
     */
    if (cl->region != NULL) {
        /* use mapped region */
        bs_offset = cl->region->bs_offset;
        reg_size = cl->region->reg_size;
    } else {
        /* use last file */
        bs_offset = cf->bs_offset + cf->cf_size;
        reg_size = 0;
    }
                
    /* overwriting is not allowed */
    if (in->ofs < bs_offset) {
	warn("id: %d, %s; overwriting not allowed\n", 
	    in->id, bs->name); 
        senderr(sender, in->id, EINVAL);
        return IPC_CLOSE;
    }
        
    /* gaps are not allowed */
    if (in->ofs > bs_offset + reg_size) {
	warn("id: %d, %s; gaps not allowed\n", in->id, bs->name); 
        senderr(sender, in->id, EINVAL);
        return IPC_CLOSE;
    }
            
    /*   
     * valid request. first of all commit the writes
     * done so far. this way we will be able to wake up
     * some blocked readers.
     */
    cf->cf_size = in->ofs - cf->bs_offset;
    bs->size = in->ofs - bs->file_first->bs_offset; 

    /*
     * append the current region to the write buffer (the scheduler
     * will take care of that). then, get a new region, add it to
     * the head of the list and mmap the region of file requested.
     */
    if (cl->region != NULL) 
	append_to_wb(cl->region, bs);

    /*
     * now check if we need to increase the OS file size beyond the
     * point already reached by the writer (the readers are stuck
     * at cf->offset + cf->size == cl->region->offset)
     */
    want = in->ofs + in->size; 
    have = bs_offset + reg_size;        /* actual data on disk */
    if (want > have) {
        size_t ext;     /* the extra data to write */
        char * buf;
 
        ext = want - have;
     
        /*
         * Extend the file if possible, or truncate it
         * (at cf->cf_size) and open a new one if we are
         * exceeding the limit (s_como_st.maxfilesize).
         */
        if (want - cf->bs_offset > s_como_st.maxfilesize) {
            /*
             * if the writer was active, append the region to
             * the write buffer and prepare the region so that
             * the scheduler can do the cleanup later on.
             */
            if (cl->region != NULL) {
                /* 
		 * store the OS fd in the region so that the 
		 * scheduler can close the file while the bytestream
		 * keeps only the OS fd of the current file. 
		 */
		cl->region->file = cf; 
                cl->region->wfd = bs->wfd;
		append_to_wb(cl->region, bs);
                bs->wfd = -1; /* we will need a new one */
            }

	    /* update the size of the current file */
	    cf->cf_size = in->ofs - cf->bs_offset; 

            /*
             * now create a descriptor for the new file and create
             * it empty so we can extend it afterwards
             */
            cf = new_csfile(bs, in->ofs, (size_t)0);
            open_file(cf, CS_WRITER); /* XXX error checking */
            ext = in->size;
        }

        /* finally, prepare to extend the file */
        buf = como_calloc(1, ext);
        if (write(bs->wfd, buf, ext) < 0) {
	    free(buf);
            warn("id: %d,%s; write to extend file failed: %s\n",
                in->id, bs->name, strerror(errno));
            senderr(sender, in->id, errno);
            return IPC_OK;
        }
        free(buf);
    }


    /* now do the mmap. before doing so align the offset to
     * the page size and adjust the size of the region accordingly.
     * we just
     *
     * NOTE: this is needed for Linux but FreeBSD seems to work
     *       fine even with not-page-aligned offsets.
     */
    diff = (in->ofs - cf->bs_offset) % getpagesize();
    in->ofs -= diff; 
    cl->region = new_csregion(in->ofs, in->size + diff);

    cl->region->addr = mmap(0, in->size + diff, PROT_WRITE,
        MAP_NOSYNC|MAP_SHARED, cl->bs->wfd, in->ofs - cf->bs_offset);
    if (cl->region->addr == MAP_FAILED || cl->region->addr == NULL)
        error("mmap got NULL (%s)\n", strerror(errno));

    /*
     * acknowledge the request sending back the size
     * of the block. The offset is always the beginning of the file
     * so the client knows whether or not it has to open a different
     * file.
     */
    sendack(sender, in->id, cf->bs_offset, in->size);

    /* done! now wakeup blocked clients (if any) */
    wakeup_clients(cl->bs);

    return IPC_OK;
}


/* 
 * -- handle_inform
 * 
 * this function results in updating the bytestream and file information
 * so that blocked readers can be woken up. The client is the writer and 
 * it is already moving on to write more. No acknowledgement is necessary. 
 * 
 */
static int
handle_inform(UNUSED ipc_peer_t * sender, csmsg_t * in,
	    UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    csclient_t * cl;
    off_t bs_offset; 
    size_t reg_size;
    csfile_t *cf;

    debug("INFORM: %d %lld\n", in->id, in->ofs);
 
    assert(in->id >= 0 && in->id < CS_MAXCLIENTS);

    cl = s_como_st.clients[in->id];
    assert(cl != NULL);
    assert(cl->mode == CS_WRITER);
    cl->timeout = CS_DEFAULT_TIMEOUT; 

    /*
     * the writer is always operating on the last file of bytestream. 
     */
    cf = cl->bs->file_last;
    assert(cf != NULL);

    /*
     * validate the parameters -- the new in->ofs must be within
     * the current region. 
     */
    assert(cl->region != NULL); 
    bs_offset = cl->region->bs_offset;
    reg_size = cl->region->reg_size;

    /* overwriting and gaps are not allowed */
    assert(in->ofs >= bs_offset && in->ofs <= bs_offset + reg_size); 

    /*  
     * valid request. commit the writes done so far. this way we 
     * will be able to wake up some blocked readers.
     */
    cf->cf_size = in->ofs - cf->bs_offset;
    cl->bs->size = in->ofs - cl->bs->file_first->bs_offset;

    /* done! now wakeup blocked clients (if any) */
    wakeup_clients(cl->bs);
    return IPC_OK;
}
   

/** 
 * -- handle_region
 *
 * runs some error checking on the incoming message
 * and then calls the relevant function (depending if
 * this is a read or write operation) 
 *
 */
static int
handle_region(ipc_peer_t * sender, csmsg_t * in,
	      UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    csclient_t * cl;

    debug("S_REGION: id %d; ofs %12lld; size %7d;\n", 
	in->id, in->ofs, in->size);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
        warn("S_REGION: invalid id (%d)\n", in->id);
	senderr(sender, in->id, EINVAL);
        return IPC_CLOSE;
    }
        
    cl = s_como_st.clients[in->id];
    if (cl == NULL) {
        warn("S_REGION: client does not exists (id: %d)\n", in->id);
	senderr(sender, in->id, EBADF);
        return IPC_CLOSE;
    }

    /* one can read/write at most maxfragmentsize bytes */
    if (in->size > s_como_st.maxfilesize)  {
	warn("S_REGION size %ld too large, using %ld\n",
	    (int)(in->size), (int)s_como_st.maxfilesize); 
	in->size = s_como_st.maxfilesize;
    }

    /* 
     * we consider the read/write mode separately. 
     */ 
    cl->timeout = CS_DEFAULT_TIMEOUT; 
    if (cl->mode == CS_WRITER)  	/* write mode */
	return region_write(sender, in, cl);
    else
	return region_read(sender, in, cl);
}

/*
 * -- scheduler 
 *
 * The scheduler is in charge of maintaining the bytestreams.
 * It unmaps the blocks that are not needed anymore, closes the 
 * bytestreams that have no clients and keeps the bytestream below
 * its sizelimit taking care of deleting old files (if no active clients
 * exists for them).
 * 
 * XXX this function is only partially implemented. it only takes
 *     care of unmapping blocks and keeping the bytestream below the 
 *     size limit. in the future it should also prefetch pages for the 
 *     readers and manage efficiently the disk bandwidth across all 
 *     bytestreams. 
 *
 */
static void
scheduler(timestamp_t elapsed)
{
    csbytestream_t * bs; 
    int i; 
             
    /*
     * browse the list of bytestreams and clean up the data 
     * structures, emptying the write buffer and keeping the 
     * overall stream size below the limit. 
     */   
    bs = s_como_st.bs; 
    while (bs != NULL) { 

	/* flush the write buffer */
      	flush_wb(bs); 

        /*
	 * make sure the stream does not exceed the limit. 
	 * if so, delete the first file unless there is 
	 * a reader attached to it. 
	 * 
	 * we do this only if there is an active writer. 
	 */
	if (bs->the_writer && bs->size > bs->sizelimit) { 
	    csfile_t * cf; 

	    cf = bs->file_first; 
	    if (cf->clients == NULL) {
		delete_csfile(cf);
	    } else if (bs->size > bs->sizelimit * 12 / 10) { 
		csclient_t * cl;

		warn("file %s exceeding limit by 20%%\n", bs->name); 

		/* remove all clients accessing this file */
		for (cl = cf->clients; cf->clients; cl = cf->clients)
		    client_unlink(cl); 
		delete_csfile(cf);
	    } 
	}

	/* 
	 * now close the bytestream if there are no 
	 * clients 
	 */
        if (bs->client_count == 0) { 
	    csfile_t * cf; 
	    csbytestream_t *p, *q; 

	    /* close all files */
	    while (bs->file_first) {
		cf = bs->file_first;
		bs->file_first = cf->next;

		if (cf->rfd >= 0) 
		    close(cf->rfd); 
		free(cf);
	    } 
	    
	    /* remove the bytestream from the list */
	    for (p = NULL, q = s_como_st.bs; q != bs; p = q, q = q->next)
		; 
	    if (p == NULL)  
		s_como_st.bs = bs->next; 
	    else 
		p->next = bs->next; 
	    bs = bs->next;
	    free(q);
	    continue; 
        }

	bs = bs->next; 
    }

    /* now browse the list of clients and remove all the readers 
     * that are not blocked and for which the timeout expired. 
     * this is to catch all QUERY processes that died before being 
     * able to send a S_CLOSE message. 
     */
    for (i = 0; i < s_como_st.client_count; i++) { 
	csclient_t * cl = s_como_st.clients[i]; 

	if (cl == NULL || cl->mode == CS_WRITER || cl->blocked) 
	    continue; 

	if (cl->timeout < elapsed) {
	    /* remove this client and recover the record */
	    client_unlink(cl); 
    
	    /* remove this client from the bytestream */
	    bs = cl->bs;
	    bs->client_count--;

	    /* remove client from array of clients */
	    s_como_st.clients[cl->id] = NULL;
	    s_como_st.client_count--;

	    free(cl);

	    warn( 
		"client timeout. file %s, clients %d, total %d\n", 	
		bs->name, bs->client_count, s_como_st.client_count); 
	} 

	cl->timeout -= elapsed; 
    }
}


/*
 * -- handle_shutdown 
 *
 */
static int
handle_shutdown(UNUSED ipc_peer_t * sender, UNUSED void * buf,
		UNUSED size_t len, UNUSED int swap, UNUSED void * user_data)
{
    /* TODO: cleanup! */
    exit(EXIT_SUCCESS);
    return IPC_OK;
}


/*
 * This is the mainloop of the storage-server process. It waits on a select
 * for a message on any of the open socket and then performs the 
 * action requested by the clients (e.g., release or request a block). 
 */
static void
como_st_run()
{
    struct timeval to = { 5, 200000 };	// XXX just to put something?


    /* register handlers for IPC messages */
    ipc_register(S_CLOSE, (ipc_handler_fn) handle_close);
    ipc_register(S_OPEN, (ipc_handler_fn) handle_open);
    ipc_register(S_REGION, (ipc_handler_fn) handle_region);
    ipc_register(S_SEEK, (ipc_handler_fn) handle_seek);
    ipc_register(S_INFORM, (ipc_handler_fn) handle_inform);

    event_loop_add(&s_como_st.el, s_como_st.accept_fd);
    
    ipc_register(SU_ANY_EXIT, handle_shutdown);
    

    /* listen to SUPERVISOR */
    event_loop_add(&s_como_st.el, s_como_st.supervisor_fd);

    /*
     * The real main loop.
     */
    for (;;) {
        fd_set r;
	struct timeval last; 

	timestamp_t elapsed; 
        int n_ready;
	int i;
	int ipcr;

	/*
	 * use a timeout if we have files open. this way the 
	 * scheduler starts when clients are idle too.
	 */
        if (s_como_st.client_count > 0) {
	    event_loop_set_timeout(&s_como_st.el, &to);
        }

	gettimeofday(&last, 0);
	
	n_ready = event_loop_select(&s_como_st.el, &r);
	if (n_ready < 0) {
		continue;
	}

	for (i = 0; n_ready > 0 && i < s_como_st.el.max_fd; i++) {

	    if (!FD_ISSET(i, &r))
		continue;

	    n_ready--;

	    if (i == s_como_st.accept_fd) {
		int x = accept(i, NULL, NULL);
		if (x < 0) {
		    warn("Failed on accept(): %s\n", strerror(errno));
		} else {
 		    event_loop_add(&s_como_st.el, x);
		}
		continue;
	    }
	    
	    ipcr = ipc_handle(i);
	    switch (ipcr) {
	    case IPC_ERR:
		/* an error. close the socket */
		warn("error on IPC handle from %d\n", i);
	    case IPC_EOF:
	    case IPC_CLOSE:
		close(i);
		event_loop_del(&s_como_st.el, i);
		break;
	    }
        }       

	/* 
	 * run the scheduler to clean up the files, decide
	 * the blocks to be pre-fetched and then prefetch 
	 * pages into memory. 
	 */
	if (s_como_st.client_count > 0) {
	    struct timeval now; 

	    gettimeofday(&now, 0); 
	    elapsed = TIME2TS(now.tv_sec, now.tv_usec) - 
		      TIME2TS(last.tv_sec, last.tv_usec); 
	    scheduler(elapsed); 
	}
    }
} 

/* 
 * -- storage_mainloop 
 * 
 *
 */
int
main(int argc, char ** argv)
{
    char *location;
    uint64_t maxfilesize;

    if (argc != 4) {
        fprintf(stderr, "usage: %s su_location maxfilesize running_inline\n",
            argv[0]);
	exit(EXIT_FAILURE);
    }
    if (argv[1][0] != '/') {
        fprintf(stderr, "invalid su_location `%s'\n", argv[1]);
	exit(EXIT_FAILURE);
    }

    maxfilesize = strtoll(argv[2], NULL, 0);
    if (maxfilesize == 0) {
        fprintf(stderr, "invalid maxfilesize `%lld'\n", maxfilesize);
	exit(EXIT_FAILURE);
    }

    location = como_strdup(argv[1]);
    como_init("ST", argc, argv);

    if (atoi(argv[3])) /* inline mode */
        log_set_level(LOG_LEVEL_ERROR); /* be silent */

    setproctitle("STORAGE");

    /* init data structures */
    memset(&s_como_st, 0, sizeof(s_como_st));
    s_como_st.accept_fd = -1;
    s_como_st.maxfilesize = maxfilesize;
    
    /* initialize IPC */
    ipc_init(ipc_peer_at(COMO_ST, location), NULL, &s_como_st);
    s_como_st.accept_fd = ipc_listen();

    /* connect to SU - we are ready to handle connections */
    s_como_st.supervisor_fd = ipc_connect(COMO_SU);

    /* if needed, wait for debugger */
    DEBUGGER_WAIT_ATTACH("st");
    
    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    /* ignore SIGHUP */ 
    signal(SIGHUP, SIG_IGN); 

    /* run */
    como_st_run();
    
    exit(EXIT_SUCCESS);
}

/* end of file */
