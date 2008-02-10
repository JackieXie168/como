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

#include "como.h"
#include "comopriv.h"
#define _COMO_STORAGE_SERVER  /* enables private types in storage.h */
#include "storage.h"
#include "ipc.h"


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
 * state variables 
 */
extern struct _como map;		/* global state */
static struct _cs_state cs_state;


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
	    panic("writebuffer cyclic");
	ptr2 = ptr2->next;
	ptr1 = ptr1->next;
    }
}

static void
assert_region_not_in_list(csregion_t *blk, csregion_t *list)
{
    while (list != NULL) {
	if (blk == list)
	    panic("region unexpectedly in list");
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

    blk = cs_state.reg_freelist;
    if (blk == NULL)
	blk = safe_calloc(1, sizeof(csregion_t));
    else 
	cs_state.reg_freelist = blk->next;
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
    assert_region_not_in_list(blk, cs_state.reg_freelist);
    assert_regionlist_acyclic(cs_state.reg_freelist);
    blk->next = cs_state.reg_freelist;
    cs_state.reg_freelist = blk;
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

    cf = safe_calloc(1, sizeof(csfile_t));
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
	panicx("reducing bytestream %s to zero size", bs->name); 

    if (cf->rfd >= 0)
	close(cf->rfd); 

    asprintf(&nm, FILE_NAMEFMT, bs->name, cf->bs_offset); 
    unlink(nm);
    free(nm);

    logmsg(V_LOGSTORAGE, "resizing bytestream %s (from %lld to %lld)\n", 
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

    logmsg(V_LOGSTORAGE, "open_file %016llx mode %s rfd %d wfd %d\n",
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
        panic("opening file %s: %s\n", name, strerror(errno));
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

    logmsg(V_LOGSTORAGE, "getting meta information for %s\n", name); 

    /* open the directory to see if it is there */
    d = opendir(name);
    if (d == NULL) {
        /*
         * The directory is not there (XXX or it is too big...).
         * If in read mode return an error. In write mode, we 
	 * assume O_CREAT by default so we create it empty.
         */
	if (mode != CS_WRITER) { 
	    logmsg(LOGWARN, "get_fileinfo: file %s does not exist\n", name); 
	    return EINVAL; 
	} 
	ret = mkdir(name, (mode_t) (S_IRWXU | S_IRWXG | S_IRWXO));
	if (ret < 0) { 
	    logmsg(LOGWARN, 
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

    logmsg(V_LOGSTORAGE, "bytestream %s size %lld\n", bs->name, bs->size); 
    return 0;
} 


/**
 * -- senderr
 *
 * sends an error message. 
 *
 */
static void
senderr(procname_t who, int id, int code)
{
    csmsg_t m;

    memset(&m, 0, sizeof(m));
    if (code == 0)
	panic("storage failing a request without giving a reason");
    m.id = id;
    m.arg = code;
    if (ipc_send(who, IPC_ERROR, &m, sizeof(m)) != IPC_OK) {
	panic("sending error message: %s\n", strerror(errno));
    }

    logmsg(LOGSTORAGE, "out: ERROR - id: %d; code: %d;\n", id, code);
}


/**
 * -- sendack
 *
 * sends an acknowledgement 
 *
 */
static void
sendack(procname_t who, int id, off_t ofs, size_t sz)
{
    csmsg_t m;

    memset(&m, 0, sizeof(m));
    m.id = id;
    m.ofs = ofs;
    m.size = sz;
    if (ipc_send(who, IPC_ACK, &m, sizeof(m)) != IPC_OK) {
	panic("sending ack: %s\n", strerror(errno));
    }

    logmsg(V_LOGSTORAGE, "out: ACK - id: %d, ofs: %12lld, sz: %8d\n",
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

    bs = safe_calloc(1, sizeof(csbytestream_t));
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
	if (cs_state.clients[i] == NULL)
	    break;
    if (i == CS_MAXCLIENTS)
	panic("too many clients, should not happen!!!\n");
    cs_state.clients[i] = cl;
    cs_state.client_count++;
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

    cl = safe_calloc(1, sizeof(csclient_t));
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
        logmsg(LOGWARN, "region pointer is NULL. append failed\n");
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
    assert_regionlist_acyclic(cs_state.reg_freelist);

    while (bs->wb_head != NULL) { 
	csregion_t * wr;
	int ret;

	assert_regionlist_acyclic(bs->wb_head);

	wr = bs->wb_head; 
        if (wr->addr == NULL)
            panic("region in write buffer with addr == NULL\n");

	ret = munmap(wr->addr, wr->reg_size);
	if (ret < 0)
	    panic("flush_wb unsuccessful: %s\n", strerror(errno));

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
    assert_regionlist_acyclic(cs_state.reg_freelist);
}


/**
 * -- handle_open 
 * 
 * On the first request for a bytestream, compile a list of files.
 * Then do a bit of error checking, and hook the client to the
 * relevant file.
 * 
 */
static void
handle_open(procname_t s, csmsg_t * in,
	    __attribute__((__unused__)) size_t len)
{
    csbytestream_t *bs; 
    csclient_t *cl;
    off_t ofs_ack;

    logmsg(V_LOGSTORAGE, "in: OPEN [%s] %s\n", in->name,
	    in->arg == CS_WRITER ? "CS_WRITER" : "CS_READER"); 

    /* 
     * first check if we have too many active clients. 
     */
    if (cs_state.client_count == CS_MAXCLIENTS) { 
	logmsg(LOGWARN, "too many clients (%d)\n", cs_state.client_count); 
	senderr(s, in->id, EMFILE);
	return; 
    }
      
    /*
     * browse the list of open bytestreams to check if this one
     * is already open (likely the case when the
     * QUERY process asks for opening a bytestream). in that case 
     * we just add a client.
     */ 
    for (bs = cs_state.bs; bs; bs = bs->next) {
	if (strcmp(bs->name, in->name) == 0) { 	/* found it */
	    logmsg(LOGSTORAGE, "file [%s] found, clients %d, wfd %d\n", 
		   in->name, bs->client_count, bs->wfd); 
	    break;
        } 
    }

    if (bs == NULL) {	/* not found */
	bs = new_bytestream(in);
	if (bs == NULL) { 
	    logmsg(LOGWARN, "cannot allocate bytestream [%s]\n", in->name); 
	    senderr(s, in->id, EMFILE);
	    return; 
	}
	bs->next = cs_state.bs;
	cs_state.bs = bs;
    }

    /* 
     * if opened in write mode, fail if there is already a writer 
     */
    if (in->arg == CS_WRITER && bs->the_writer != NULL) {
	logmsg(LOGWARN, "two writers not allowed [%s]\n", in->name); 
	senderr(s, in->id, EPERM);
	return;
    }

    /*
     * create a client descriptor, hook it to the first or last file
     * depending on the mode (CS_READER or CS_WRITER respectively).
     * The id for the new client is generated in new_csclient();
     */
    cl = new_csclient(bs, in->arg);
    logmsg(LOGSTORAGE, "new client for [%s], id %d\n", in->name, cl->id);

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
    sendack(s, cl->id, ofs_ack, 0); 
    return;
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
    for (prev = NULL, x = cf->clients; x != cl; prev = x, x = x->next) ;

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
static void
handle_close(__attribute__((__unused__)) procname_t sender,
             csmsg_t * in, __attribute__((__unused__)) size_t len)
{
    csbytestream_t * bs;
    csclient_t * cl;

    logmsg(V_LOGSTORAGE, "CLOSE: %d %lld %d\n", in->id, in->ofs, in->size);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
	logmsg(LOGWARN, "close: invalid id (%d)\n", in->id); 
	return;
    } 

    cl = cs_state.clients[in->id];
    if (cl == NULL) { 
	logmsg(LOGWARN, "close: client does not exist (id: %d)\n", in->id); 
	return; 
    } 

    /* remove client from array of clients */
    cs_state.clients[in->id] = NULL;
    cs_state.client_count--;
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
		panic("write buffer not empty but writer is inactive\n"); 
	    close(bs->wfd);
	} 

	logmsg(LOGSTORAGE, "writer removed (bytestream: %x %s)", bs, bs->name);
	bs->wfd = -1;
	bs->the_writer = NULL;
	free(cl);
	return; /* done! */
    } 

    /* 
     * just a reader. unlink the client from the 
     * file descriptor and free the client descriptor.  
     */ 
    client_unlink(cl); 
    free(cl); 
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
block_client(csclient_t *cl, csmsg_t *in, int s)
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
    p = safe_calloc(1, sizeof(csblocked_t)); 
    p->client = cl; 
    p->msg = *in; 
    p->sock = s; 

    /* link this client to the list of blocked clients */
    bs = cl->bs; 
    p->next = bs->blocked; 
    bs->blocked = p;
   
    logmsg(LOGSTORAGE, "client %d blocked on ofs: %12lld, sz: %8d\n", 
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
static void
handle_seek(procname_t s, csmsg_t * in, __attribute__((__unused__)) size_t len)
{
    csfile_t * cf;
    csclient_t * cl;

    logmsg(V_LOGSTORAGE, "seek: id %d, arg %d, ofs %lld\n", 
	   in->id, in->arg, in->ofs);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
	logmsg(LOGWARN, "close: invalid id (%d)\n", in->id); 
        senderr(s, in->id, EINVAL);
	return;
    } 

    cl = cs_state.clients[in->id];
    if (cl == NULL) { 
	logmsg(LOGWARN, "seek: client does not exist (id: %d)\n", in->id); 
        senderr(s, in->id, EINVAL);
	return; 
    } 
    if (cl->mode == CS_WRITER) {
	logmsg(LOGWARN, "seek: writers should not seek (id: %d)\n", in->id); 
        senderr(s, in->id, EINVAL);
	return; 
    }
    cf = client_unlink(cl);
    cl->timeout = CS_DEFAULT_TIMEOUT; 

    switch (in->arg) {	/* determine where to seek */
    default:
	panic("invalid argument %d\n", in->arg);
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
	logmsg(LOGSTORAGE, "id: %d,%s; seek reached the end of file\n", 
	    in->id, cl->bs->name); 
	senderr(s, in->id, ENODATA); 
	return;
    }

    /* append this client to the list of clients */
    cl->file = cf;
    cl->next = cf->clients;
    cf->clients = cl;
    open_file(cl->file, cl->mode);
    sendack(s, in->id, cf->bs_offset, in->size);
}

/** 
 * -- region_read
 * 
 * handles all read operations. it may result in mmapping a new 
 * region, returning EOF or blocking the client to wait for new 
 * data from the writer. 
 *
 */ 
static void
region_read(procname_t s, csmsg_t * in, csclient_t *cl)
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
	    panicx("impossible case in region_read\n");

	/* send an EOF */
	sendack(s, in->id, (off_t)0, (size_t)0); 
	return;
    } 

    /* 
     * we have files, check request against available data 
     */
    if (in->ofs < bs->file_first->bs_offset) {	/* before first byte */
	logmsg(LOGSTORAGE, "id: %d, %s no data available\n", in->id, bs->name);
	senderr(s, in->id, ENODATA); 
	return; 
    } else if (in->ofs >= bs->file_first->bs_offset + bs->size) { 
	/* 
	 * After current data; if a writer exists, wait for new data;
	 * otherwise return an ACK with size 0 to indicate end of file. 
	 */
	logmsg(V_LOGSTORAGE, 
	    "S_REGION: bs %x (%s) want ofs %lld have ofs %lld writer %x\n",
	    bs, bs->name, in->ofs, 
	    bs->file_first->bs_offset + bs->size, bs->the_writer);

	if (bs->the_writer == NULL || cl->mode == CS_READER_NOBLOCK)
	    sendack(s, in->id, (off_t)0, (size_t)0); 
	else 
	    block_client(cl, in, s); 
	return; 
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
	    panic("region not found for file %s off 0x%lld\n",
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
	panic("mmap got NULL (%s)\n", strerror(errno));  

    /* acknowledge the request (cf->bs_offset really tells the file name!) */
    sendack(s, in->id, cf->bs_offset, in->size);
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
    
    logmsg(V_LOGSTORAGE, "waking up all clients (%x)\n", bs);

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
  
	logmsg(V_LOGSTORAGE, "waking up id: %d\n", p->client->id); 
	p->client->blocked = 0; 
	p->client->timeout = CS_DEFAULT_TIMEOUT; 
        region_read(p->sock, &p->msg, p->client);
        
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
static void
region_write(procname_t s, csmsg_t * in, csclient_t *cl)   
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
	logmsg(LOGSTORAGE, "id: %d, %s; overwriting not allowed\n", 
	    in->id, bs->name); 
        senderr(s, in->id, EINVAL);
        return;
    }
        
    /* gaps are not allowed */
    if (in->ofs > bs_offset + reg_size) {
	logmsg(LOGSTORAGE, "id: %d, %s; gaps not allowed\n", in->id, bs->name); 
        senderr(s, in->id, EINVAL);
        return;
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
         * exceeding the limit (map.maxfilesize).
         */
        if (want - cf->bs_offset > map.maxfilesize) {
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
        buf = safe_calloc(1, ext); 
        if (write(bs->wfd, buf, ext) < 0) {
            logmsg(LOGWARN, "id: %d,%s; write to extend file failed: %s\n",
                in->id, bs->name, strerror(errno));
            senderr(s, in->id, errno);
            return;
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
        panic("mmap got NULL (%s)\n", strerror(errno));

    /*
     * acknowledge the request sending back the size
     * of the block. The offset is always the beginning of the file
     * so the client knows whether or not it has to open a different
     * file.
     */
    sendack(s, in->id, cf->bs_offset, in->size);

    /* done! now wakeup blocked clients (if any) */
    wakeup_clients(cl->bs);

    return;
}


/* 
 * -- handle_inform
 * 
 * this function results in updating the bytestream and file information
 * so that blocked readers can be woken up. The client is the writer and 
 * it is already moving on to write more. No acknowledgement is necessary. 
 * 
 */
static void
handle_inform(__attribute__((__unused__)) procname_t sender,
              csmsg_t * in, __attribute__((__unused__)) size_t len)
{
    csclient_t * cl;
    off_t bs_offset; 
    size_t reg_size;
    csfile_t *cf;

    logmsg(V_LOGSTORAGE, "INFORM: %d %lld\n", in->id, in->ofs);
 
    assert(in->id >= 0 && in->id < CS_MAXCLIENTS);

    cl = cs_state.clients[in->id];
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
}
   

/** 
 * -- handle_region
 *
 * runs some error checking on the incoming message
 * and then calls the relevant function (depending if
 * this is a read or write operation) 
 *
 */
static void
handle_region(procname_t sender, csmsg_t * in, 
	      __attribute__((__unused__)) size_t len)
{
    csclient_t * cl;

    logmsg(V_LOGSTORAGE, "S_REGION: id %d; ofs %12lld; size %7d;\n", 
	in->id, in->ofs, in->size);

    if (in->id < 0 || in->id >= CS_MAXCLIENTS) {
        logmsg(LOGWARN, "S_REGION: invalid id (%d)\n", in->id);
	senderr(sender, in->id, EINVAL);
        return;
    }
        
    cl = cs_state.clients[in->id];
    if (cl == NULL) {
        logmsg(LOGWARN, "S_REGION: client does not exists (id: %d)\n", in->id);
	senderr(sender, in->id, EBADF);
        return;
    }

    /* one can read/write at most maxfragmentsize bytes */
    if (in->size > map.maxfilesize)  {
	logmsg(LOGWARN, "S_REGION size %ld too large, using %ld\n",
	    (int)(in->size), (int)map.maxfilesize); 
	in->size = map.maxfilesize;
    }

    /* 
     * we consider the read/write mode separately. 
     */ 
    cl->timeout = CS_DEFAULT_TIMEOUT; 
    if (cl->mode == CS_WRITER)  	/* write mode */
	region_write(sender, in, cl);
    else
	region_read(sender, in, cl);
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
    bs = cs_state.bs; 
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

		logmsg(LOGWARN, "file %s exceeding limit by 20%%\n", bs->name); 

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
	    for (p = NULL, q = cs_state.bs; q != bs; p = q, q = q->next)
		; 
	    if (p == NULL)  
		cs_state.bs = bs->next; 
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
    for (i = 0; i < cs_state.client_count; i++) { 
	csclient_t * cl = cs_state.clients[i]; 

	if (cl == NULL || cl->mode == CS_WRITER || cl->blocked) 
	    continue; 

	if (cl->timeout < elapsed) {
	    /* remove this client and recover the record */
	    client_unlink(cl); 
    
	    /* remove this client from the bytestream */
	    bs = cl->bs;
	    bs->client_count--;

	    /* remove client from array of clients */
	    cs_state.clients[cl->id] = NULL;
	    cs_state.client_count--;

	    free(cl);

	    logmsg(V_LOGWARN, 
		"client timeout. file %s, clients %d, total %d\n", 	
		bs->name, bs->client_count, cs_state.client_count); 
	} 

	cl->timeout -= elapsed; 
    }
}


/*
 * -- st_ipc_exit 
 *
 */
static void
st_ipc_exit(procname_t sender, __attribute__((__unused__)) void * buf,
             __attribute__((__unused__)) size_t len)
{
    assert(sender == map.parent);  
    exit(EXIT_SUCCESS); 
}


/* 
 * -- storage_mainloop 
 * 
 * This is the mainloop of the hf-server process. It waits on a select
 * for a message on any of the open socket and then performs the 
 * action requested by the clients (e.g., release or request a block). 
 * The input parameters are the memory allocated to the process for 
 * mapping open files, the descriptors of all the open sockets and their 
 * number. 
 *
 */
void
storage_mainloop(int accept_fd, int supervisor_fd,
                 __attribute__((__unused__)) int id)
{
    int max_fd; 
    fd_set valid_fds; 

    /* register file descriptors */ 
    max_fd = 0; 
    FD_ZERO(&valid_fds); 

    /* register handlers for signals */ 
    signal(SIGPIPE, exit); 
    signal(SIGINT, exit);
    signal(SIGTERM, exit);
    /* ignore SIGHUP */ 
    signal(SIGHUP, SIG_IGN); 
    
    /* register handlers for IPC messages */
    ipc_clear();
    ipc_register(S_CLOSE, (ipc_handler_fn) handle_close);
    ipc_register(S_OPEN, (ipc_handler_fn) handle_open);
    ipc_register(S_REGION, (ipc_handler_fn) handle_region);
    ipc_register(S_SEEK, (ipc_handler_fn) handle_seek);
    ipc_register(S_INFORM, (ipc_handler_fn) handle_inform);
    ipc_register(IPC_EXIT, st_ipc_exit);

    /* accept connections from other processes */
    max_fd = add_fd(accept_fd, &valid_fds, max_fd);

    /* listen to SUPERVISOR */
    max_fd = add_fd(supervisor_fd, &valid_fds, max_fd);

    /* init data structures */
    bzero(&cs_state, sizeof(cs_state)); 

    /* 
     * wait for the debugger to attach
     */
    DEBUGGER_WAIT_ATTACH(map);

    /*
     * The real main loop.
     */
    for (;;) {
        fd_set r = valid_fds;
	struct timeval * pto;
	struct timeval last; 
	struct timeval to = { 5, 200000 };	// XXX just to put something?
	timestamp_t elapsed; 
        int n_ready;
	int i;
	int ipcr;

	/*
	 * use a timeout if we have files open. this way the 
	 * scheduler starts when clients are idle too.
	 */
        pto = (cs_state.client_count > 0) ? &to : NULL; 

	gettimeofday(&last, 0); 
	n_ready = select(max_fd, &r, NULL, NULL, pto); 
	if (n_ready < 0) {
	    if (errno == EINTR) {
		continue;
	    }
	    panic("waiting for select (%s)\n", strerror(errno));
	}

	for (i = 0; n_ready > 0 && i < max_fd; i++) {

	    if (!FD_ISSET(i, &r))
		continue;

	    n_ready--;

	    if (i == accept_fd) {
		int x;

		x = accept(i, NULL, NULL);
		if (x < 0) {
		    logmsg(LOGWARN, "accept fd[%d] got %d (%s)\n", 
			i, x, strerror(errno));
		} else 
 		    max_fd = add_fd(x, &valid_fds, max_fd);
		continue;
	    }
	    
	    ipcr = ipc_handle(i);
	    switch (ipcr) {
	    case IPC_ERR:
		/* an error. close the socket */
		logmsg(LOGWARN, "error on IPC handle from %d\n", i);
	    case IPC_EOF:
		close(i);
		del_fd(i, &valid_fds, max_fd);
		break;
	    }
        }       

	/* 
	 * run the scheduler to clean up the files, decide
	 * the blocks to be pre-fetched and then prefetch 
	 * pages into memory. 
	 */
	if (cs_state.client_count > 0) {
	    struct timeval now; 

	    gettimeofday(&now, 0); 
	    elapsed = TIME2TS(now.tv_sec, now.tv_usec) - 
		      TIME2TS(last.tv_sec, last.tv_usec); 
	    scheduler(elapsed); 
	}
    }
} 
/* end of file */
