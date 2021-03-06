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
 * $Id:storage-client.c 1032 2006-11-14 13:29:01Z m_canini $
 */

/*
 *
This file implements the client side for processes trying to
access files in CoMo. The interface to the storage module has
four methods, and provides an mmap-like interface.

  int csopen(const char * name, int mode, off_t size, ipc_peer_t * storage)

	name		is the file name
	mode		is the access mode, CS_READER or CS_WRITER
 	size		is the max bytestream size (CS_WRITER only)
	storage		is the peer used to talk to the
			daemon supplying the service.

	Returns an integer to be used as a file descriptor,
	or -1 on error.

  off_t csgetofs(int fd)

	fd		is the file descriptor

	Returns the offset in the current file.

  void *csmap(int fd, off_t ofs, ssize_t * sz)

	fd		is the file descriptor
	ofs		is the offset that we want to map
	*sz		on input, the desired size;
			on output, the actual size;

	Flushes any unmapped block, and returns a new one.
	Returns a pointer to the mapped region.

  off_t csseek(int fd, csmethod_t where)

	fd		is the file descriptor
	where		what to seek (next file or prev file)

	Moves to the beginning of the next/prev file, unmapping any
	mapped region.

  void csclose(int fd, off_t ofs)  

	fd		is the file descriptor
        ofs		last valid byte written to disk (CS_WRITER only)

	Flushes any unmapped block, and closes the descriptor.
  
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <assert.h>

#define LOG_DISABLE
#define LOG_DOMAIN	"ST-CL"
#include "como.h"
#include "comopriv.h"
#include "storagepriv.h"


/* 
 * Client-side file descriptor 
 * 
 * This data structure contains the minimal information a client
 * needs to know about the open file, i.e., the id, the current offset, 
 * the address and size of the current mmapped block, the start offset
 * of the block and the socket descriptor to communicate with the storage
 * process.
 * 
 */
typedef struct { 
    ipc_peer_t *storage;	/* unix socket 
				   XXX not that nice to have it here */
    char *	name;		/* file name, dynamically allocated */
    int		mode;		/* file access mode */
    int		fd;		/* OS file descriptor */
    int		id;		/* STORAGE file ID */
    off_t	off_file;	/* start offset of current file */
    void *	addr;		/* address of memory mapped block */
    size_t	size;		/* size of memory mapped block */
    off_t	offset;		/* bytestream offset of the mapped block */
    off_t	readofs;	/* currently read offset (used by csreadp) */
    off_t	readsz;		/* currently read size (used by csreadp) */
} csfile_t;


/* file descriptors for open files */
static csfile_t * files[CS_MAXCLIENTS];


/* 
 * -- csopen
 * 
 * csopen() opens a file managed by the storage process. It 
 * uses the unix socket to communicate its intentions. The function 
 * returns an integer used as file descriptor, or -1 on error.
 * Obviously the descriptor is not select()-able.
 */ 
int
csopen(const char * name, csmode_t mode, off_t size, ipc_peer_t * storage)
{ 
    csfile_t * cf;
    csmsg_t m;
    int fd;
    ipc_type ret;
    size_t sz;
    int swap;

    assert(mode == CS_READER || mode == CS_WRITER ||
	   mode == CS_READER_NOBLOCK);

    /* look for an empty file descriptor */
    for (fd = 0; fd < CS_MAXCLIENTS && files[fd] != NULL; fd++)
	;

    if (fd == CS_MAXCLIENTS) {
	warn("Can't open %s: Too many open files.\n", name); 
	return -1;
    } 

    /* 
     * file descriptor found, prepare and send the request 
     * message to the storage process
     */
    bzero(&m, sizeof(m));
    m.arg = mode;
    m.size = size;
    strncpy(m.name, name, FILENAME_MAX);
    
    sz = sizeof(m);
    
    if (ipc_send(storage, S_OPEN, &m, sz) != IPC_OK) {
	error("sending message to storage: %s\n", strerror(errno));
    }
    
    if (ipc_receive(storage, &ret, &m, &sz, &swap, NULL) != IPC_OK) {
	error("receiving reply from storage: %s\n", strerror(errno));
    }
    
    if (ret == S_ERROR) {
	warn("Can't open %s: %s.\n", name, strerror(m.arg));
	errno = m.arg;
	return -1;
    }

    /* 
     * allocate a new file descriptor and initialize it with 
     * the information in the message. 
     */
    cf = como_new0(csfile_t);
    cf->fd = -1;
    cf->storage = storage;
    cf->name = strdup(name);
    cf->mode = mode;
    cf->id = m.id;
    cf->off_file = m.ofs;  

    /* store current offset. m.size is set to 0 by the server if this client
     * is a reader. otherwise it is equal to the size of the bytestream so 
     * that writes are append only. 
     */
    cf->offset = m.ofs + m.size; 

    files[fd] = cf;
    return fd; 
}
    

/* 
 * -- _csinform
 * 
 * send a message to storage to inform that the writer has moved
 * to another offset. note that writes are append-only so we can 
 * only move forward. this message does not need acknowledgement and
 * allows storage to wakeup clients waiting for new data. 
 *
 */
static void
_csinform(csfile_t * cf, off_t ofs) 
{ 
    csmsg_t m;

    m.id = cf->id;
    m.arg = 0; 
    m.ofs = ofs; 

    if (ipc_send(cf->storage, S_INFORM, &m, sizeof(csmsg_t)) != IPC_OK) {
	error("message to storage: %s\n", strerror(errno)); 
    }
}


/* 
 * -- _csmap
 * 
 * this function provides an interface similar to mmap. 
 * it maps in memory a region of the file. before doing so, informs 
 * the server of this intentions and makes sure that it can do it. 
 *  
 * the acknowledgement from the server carries two pieces of information: 
 *   . offset, that is set to the start offset of the file that 
 *     contains the block.
 *   . size, that indicates the size of the region that can be memory mapped. 
 *     (different only if the region overlaps multiple files). 
 * 
 * this function returns a pointer to the memory mapped region and the size
 * of the region. 
 *
 * _csmap is the back-end for csmap, csreadp, csseek. 
 *
 * XXX how is the error condition notified/used? just returning NULL? 
 *     or *sz must be -1 as well?  
 */
static void * 
_csmap(int fd, off_t ofs, ssize_t * sz, int method, int arg) 
{
    csfile_t * cf;
    csmsg_t m;
    int flags;
    int diff;
    size_t m_sz;
    ipc_type ret;
    int swap;

    cf = files[fd];

    /* Package the request and send it to the server */
    m.id = cf->id;
    m.arg = arg;
    m.size = *sz;
    m.ofs = ofs; /* the map offset */
    
    m_sz = sizeof(csmsg_t);

    /* send the request out */
    if (ipc_send(cf->storage, method, &m, m_sz) != IPC_OK) {
	error("message to storage: %s\n", strerror(errno));
    }

    /* block waiting for the acknowledgment */
    if (ipc_receive(cf->storage, &ret, &m, &m_sz, &swap, NULL) != IPC_OK) {
	error("receiving reply from storage: %s\n", strerror(errno));
    }

    switch (ret) {
    case S_ERROR: 
	errno = m.arg;
	*sz = -1;		
	return NULL;

    case S_ACK: 
	/* 
	 * The server acknowledged our request,
	 * unmap the current block (both for csmap and csseek)
	 */
	if (cf->addr)
	    munmap(cf->addr, cf->size);

	if (method == S_REGION) {
	    /* 
	     * A zero sized block indicates end-of-bytestream. If so, close
	     * the current file and return an EOF as well.
	     */
	    if (m.size == 0) { 
		close(cf->fd);
		*sz = 0;
		return NULL;
	    }
	} else {	/* seek variants */
	    /* the current file is not valid anymore */
	    close(cf->fd);
	    cf->off_file = m.ofs;
	    cf->fd = -1;
	    return NULL;		/* we are done */
	}
	break;

    default: 
	error("unknown msg type %d from storage\n", ret);
	break;
    }

    if ((ssize_t) m.size == -1)
	error("unexpected return from storage process");

    /*
     * now check if the requested block is in the same file (i.e., 
     * the server replied with an offset that is the first offset of 
     * the currently open file. if not, close the current file and 
     * open a new one. 
     */
    if (cf->fd < 0 || m.ofs != cf->off_file) {
	char * nm;

	if (cf->fd >= 0)
	    close(cf->fd);

#ifdef linux
	flags = (cf->mode != CS_WRITER)? O_RDWR : O_RDWR|O_APPEND; 
#else
	flags = (cf->mode != CS_WRITER)? O_RDONLY : O_WRONLY|O_APPEND; 
#endif
	asprintf(&nm, "%s/%016llx", cf->name, m.ofs); 
	cf->fd = open(nm, flags, 0666);
	if (cf->fd < 0)
	    error("opening file %s acked! (%s)\n", nm, strerror(errno));
	cf->off_file = m.ofs;
	free(nm);
    } 
	   
    /*
     * mmap the new block 
     */
    flags = (cf->mode != CS_WRITER)? PROT_READ : PROT_WRITE; 
    cf->offset = ofs; 
    cf->size = *sz = m.size;

    /* 
     * align the mmap to the memory pagesize 
     */
    diff = (cf->offset - cf->off_file) % getpagesize();
    cf->offset -= diff; 
    cf->size += diff; 

    cf->addr = mmap(0, cf->size, flags, MAP_NOSYNC | MAP_SHARED, 
		    cf->fd, cf->offset - cf->off_file);
    if (cf->addr == MAP_FAILED || cf->addr == NULL)
        error("mmap failed: %s\n", strerror(errno));

    assert(cf->addr + diff != NULL);

    return (cf->addr + diff);
}


/* 
 * -- csmap
 * 
 * this function request to mmap a new region in the bytestream. 
 * it first checks if the input parameters are correct. then it 
 * checks if the region requested is already mmapped. if so, it 
 * informs of the request the storage server only if this is a 
 * writer. 
 * 
 * it then uses _csmap to perform the action. 
 */
void * 
csmap(int fd, off_t ofs, ssize_t * sz) 
{
    csfile_t * cf;
    ssize_t newsz; 
    void * addr; 

    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL); 
    cf = files[fd];

    /* 
     * check if we already have mmapped the requested region. 
     */
    if (ofs > cf->offset && ofs + *sz <= cf->offset + cf->size) { 
        debug("ofs %lld sz %d silently approved (%lld:%d)\n", 
	      ofs, *sz, cf->offset, cf->size);

        return (cf->addr + (ofs - cf->offset));
    } 

    /* 
     * inflate the block size if too small. this will help answering
     * future requests. however do not tell anything to the caller. 
     * we change *sz only if the storage process cannot handle the 
     * requested size; 
     */
    newsz = (*sz < CS_OPTIMALSIZE)? CS_OPTIMALSIZE : *sz; 
    addr = _csmap(fd, ofs, &newsz, S_REGION, 0);
    if (newsz < *sz) 
	*sz = newsz; 
    return addr; 
}


/* 
 * -- cscommit
 * 
 * this function commits the number of bytes written so far 
 * so that the storage process knows that we are moving forward 
 * and can inform other readers. 
 * 
 */
void
cscommit(int fd, off_t ofs) 
{
    csfile_t * cf;

    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL);
    cf = files[fd];

    if (cf->mode != CS_WRITER) 
	return; 		/* just for writers */

    /*
     * check if the offset if valid, i.e. within a mmapped region
     */ 
    if (ofs < cf->offset || ofs > cf->offset + cf->size) 
	return; 

    /* send the message to the STORAGE process */
    _csinform(cf, ofs);
}


/* 
 * -- csseek
 * 
 * jump to next file in the bytestream. it uses _csmap to do it. 
 * 
 */
off_t
csseek(int fd, csmethod_t where)
{
    ssize_t retval;

    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL); 

    retval = 0;
    _csmap(fd, 0, &retval, S_SEEK, (int) where);

    if (retval < 0) 
	return -1;

    /* reset read values */
    files[fd]->readofs = files[fd]->offset; 
    files[fd]->readsz = 0;   

    return files[fd]->off_file; 
}


/* 
 * -- csreadp
 *
 * this is a simpler interface to csmap that does not require to 
 * know the offset. it returns a pointer to the mmapped region and 
 * its size
 */
size_t
csreadp(int fd, void ** buf, size_t sz)
{
    csfile_t * cf; 
    ssize_t realsz = sz; 

    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL); 
    cf = files[fd];

    *buf = csmap(fd, cf->readofs + cf->readsz, &realsz); 

    /* update the read offset and size */
    cf->readofs += cf->readsz; 
    cf->readsz = realsz; 
 
    return cf->readsz; 
}


/*
 * -- csclose
 *
 * Closes the file and sends the message to the server. 
 * For writers it requires the last offset really written to 
 * disk (i.e., with valid data given that one could mmap large
 * portion of file and never write anything to them). 
 * This offset is sent to the STORAGE process that uses it to 
 * inform readers of the last valid byte to read. 
 */
void
csclose(int fd, off_t ofs)
{
    csfile_t * cf;
    csmsg_t m;

    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL); 
    cf = files[fd];
    files[fd] = NULL;

    /* unmap the current block and close the file, if any */
    if (cf->addr != NULL)
	munmap(cf->addr, cf->size);
    if (cf->fd >= 0)
	close(cf->fd); 

    /* send the release message to the hfd */
    memset(&m, 0, sizeof(m));
    m.id = cf->id; 
    m.ofs = ofs;
    
    if (ipc_send(cf->storage, S_CLOSE, &m, sizeof(m)) != IPC_OK)
	error("sending message to storage: %s\n", strerror(errno));
    
    free(cf);
}


/* 
 * -- csgetofs
 * 
 * returns the current offset of the file. 
 */
inline off_t
csgetofs(int fd)
{
    assert(fd >= 0 && fd < CS_MAXCLIENTS && files[fd] != NULL); 
    return files[fd]->offset;
} 

/* 
 * -- csseek_ts
 * 
 * This function looks into the first record of each file until it 
 * finds the one with the closest start time to the requested one. 
 * We do a linear search (instead of a faster binary search) because
 * right now csseek only supports CS_SEEK_FILE_PREV and CS_SEEK_FILE_NEXT. 
 * The function returns the offset of the file to be read or -1 in case
 * of error.
 */
off_t
csseek_ts(int fd, timestamp_t where)
{
    ssize_t len;
    off_t ofs;
    csrec_t *rec;

    ofs = csgetofs(fd);

    /* 
     * first, find the right file in the bytestream 
     */
    for (;;) { 
	len = sizeof(csrec_t);

	/* read the first record */
	rec = csmap(fd, ofs, &len); 
	if (rec == NULL) { 
	    if (len == 0) {
		/* 
		 * we hit EOF. this can only happen if the file has
		 * just been created with zero length and no records 
		 * have been written yet. so, go back one file and 
		 * use that one as starting point. 
		 */
		ofs = csseek(fd, CS_SEEK_FILE_PREV);
		break; 
	    }
	    return -1;	/* error */
	} 

	/* use the current record timestamp to move to the correct file */
	if (rec->ts < where) {
	    ofs = csseek(fd, CS_SEEK_FILE_NEXT);
	} else {
	    /* found. go one file back; */
	    ofs = csseek(fd, CS_SEEK_FILE_PREV);
	} 

	/* 
	 * if the seek failed it means we are
	 * at the first or last file. return the 
	 * offset of this file and be done. 
	 */
	if (ofs == -1) {
	    ofs = csgetofs(fd);
	    break; 
	}
    }

    /* 
     * then find the record inside the file 
     */
    for (;;) {
	len = sizeof(csrec_t);

	/* 
 	 * mmap len bytes starting from last ofs. 
	 * 
	 */ 
	rec = csmap(fd, ofs, &len); 
	if (rec == NULL) {
	    if (len != 0) {
/*
		warn("error reading file %s: %s\n",
		       mdl->output, strerror(errno));
*/
	    }
	    /* there's no data */
	    ofs = -1;
	    break;
	}

	/*
	 * check if we have lost sync (indicated by a zero timestamp)
	 */
	if (rec->ts == 0) {
	    /*
	     * If lost sync, move to the next file and try again. 
	     */
	    ofs = csseek(fd, CS_SEEK_FILE_NEXT);
	    continue;
	}

	if (rec->ts >= where) {
	    break;
	}
	ofs += rec->sz;

    }

    return ofs;
}

csrec_t *
csgetrec(int fd, off_t ofs)
{
    ssize_t len;
    csrec_t *rec;
    
    len = sizeof(csrec_t);
    rec = csmap(fd, ofs, &len);
    if (rec == NULL)
	return NULL;

    if (rec->ts == 0) {
	return NULL;
    }

    len = rec->sz;
    rec = csmap(fd, ofs, &len);

    return rec;
}

/* end of file */
