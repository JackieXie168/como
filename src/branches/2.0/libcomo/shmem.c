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
/* Based on the Apache Portable Runtime: */
/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define LOG_DOMAIN "SHMEM"
#include "como.h"
#include "comopriv.h"

#ifndef MAP_NOSYNC
#define MAP_NOSYNC 0
#endif
#ifndef SHM_R
#define SHM_R 0400
#endif
#ifndef SHM_W
#define SHM_W 0200
#endif
/* Not all systems seem to have MAP_FAILED defined, but it should always
 * just be (void *)-1. */
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif


struct shmem {
    void *	base;		/* base real address */
    void *	usable;		/* base usable address */
    size_t	reqsize;	/* requested segment size */
    size_t	realsize;	/* actual segment size */
    char *	filename;	/* NULL if anonymous */
    int		shmid;		/* shmem ID returned from shmget() */
};


shmem_t *
shmem_create(size_t reqsize, const char * filename)
{
    shmem_t *new_m;

    new_m = como_new0(shmem_t);
    new_m->reqsize = reqsize;

    if (filename == NULL) {
	/* Anonymous shared memory */
	new_m->reqsize = reqsize;
	new_m->realsize = reqsize + 
	    ALIGN_DEFAULT(sizeof(size_t)); /* room for metadata */
	new_m->filename = NULL;

	new_m->base = mmap(NULL, new_m->realsize, PROT_READ|PROT_WRITE,
			   MAP_ANON|MAP_NOSYNC|MAP_SHARED, -1, 0);
	if (new_m->base == (void *)MAP_FAILED) {
	    goto error;
	}

	/* store the real size in the metadata */
	*((size_t *) new_m->base) = new_m->realsize;
	/* metadata isn't usable */
	new_m->usable = new_m->base + ALIGN_DEFAULT(sizeof(size_t));
	
	notice("allocated %lu of mapped memory\n", reqsize);
    } else {
	/* Name-based shared memory */
	int fd;
	ssize_t r;
	struct shmid_ds shmbuf;
	key_t shmkey;

	new_m->realsize = reqsize;
	new_m->filename = como_strdup(filename);

	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
	    goto error;
	}

	/* ftok() (on solaris at least) requires that the file actually
	 * exist before calling ftok(). */
	shmkey = ftok(filename, 1);
	if (shmkey == (key_t)-1) {
	    goto error;
	}

	new_m->shmid = shmget(shmkey, new_m->realsize,
			      SHM_R | SHM_W | IPC_CREAT | IPC_EXCL);
	if (new_m->shmid < 0) {
	    goto error;
	}

	new_m->base = shmat(new_m->shmid, NULL, 0);
	if (new_m->base == (void *)-1) {
	    goto error;
	}
	new_m->usable = new_m->base;

	if (shmctl(new_m->shmid, IPC_STAT, &shmbuf) == -1) {
	    goto error;
	}
	shmbuf.shm_perm.uid = getuid();
	shmbuf.shm_perm.gid = getgid();
	if (shmctl(new_m->shmid, IPC_SET, &shmbuf) == -1) {
	    goto error;
	}

	r = write(fd, &reqsize, sizeof(reqsize));
	if (r == -1) {
	    goto error;
	}
	r = close(fd);
	if (r == -1) {
	    goto error;
	}
    }

    return new_m;
error:
    warn("shmem_create(): %s\n", strerror(errno));
    free(new_m);
    return NULL;
}


int
shmem_remove(const char * filename)
{
    int fd;
    key_t shmkey;
    int shmid;

    /* Presume that the file already exists; just open for writing */    
    fd = open(filename, O_WRONLY);
    if (fd < 0) {
	goto error;
    }

    /* ftok() (on solaris at least) requires that the file actually
     * exist before calling ftok(). */
    shmkey = ftok(filename, 1);
    if (shmkey == (key_t)-1) {
        goto error;
    }

    close(fd);
    fd = -1;

    if ((shmid = shmget(shmkey, 0, SHM_R | SHM_W)) < 0) {
        goto error;
    }

    /* Indicate that the segment is to be destroyed as soon
     * as all processes have detached. This also disallows any
     * new attachments to the segment. */
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        goto error;
    }
    return unlink(filename);

error:
    debug("shmem_remove(): %s\n", strerror(errno));
    if (fd != -1)
	close(fd);
    /* ensure the file has been removed anyway. */
    unlink(filename);
    return -1;
} 

int
shmem_destroy(shmem_t * m)
{
    /* anonymous shared memory */
    if (m->filename == NULL) {
	if (munmap(m->base, m->realsize) == -1) {
	    warn("munmap(): %s\n", strerror(errno));
	    return -1;
	}
	free(m);
	return 0;
    } else {
	/* name-based shared memory */
	/* Indicate that the segment is to be destroyed as soon
	 * as all processes have detached. This also disallows any
	 * new attachments to the segment. */
	if (shmctl(m->shmid, IPC_RMID, NULL) == -1) {
	    warn("shmctl(): %s\n", strerror(errno));
	    return -1;
	}
	if (shmdt(m->base) == -1) {
	    warn("shmdt(): %s\n", strerror(errno));
	    return -1;
	}
	free(m);
        return unlink(m->filename);
    }
}


shmem_t *
shmem_attach(const char * filename, void *base_addr)
{
    shmem_t *new_m;
    int fd;   /* file where metadata is stored */
    ssize_t r;
    key_t shmkey;

    if (filename == NULL) {
        /* It doesn't make sense to attach to a segment if you don't know
         * the filename. */
        return NULL;
    }

    new_m = como_new0(shmem_t);

    fd = open(filename, O_RDWR);
    if (fd < 0) {
	goto error;
    }

    r = read(fd, &(new_m->reqsize), sizeof(new_m->reqsize));
    if (r == -1) {
	goto error;
    }
    r = close(fd);
    if (r == -1) {
	goto error;
    }

    new_m->filename = como_strdup(filename);
    shmkey = ftok(filename, 1);
    if (shmkey == (key_t)-1) {
	goto error;
    }

    new_m->shmid = shmget(shmkey, 0, SHM_R | SHM_W);
    if (new_m->shmid == -1) {
	goto error;
    }

    new_m->base = shmat(new_m->shmid, base_addr, 0);
    if (new_m->base == (void *)-1) {
        debug("shmat() error - %s\n", strerror(errno));
	goto error;
    }

    new_m->usable = new_m->base;
    new_m->realsize = new_m->reqsize;

    return new_m;
error:
    warn("shmem_attach(): %s\n", strerror(errno));
    free(new_m);
    return NULL;
}


int
shmem_detach(shmem_t * m)
{
    /* It doesn't make sense to detach from an anonymous memory segment. */
    if (m->filename != NULL) {
	if (shmdt(m->base) == -1) {
	    warn("shmdt(): %s\n", strerror(errno));
	    return -1;
	}
    }

    return 0;
}

void *
shmem_baseaddr(const shmem_t * m)
{
    return m->usable;
}

size_t
shmem_size(const shmem_t * m)
{
    return m->reqsize;
}

const char *
shmem_filename(const shmem_t * m)
{
    return m->filename;
}

