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
 * $Id:como.c 1032 2006-11-14 13:29:01Z m_canini $
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>		/* strlen strcpy strncat memset */

/* Required for symlink deletion */
#include <errno.h>
#include <signal.h>	// signal... 
#include <unistd.h>

#include "como.h"
#include "comopriv.h"
#include "storage.h"	// mainloop
#include "ipc.h"	// ipc_listen()


/**
 * -- safe__malloc
 *
 * Not to be called directly, but through safe_malloc()
 *
 * simple wrapper to malloc that handles errors
 * and returns only if the malloc call succeded. it
 * forces a termination, otherwise.
 *
 */
void *
safe__malloc(size_t sz, const char * file, int line)
{
    void * v;

    v = malloc(sz);
    if (v == NULL) {
	error("malloc failed: %u bytes (%s:%d): %s\n",
	      sz, file, line, strerror(errno));
    }

    return v;
}


/**
 * -- safe__calloc
 * 
 * Not to be called directly, but through safe_calloc()
 *
 * simple interface to calloc that handles errors
 * and returns only if the calloc call succeded. it
 * forces a termination, otherwise.
 *
 */
void *
safe__calloc(size_t n, size_t sz, const char * file, int line)
{
    void * v;

    v = calloc(n, sz);
    if (v == NULL) {
	error("calloc failed: %u * %u bytes (%s:%d): %s\n",
	      n, sz, file, line, strerror(errno));
    }

    return v;
}


/**          
 * -- safe__realloc
 *
 * Not to be called directly, but through safe_realloc()
 *
 * simple interface to realloc that handles errors
 * and returns only if the realloc call succeded. it
 * forces a termination, otherwise.
 *   
 */ 
void *
safe__realloc(void * ptr, size_t sz, const char * file, const int line)
{
    void * v;
        
    v = realloc(ptr, sz);
    if (v == NULL) {
        error("realloc failed: %u bytes (%s:%d): %s\n",
	      sz, file, line, strerror(errno));
    }
    
    return v;
}


/**
 * -- safe__strdup
 * 
 * Not to be called directly, but through safe_strdup()
 *
 * simple interface to strdup() that handles errors
 * and returns only if the call succeded. it
 * forces a termination, otherwise.
 *
 */
char *
safe__strdup(const char * str, const char * file, const int line)
{
    char * v; 

    if (str == NULL) 
	return NULL; 

    v = strdup(str); 
    if (v == NULL) {
	error("strdup failed (%s:%d): %s\n",
	      file, line, strerror(errno));
    }

    return v;
}


/*
 * -- safe__freedup 
 * 
 * Not to be called directly, but through safe_freedup()
 *
 * Makes a malloc'ed copy of src into *dst, 
 * freeing the previous one if any
 */
char *
safe__freedup(char **dst, char *src, const char * file, const int line)
{
    if (*dst)
        free(*dst);
    *dst = safe__strdup(src, file, line);
    return *dst;
}


int
safe__fileno(FILE *stream, const char *file, const int line)
{
    int i = fileno(stream);
    if (i < 1)
        error("fileno failed (%s:%d): %s\n",
            file, line, strerror(errno));
    if (fflush(stream) < 0) /* user will be using the fd, so first flush */
        error("fileno failed (%s:%d) - can't flush stream: %s\n",
            file, line, strerror(errno));
    return i;
}


char *
safe__asprintf(const char * file, const int line, char *fmt, ...)
{
    char *str;
    va_list ap;
    va_start(ap, fmt);
    vasprintf(&str, fmt, ap);
    if (str == NULL) {
	error("vasprintf failed (%s:%d): %s\n",
	      file, line, strerror(errno));
    }
    va_end(ap);
    return str;
}

char *
como_basename(const char * path)
{
    return basename(path); /* GNU version of basename */
}


alc_t *
como_alc()
{
    static alc_t alc = {
	malloc: (alc_malloc_fn) safe__malloc,
	calloc: (alc_calloc_fn) safe__calloc,
	free: (alc_free_fn) free,
	data: NULL
    };
 
    return &alc;
}

