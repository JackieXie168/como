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
 *
 * Debugging and various utility functions.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> 			/* va_start */
#include <string.h>
#include <errno.h>
#include <unistd.h>     
#include <dlfcn.h>
#undef __unused        /* XXX linux's netdb.h has a variable with this name */
#include <netdb.h>                     /* gethostbyname */
#include <assert.h>

#include "como.h"

extern struct _como map;

/**
 * -- _smalloc
 *
 * Not to be called directly, but through safe_malloc()
 *
 * simple wrapper to malloc that handles errors
 * and returns only if the malloc call succeded. it
 * forces a termination, otherwise.
 *
 */
void *
_smalloc(const char * file, const int line, size_t sz)
{
    void * v;

    v = malloc(sz);
    if (v == NULL) {
        fprintf(stderr, "[%2s]  **** PANIC: malloc %u bytes (%s:%d): %s\n",
            getprocname(map.whoami), sz, file, line, strerror(errno));
        abort();
    }

    return v;
}


/**
 * -- _scalloc
 * 
 * Not to be called directly, but through safe_calloc()
 *
 * simple interface to calloc that handles errors
 * and returns only if the calloc call succeded. it
 * forces a termination, otherwise.
 *
 */
void *
_scalloc(const char * file, const int line, int n, size_t sz)
{
    void * v;

    v = calloc((unsigned int) n, sz);
    if (v == NULL) {
	fprintf(stderr, "[%2s]  **** PANIC: calloc n:%d sz:%u (%s:%d)\n", 
	    getprocname(map.whoami), n, sz, file, line);
	abort();
    }

    return v;
}


/**          
 * -- _srealloc
 *
 * Not to be called directly, but through safe_realloc()
 *
 * simple interface to realloc that handles errors
 * and returns only if the realloc call succeded. it
 * forces a termination, otherwise.
 *   
 */ 
void *
_srealloc(const char * file, const int line, void * ptr, size_t sz)
{
    void * v;
        
    v = realloc(ptr, sz);
    if (v == NULL) {
        fprintf(stderr, "[%2s]  **** PANIC: calloc (%s:%d)\n",
            getprocname(map.whoami), file, line);
        abort();
    }
    
    return v;
}


/**
 * -- _sstrdup
 * 
 * Not to be called directly, but through safe_strdup()
 *
 * simple interface to strdup() that handles errors
 * and returns only if the call succeded. it
 * forces a termination, otherwise.
 *
 */
char *
_sstrdup(const char * file, const int line, const char * str)
{
    char * v; 

    v = strdup(str); 
    if (v == NULL) {
	fprintf(stderr, "[%2s]  **** PANIC: strdup (%s:%d)\n", 
	    getprocname(map.whoami), file, line);
	abort();
    }

    return v;
}


/** 
 * -- _sfree
 * 
 * Not to be called directly but thru safe_free() 
 * 
 * Free a memory making sure the original pointer is not NULL. 
 * If NULL, writes warning message. 
 * 
 */
void 
_sfree(const char * file, const int line, void * ptr)
{ 
    if (ptr == NULL) { 
	logmsg(LOGWARN, "freeing NULL pointer (%s:%d)\n", file, line); 
	return; 
    } 
 
    free(ptr); 
}

/*
 * -- _sdup 
 * 
 * Not to be called directly, but through safe_strdup()
 *
 * Makes a malloc'ed copy of src into *dst, 
 * freeing the previous one if any
 */
void
_sdup(const char * file, const int line, char **dst, char *src)
{
    if (*dst)
        free(*dst);
    *dst = _sstrdup(file, line, src);
}

