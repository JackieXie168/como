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
_smalloc(size_t sz, const char * file, int line)
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
_scalloc(size_t n, size_t sz, const char * file, int line)
{
    void * v;

    v = calloc(n, sz);
    if (v == NULL) {
	fprintf(stderr, "[%2s]  **** PANIC: calloc n:%u sz:%u (%s:%d): %s\n", 
	    getprocname(map.whoami), n, sz, file, line, strerror(errno));
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
_srealloc(void * ptr, size_t sz, const char * file, const int line)
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
_sstrdup(const char * str, const char * file, const int line)
{
    char * v; 

    if (str == NULL) 
	return NULL; 

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
_sfree(void * ptr, const char * file, int line)
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
 * Not to be called directly, but through safe_sdup()
 *
 * Makes a malloc'ed copy of src into *dst, 
 * freeing the previous one if any
 */
void
_sdup(char **dst, char *src, const char * file, const int line)
{
    if (*dst)
        free(*dst);
    *dst = _sstrdup(src, file, line);
}

