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
 
#ifdef __FreeBSD__
#include <stdlib.h>	/* malloc */
#include <string.h>	/* strlen, memcpy */

char *strndup(const char *s, unsigned int n)
{
    unsigned int len = strlen(s);
    char *new;
    if (n < len)
        len = n;
    new = (char*)malloc(len + 1);
    if (new == NULL)
        return NULL;
    
    new[len] = '\0';
    return (char*)memcpy(new, s, len);
}

#endif
  
#if defined(linux) || defined(__CYGWIN32__)
        
/*
 * A trivial setproctitle(3) implementation for Linux is provided here.
 * It just replaces the contents of argv[0], without exceeding its
 * original length. Unfortunately, init_setproctitle should be called first.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>  /* _POSIX_PATH_MAX */

#include "os.h"

static int spt_argc = 0;
static char** spt_argv = NULL;

void 
init_setproctitle(int argc, char** argv)
{
    spt_argc = argc;
    spt_argv = argv;
}

int 
setproctitle(const char *fmt, ...)
{
    int n;
    va_list ap;
    char buff[_POSIX_PATH_MAX + 1]; 

    buff[_POSIX_PATH_MAX] = '\0';
    if (spt_argc == 0)
        return -1;
    
    buff[0] = 'c';
    buff[3] = buff[1] = 'o';
    buff[2] = 'm';

    va_start(ap, fmt);
    n = vsnprintf(buff + 4, _POSIX_PATH_MAX - 4, fmt, ap);
    va_end(ap);

    if (n < 0)
        return -1;
    
    n += 4;

    if (n > _POSIX_PATH_MAX)
        n = _POSIX_PATH_MAX;

    buff[n] = '\0';
    n++; /* String length with trailing '\0' */

#ifndef SETPROCTITLE_DIRTY_AND_UNSAFE_HACK
    /*
     * If we change argv[0], ps won't notice at all. Unfortunately,
     * if we overwrite the string at address argv[0] instead, we are
     * going to overwrite other arguments or the environment.
     * Thus, it is UNSAFE to write beyond the original argv[0] length.
     */
    n = strlen(spt_argv[0]);
#endif

    strncpy(spt_argv[0], buff, n);

    return 0;
}
#endif /* linux */

#if defined(__CYGWIN32__)

char *
mkdtemp(char *template)
{
    int i;
    char *t = mktemp(template);

    i = mkdir(t, 0700);
    return t;
}

#include <ctype.h>

const char *
strcasestr(const char *s1, const char *s2)
{
    char *c1, *c2;
    const char *cp;
    int i;

    c1 = strdup(s1);
    c2 = strdup(s2);
    for (i=0; c1[i] != '\0'; i++)
	c1[i] = tolower(c1[i]);
    for (i=0; c2[i] != '\0'; i++)
	c2[i] = tolower(c2[i]);
    cp = strstr(c1, c2);
    cp = (cp == NULL) ? NULL : s1 + (cp - c1);
    free(c1);
    free(c2);
    return cp;
}


char *
ether_ntoa(__unused const struct ether_addr *n)
{
    return "unimplemented ether_ntoa XXX" ;
}
const char *
inet_ntop(__unused int af, __unused const void *src,
	__unused char *dst, __unused size_t size)
{
    return "unimplemented inet_ntop XXX";
}
#endif

