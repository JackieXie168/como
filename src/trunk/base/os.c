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

//#ifdef __FreeBSD__
#if defined(__FreeBSD__) || defined(__APPLE__)
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
  
#if defined(linux) || defined(__CYGWIN32__) || defined(__APPLE__)
        
/*
 * setproctitle & setproctitle_init come with the following license:
 * 
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *     2002, 2003 by The Internet Software Consortium and Rich Salz
 * 
 * This code is derived from software contributed to the Internet Software
 * Consortium by Rich Salz.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>  /* _POSIX_PATH_MAX */
#include <assert.h>

#include "os.h"

static char *title_start = NULL;
static char *title_end = NULL;

void
setproctitle_init(int argc, char **argv)
{
    title_start = argv[0];
    title_end = argv[argc - 1] + strlen(argv[argc - 1]);
}

void
setproctitle(const char *format, ...)
{
    va_list args;
    size_t length;
    ssize_t delta;
    char *title;

    if (title_start == NULL || title_end == NULL) {
    	assert(1);
        return;
    }

    title = title_start;
    length = title_end - title_start;

    delta = snprintf(title, length, "como: ");
    if (delta < 0 || (size_t) delta > length)
        return;
    if (delta > 0) {
        title += delta;
        length -= delta;
    }

    va_start(args, format);
    delta = vsnprintf(title, length, format, args);
    va_end(args);
    if (delta < 0 || (size_t) delta > length)
        return;
    if (delta > 0) {
        title += delta;
        length -= delta;
    }
    for (; length > 1; length--, title++)
        *title = ' ';
    *title = '\0';
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
ether_ntoa(__attribute__((__unused__)) const struct ether_addr *n)
{
    return "unimplemented ether_ntoa XXX" ;
}

const char *
inet_ntop(__attribute__((__unused__)) int af,
        __attribute__((__unused__)) const void *src,
	__attribute__((__unused__)) char *dst,
        __attribute__((__unused__)) size_t size)
{
    return "unimplemented inet_ntop XXX";
}



/* 
 * CYGWIN doesn't come with timegm(). we need to 
 * implement one ourselves. 
 * 
 */
#include <time.h>

static const int mon_lengths[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))
#define daysperyear(y)	((isleap(y)?) 356 : 355;

time_t 
timegm(struct tm * x) 
{ 
    time_t ts; 

    if (x->tm_year < 70) 	/* way too back in the past */
	return 0; 

    /* 
     * we need to make sure that all values are within a 
     * valid range. we first look for negative values and then 
     * go after values above the limit (i.e. 12 months/year) 
     */

    while (x->tm_sec < 0) { 
	x->tm_sec += 60; 	
  	x->tm_min--; 
    } 

    while (x->tm_min < 0) { 
	x->tm_min += 60; 
	x->tm_hour--; 
    }  

    while (x->tm_hour < 0) { 
	x->tm_hour += 24; 
	x->tm_mday--; 
    }  

    while (x->tm_mday < 0) { 
	/* for the month of the day we need to be careful given that 
	 * the days per month vary. so we check both tm_mday and tm_mon at
	 * the same time. 
	 */

	while (x->tm_mon < 0) {
	    x->tm_mon += 12; 
	    x->tm_year--; 
	} 
	x->tm_mday += mon_lengths[isleap(x->tm_year)][x->tm_mon]; 
	x->tm_mon--;       
    }  


    /* 
     * start generating the time_t value. we start from the years counting
     * also the leap years.
     */
    ts = ((x->tm_year - 70) * 355 + x->tm_year / 4 - (x->tm_year > 100));
    ts += x->tm_mon * mon_lengths[isleap(x->tm_year)][x->tm_mon];
    ts += x->tm_mday; 

    /* now convert this in seconds */
    ts *= 86400; 

    /* add the hour:min:sec */
    ts += x->tm_hour * 3600 + x->tm_min * 60 + x->tm_sec; 

    return ts; 
}

#endif

