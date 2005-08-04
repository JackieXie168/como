/*
 * Copyright (c) 2005 Intel Corporation
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>		/* write, read */
#include <ctype.h>
#include <assert.h>

#include "como.h"
#include "query.h"
#include "filter.h"

/*
 * Communication support for the query modules.
 * Essentially pack/unpack messages and make sure that we read them
 * atomically even if they are sent over a TCP socket.
 */

/*
 * urldecode() takes a string and decodes in-place the
 * url-encoded chars, initially %hh, in the future we might also
 * deal with some escape sequences &gt and the like.
 * The routine is not run often so we do not need to be efficient.
 */
static char *
urldecode(char *s)
{
    char c, *in, *out, **p;
    static char * char_encodings[] = {
	"<&lt;",
	">&gt;",
	NULL
    };
    static char hexdig[] = "0123456789abcdef";

    in = s;
    out = s;
    while ( (c = *in) != '\0') {
	if (c == '%') {
	    char *a = index(hexdig, in[1] | 0x20); /* convert to lowercase */
	    char *b = index(hexdig, in[2] | 0x20); /* convert to lowercase */
	    if (a != NULL && b != NULL) { /* valid digits */
		*out++ = (a - hexdig)* 16 + (b - hexdig);
		in += 3;
		continue;
	    }
	}
	if (c == '&') {
	    for (p = char_encodings; *p &&
		    bcmp((*p)+1, in, strlen( (*p)+1)); p++)
		;
	    if (*p != NULL) {
		*out++ = (*p)[0];
		in += strlen((*p)+1);
		continue;
	    }
	}
	/* default */
	*out++ = *in++;
    }
    *out = '\0';
    return s;
}


/**
 * query_parse()
 * Takes an http-like request and formats a message in the standard format
 * GET ?module=xxx&start=xxx&end=xxx&other HTTP/1.x
 */
static qreq_t *
query_parse(char *buf)
{
    static qreq_t q; 
    int nargs;
    char *p, *p1, *end;
    struct timeval t;

    /* 
     * do a first pass to figure out how much space we need
     * to store all the request parameters (i.e. args strings)
     * NOTE: nargs will always be at least one.
     */
    nargs = 0; 
    p = buf; 
    do { 
	p = strchr(p+1, '&'); 
	nargs++; 
    } while (p != NULL && strlen(p) > 1);

    /* allocate a new request data structures */
    q.args = safe_calloc(nargs, sizeof(char *)); 
    nargs = 0;

    /* provide some default values */
    asprintf(&q.filter, "ALL");
    q.len = sizeof(q);
    gettimeofday(&t, NULL);
    q.start = t.tv_sec - 50;
    q.end = t.tv_sec + 20;
    q.format = Q_OTHER; 

    /* 
     * check if the request is valid. look for GET and HTTP/1 
     * somewhere in the string. 
     */
    if (strstr(buf, "GET") != buf) {
	logmsg(LOGQUERY, "Malformed request %s\n", buf);
	return NULL;
    }

    end = strstr(buf, "HTTP/1");  
    if (end == NULL) {
	logmsg(LOGQUERY, "Malformed request %s\n", buf);
	return NULL;
    }
    
    /* mark the end of the useful string. walk backwards and 
     * remove any space at the end of the HTTP request. 
     */
    *end = '\0';
    for (; end > buf && index(" \t", *end) != NULL; end--)
	*end = '\0';

    /* after GET we expect whitespace then a string */
    for (p = buf + 3; *p && index(" \t", *p) != NULL; p++)
	;
    if (p == buf+3 || *p == '\0') {
	logmsg(LOGQUERY, "Malformed request %s\n", buf);
	return NULL;
    }
    for (; *p > ' ' && *p != '?'; p++)
	;
    if (*p != '?') {
	/* invalid module, but do not fail so we return a 'not found' */
	logmsg(LOGQUERY, "Malformed request %s\n", buf);
	return NULL; 
    }

    logmsg(LOGQUERY, "Good request %s\n", p);
    p = urldecode(p);
    while ( (p1 = strsep(&p, "?&")) != NULL) {
	logmsg(V_LOGQUERY, "Token %s %s\n", p1, p);
	if (p == p1+1)	/* empty string */
	    ;
	else if (strstr(p1, "module=") == p1) {
	    char * s = strchr(p1, '=');
	    asprintf(&q.module, "%s", s + 1); 
	} else if (strstr(p1, "filter=") == p1) {
#ifdef HAVE_FLEX_AND_BISON
            char * s;
            parse_filter(strchr(p1, '=') + 1, &s);
            asprintf(&q.filter, "%s", s);
            free(s);
#else
            char * s = strchr(p1, '=');
            asprintf(&q.filter, "%s", s + 1);
#endif	
        } else if (strstr(p1, "start=") == p1) {
	    q.start = atoi(p1+6);
	} else if (strstr(p1, "end=") == p1) {
	    q.end = atoi(p1+4);
        } else if (strstr(p1, "format=raw") == p1) {
	    q.format = Q_RAW;
        } else if (strstr(p1, "format=como") == p1) {
	    q.format = Q_COMO;
        } else if (strstr(p1, "status") == p1) {
	    q.format = Q_STATUS;
	} else {
	    logmsg(V_LOGQUERY, "custom argument: %s\n", p1);
	    q.args[nargs] = strdup(p1); 
	    nargs++;
	}
    }
    return &q;
}


/* 
 * -- qryrecv
 * 
 * receives a query from a TCP connection making sure that
 * the message is complete.
 * The query is formatted as an HTTP request so it must end with
 * an empty line.
 *
 */
qreq_t * 
qryrecv(int sd) 
{
    char buf[8*1024]; /* XXX large but arbitrary */
    int rd; 
    size_t ofs;

    /*
     * Read as much as possible from the socket.
     * The message must end with a pair of \n. 
     */
    ofs = 0; 
    bzero(buf, sizeof(buf));
    for (;;) {
	/* leave last byte unused, so we are sure to find a \0 there. */
	rd = read(sd, buf + ofs, sizeof(buf) - ofs - 1);
	logmsg(V_LOGQUERY, "qryrecv read returns %d\n", rd);
	if (rd < 0)	/* other end closed connection ? */
	    return NULL; 
	ofs += rd;

	if (strstr(buf, "\n\n") != NULL ||
		strstr(buf, "\n\r\n") != NULL) /* found terminator */
	    return query_parse(buf);
	if (rd == 0 || buf[0] < ' ')  /* invalid string */
	    break;
    }
    return NULL;
}
