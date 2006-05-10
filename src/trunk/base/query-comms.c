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
#include <sys/time.h>		/* struct timeval */
#include <sys/uio.h>		/* write, read */
#include <ctype.h>
#include <assert.h>
#include <time.h>

#include "como.h"
#include "query.h"

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


/* 
 * -- parse_timestr()
 * 
 * This function parse the time string of a query. The string is made of 
 * two parts representing the two extreme of the time window. They two 
 * parts are separated by a colon (:). 
 * Valid formats for the start and end times are as follows: 
 * 
 *   .   0, to indicate the time the query is received;
 *   .   @[cc[yy[mm[dd[hhmmss]]]]], to indicate an exact time; 
 *   .   [+|-][[^0-9]d][[^0-9]h][[^0-9]m][[^0-9]s], to indicate an offset 
 *       from the time the query is received.  
 * 
 */
static uint32_t
parse_timestr(char * str, timestamp_t * base) 
{
    struct tm timeinfo; 
    time_t ts;
    char * wh; 
    size_t len;
    int adding; 

    assert(str != NULL); 
    assert(base != NULL); 

    ts = TS2SEC(*base);
    gmtime_r(&ts, &timeinfo); 

    /* look if this is a start or end */
    wh = index(str, ':'); 
    len = (wh == NULL)? strlen(str) : (size_t) (wh - str); 
    adding = 0; 

    switch (str[0]) { 
    case '@': 		/* absolute timestamp */
	for (str++, len--; len > 0; str += 2, len -= 2) { 
	    char val[3] = {0}; 

	    /* get two digits */
	    bcopy(str, val, 2); 

	    if (len == 14)  			/* century */
		timeinfo.tm_year = (atoi(val) * 100) - 1900; 
	    else if (len == 12)  		/* year */
		timeinfo.tm_year = atoi(val) + 100*(timeinfo.tm_year/100); 
	    else if (len == 10)  		/* month */
		timeinfo.tm_mon = atoi(val) - 1; 
	    else if (len == 8)  		/* day */
		timeinfo.tm_mday = atoi(val); 
	    else if (len == 6)  		/* hour */
		timeinfo.tm_hour = atoi(val); 
	    else if (len == 4)  		/* minute */
		timeinfo.tm_min = atoi(val); 
	    else if (len == 2)  		/* second */
		timeinfo.tm_sec = atoi(val); 
	    else 				/* error */
		break; 				
	} 
		
	if (len > 0) {
	    logmsg(LOGWARN, "time %s incorrect, using current time\n", str); 
	    return TS2SEC(*base); 
	} 

	ts = timegm(&timeinfo); 
	*base = TIME2TS(ts, 0);
	break; 
	
    case '+': 		/* relative timestamp (after current time) */
	adding = 2; 
	/* pass thru */

    case '-': 		/* relative timestamp (before current time) */
	adding--; 
	
        /* skip first character */
	str++; len--; 

	/* check for one letter (in [dhms]) at a time */ 
	while (len > 0) { 
	    int x; 
	    int val; 

	    val = atoi(str); 
 	    x = strspn(str, "1234567890"); 
	    str += x; 
	    len -= x; 

	    if (str[0] == 'd') 			/* day */
                timeinfo.tm_mday += adding*val; 
            else if (str[0] == 'h') 		/* hour */
                timeinfo.tm_hour += adding*val; 
            else if (str[0] == 'm')             /* minute */
                timeinfo.tm_min += adding*val;
            else if (str[0] == 's') 		/* seconds */
                timeinfo.tm_sec += adding*val; 
	    else 				/* error */
		break; 				

	    /* skip letter */
	    str++; len--;
	} 
	
	if (len > 0) {
	    logmsg(LOGWARN, "time %s incorrect, using current time\n", str); 
	    return (uint32_t) timegm(&timeinfo); 
	} 

	ts = timegm(&timeinfo); 
	break; 

    default: 		/* nothing set, use current time */
	break;
    } 

    return (uint32_t) ts; 
}
    

/*
 * -- query_parse()
 * 
 * Takes an http-like request and formats a message in the standard format
 * GET ?module=xxx&start=xxx&end=xxx&other HTTP/1.x
 */
static qreq_t *
query_parse(char *buf, timestamp_t now)
{
    static qreq_t q; 
    int max_args, nargs;
    char *p, *p1, *end;

    /* 
     * do a first pass to figure out how much space we need
     * to store all the request parameters (i.e. args strings)
     * 
     * NOTE: max_args will always be at least one (i.e., the NULL entry
     *       to indicate end of the arguments). 
     */
    max_args = 0; 
    p = buf; 
    do { 
	p = strchr(p+1, '&'); 
	max_args++; 
    } while (p != NULL && strlen(p) > 1);

    /* allocate a new request data structures */
    q.args = safe_calloc(max_args, sizeof(char *)); 
    nargs = 0;

    /* provide some default values */
    q.len = sizeof(q);
    q.start = TS2SEC(now) - 50;
    q.end = TS2SEC(now) + 20;
    q.format = Q_OTHER; 
    q.wait = 1;
    q.source = NULL;

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

    logmsg(V_LOGQUERY, "Good request %s\n", p);
    p = urldecode(p);
    while ( (p1 = strsep(&p, "?&")) != NULL) {
	logmsg(V_LOGQUERY, "Token %s %s\n", p1, p);
	if (p == p1+1)	/* empty string */
	    ;
	else if (strstr(p1, "module=") == p1) {
	    char * s = strchr(p1, '=');
	    asprintf(&q.module, "%s", s + 1); 
	} else if (strstr(p1, "filter=") == p1) {
	    char * s = strchr(p1, '=');
	    q.filter_str = strdup(s + 1);
	    parse_filter(s + 1, NULL, &(q.filter_cmp));
	} else if (strstr(p1, "start=") == p1) {
	    q.start = atoi(p1+6);
	} else if (strstr(p1, "end=") == p1) {
	    q.end = atoi(p1+4);
        } else if (strstr(p1, "format=raw") == p1) {
	    q.format = Q_RAW;
        } else if (strstr(p1, "format=como") == p1) {
	    q.format = Q_COMO;
        } else if (strstr(p1, "format=html") == p1) {
	    q.format = Q_HTML;
	    /* we forward this to the module */
	    q.args[nargs] = strdup(p1); 
	    nargs++;
	    assert(nargs < max_args);
        } else if (strstr(p1, "wait=no") == p1) {
	    q.wait = 0; 
        } else if (strstr(p1, "status") == p1) {
	    q.format = Q_STATUS;
        } else if (strstr(p1, "time=") == p1) {
	    timestamp_t current; 
	    char * str; 
	
	    current = now; 
            str = index(p1, '=') + 1; 
	    q.start = parse_timestr(str, &current); 

	    str = index(p1, ':') + 1; 
	    q.end = parse_timestr(str, &current);
	} else if (strstr(p1, "source=") == p1) {
            char * s = strchr(p1, '=');
            q.source = strdup(s + 1);
        } else {
	    logmsg(V_LOGQUERY, "custom argument: %s\n", p1);
	    q.args[nargs] = strdup(p1); 
	    nargs++;
	    assert(nargs < max_args);
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
qryrecv(int sd, timestamp_t now) 
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
	    return query_parse(buf, now);
	if (rd == 0 || buf[0] < ' ')  /* invalid string */
	    break;
    }
    return NULL;
}
