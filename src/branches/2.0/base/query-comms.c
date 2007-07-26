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
#include "hash.h"
#include "comopriv.h"

/*
 *
 * uri_unescape is taken from Abyss http server which comes with the
 * following license:
 *
 * Copyright (C) 2000 by Moez Mahfoudh <mmoez@bigfoot.com>.
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 */

/**
 * -- uri_unescape
 * 
 * Takes an URI and undecodes in-place the escaped charcters.
 */
static int
uri_unescape(char *uri)
{
    char *x, *y, c, d;

    x = y = uri;

    while (1) {
	switch (*x) {
	case '\0':
	    *y = '\0';
	    return 0;

	case '%':
	    x++;
	    c = (*x++) | 0x20;
	    if ((c >= '0') && (c <= '9'))
		c -= '0';
	    else if ((c >= 'a') && (c <= 'f'))
		c -= 'a' - 10;
	    else
		return -1;

	    d = (*x++) | 0x20;
	    if ((d >= '0') && (d <= '9'))
		d -= '0';
	    else if ((d >= 'a') && (d <= 'f'))
		d -= 'a' - 10;
	    else
		return -1;

	    *y++ = ((c << 4) | d);
	    break;

	case '+':
	    x++;
	    *y++ = ' ';
	    break;

	default:
	    *y++ = *x++;
	    break;
	}
    }
}

/* 
 * parse_relativetime
 * 
 * parses string of the form -3h5m10s from a given timestamp (base). 
 * 
 */ 
static time_t 
parse_relativetime(char * str, int multiplier, timestamp_t base)
{
    struct tm timeinfo; 
    time_t ts;
    int len; 

    /* get the base timestamp */
    ts = TS2SEC(base);
    gmtime_r(&ts, &timeinfo); 

    len = strlen(str); 

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
	    timeinfo.tm_mday += multiplier*val; 
	else if (str[0] == 'h') 		/* hour */
	    timeinfo.tm_hour += multiplier*val; 
	else if (str[0] == 'm')             /* minute */
	    timeinfo.tm_min += multiplier*val;
	else if (str[0] == 's') 		/* seconds */
	    timeinfo.tm_sec += multiplier*val; 
	else 				/* error */
	    break; 				

	/* skip letter */
	str++; len--;
    } 
    
    if (len > 0) {
	warn("time %s incorrect, using current time\n", str); 
	return ts; 
    }

    return (time_t) timegm(&timeinfo); 
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
    size_t len;

    assert(str != NULL); 
    assert(base != NULL); 

    switch (str[0]) { 
    case '@': 		/* absolute timestamp */
	ts = TS2SEC(*base);
	gmtime_r(&ts, &timeinfo); 
	len = strlen(str); 
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
	    warn("time %s incorrect, using current time\n", str); 
	    return TS2SEC(*base); 
	} 

	ts = timegm(&timeinfo); 
	*base = TIME2TS(ts, 0);
	break; 
	
    case '-': 		/* relative timestamp (before current time) */
        ts = parse_relativetime(str, -1, *base);
	break; 

    case '+': 	
    case ' ': 		/* XXX the plus sign is converted to space... */ 
        ts = parse_relativetime(str, 1, *base);
	break;

    case '0':
	return TS2SEC(*base);

    default: 	
	warn("time %s incorrect, using current time\n", str); 
	return TS2SEC(*base);
    } 

    return (uint32_t) ts; 
}
    

/*
 * -- query_parse()
 * 
 * Parses an HTTP request into a como request.
 * The HTTP requests is checked to be compliant with the RFC declaration:
 * Method SP Request-URI SP HTTP-Version CRLF
 * The only accepted method is GET.
 * To query a module the Request-Line should look like:
 * GET /<module name>?arguments HTTP/1.1
 * Example:
 * GET /traffic?time=-10s:0s&wait=no&format=html HTTP/1.1
 * When querying a module the following arguments are understood by the core:
 * - filter: the filter to identify the specific instance of a module
 * - format: the format of the output data. The values understood by the core
 *           are: raw, como, html
 * - start:  a UNIX timestamp identifying the initial timestamp of the query
 * - end:    a UNIX timestamp identifying the final timestamp of the query
 * - time:   another way to specify the query's initial and final timestamps
 * - source: the module to be used to feed the queried module
 * - wait:   a boolean argument specifying whether the query should wait until
 *           the final timestamp is reached (indefinitely if the final
 *           timestamp is not given) or give up when the data is not
 *           yet available
 * To query the node's status the Request-Line is:
 * GET /status HTTP/1.1
 * To access a service the Request-Line comes in the format:
 * GET /services/<service name> HTTP/1.1
 * This functions returns 0 if the query is parsed successfully. A negative
 * value is otherwise returned representing the HTTP response status that
 * qualifies the error.
 */
int
query_parse(qreq_t * q, char * buf, timestamp_t now)
{
    char *p, *t;
    query_ast_t * ast;
    int i;

    p = strchr(buf, '\n');
    *p = '\0';

    notice("HTTP request: %s\n", buf);

    /* provide some default values */
    memset(q, 0, sizeof(qreq_t));
    q->mode = QMODE_MODULE;
    q->start = TS2SEC(now);
    q->end = ~0;
    q->qu_format = NULL;
    q->format = NULL;
    q->wait = TRUE;
    q->args = hash_new(como_alc(), HASHKEYS_STRING, NULL, NULL);

    /* 
     * parse the request, and if successful, get its AST.
     */
    ast = parse_query_str(buf);
    if (ast == NULL || uri_unescape(ast->resource))
        return -400;

    if (strcmp(ast->resource, "/status") == 0) {
	q->mode = QMODE_SERVICE;
	q->service = "status";
    } else if (strncmp(ast->resource, "/services/", 10) == 0) {
	q->mode = QMODE_SERVICE;
	q->service = ast->resource + 10;
    } else {
        q->mode = QMODE_MODULE;
        q->module = ast->resource + 1;
    }

    /*
     * get the arguments.
     *
     * we may leak some mem but we do not care, as the
     * maximum query string length is not large and
     * this is done once during the process' lifetime.
     */
    for (i = 0; i < ast->nkeyvals; i++) {
        char *name = ast->keyvals[i].key;
        char *value = ast->keyvals[i].val;
        int insert_arg = TRUE;

        if (uri_unescape(name) == -1 || uri_unescape(value) == -1)
            return -400;

        #define if_have_kw(k) if (strcmp(name, k) == 0)
        
        switch (*name) {
            case 'm':
                if_have_kw("module") {
                    q->module = como_strdup(value);
                    insert_arg = FALSE;
                }
                break;
            case 'f':
                if_have_kw("filter") {
                    q->filter_str = como_strdup(value);
                    parse_filter(value, NULL, &(q->filter_cmp));
                    insert_arg = FALSE;
                }
                else if_have_kw("format") {
                    q->format = como_strdup(value);
                    insert_arg = FALSE;
                }
                break;
            case 's':
                if_have_kw("start") {
                    q->start = atoi(value);
                    insert_arg = FALSE;
                } else if_have_kw("source") {
                    q->source = como_strdup(value);
                    insert_arg = FALSE;
                } else if_have_kw("status") {
                    q->mode = QMODE_SERVICE;
                    q->service = "status";
                    insert_arg = FALSE;
                }
                break;
            case 'e':
                if_have_kw("end") {
                    q->end = atoi(value);
                    insert_arg = FALSE;
                }
                break;
            case 'w':
                if_have_kw("wait") {
                    if (strcmp(value, "no") == 0)
                        q->wait = FALSE;
                    insert_arg = FALSE;
                }
                break;
            case 't':
                if_have_kw("time") {
                    timestamp_t current;
                    current = now;
                    t = strchr(value, ':');
                    if (t != NULL) {
                        *t = '\0';
                        q->start = parse_timestr(value, &current);
                        q->end = parse_timestr(t + 1, &current);
                        insert_arg = FALSE;
                    }
                }
                break;
        }

        if (insert_arg == TRUE)
            hash_insert_string(q->args, name, value);
    }
    
    return 0;
}


/* 
 * -- query_recv
 * 
 * Receives a query from a TCP connection making sure that
 * the message is complete.
 * The query is formatted as an HTTP request so it must end with
 * an empty line.
 *
 */
int 
query_recv(qreq_t * q, int sd, timestamp_t now) 
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

	debug("query_recv from fd %d read returns %d\n", sd, rd);

	if (rd < 0)	/* other end closed connection ? */
	    return -1; 
	ofs += rd;

	if (strstr(buf, "\r\n\r\n") != NULL || strstr(buf, "\n\n") != NULL)
	    return query_parse(q, buf, now); 

	if (rd == 0 || buf[0] < ' ')  /* invalid string */
	    break;
    }
    return -1;
}

