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
 * This is the logging facility. 
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> 			/* va_start */
#include <string.h>
#include <errno.h>
#include <unistd.h>     
#include <dlfcn.h>
#include <assert.h>

#include "como.h"

extern struct _como map;	/* root of the data */


/** 
 * -- loglevel_name
 * 
 * Returns a string with the log message level. 
 * 
 * XXX It ignores the verbose flags. 
 */
char *
loglevel_name(int flags)
{
    static char s[1024];

    char *ui= flags & LOGUI ? "UI " : "";
    char *wa= flags & LOGWARN ? "WARN " : "";
    char *st= flags & LOGSTORAGE ? "STORAGE " : "";
    char *ca= flags & LOGCAPTURE ? "CAPTURE " : "";
    char *ex= flags & LOGEXPORT ? "EXPORT " : "";
    char *qu= flags & LOGQUERY ? "QUERY " : "";
    char *sn= flags & LOGSNIFFER ? "SNIFFER " : "";
    char *ti= flags & LOGTIMER ? "TIMER " : "";
    char *db= flags & LOGDEBUG ? "DEBUG " : "";

    sprintf(s, "%s%s%s%s%s%s%s%s%s", ui, wa, st, ca, ex, qu, sn, ti, db);
    return s;
}

static void
_logmsg(int flags, const char *fmt, va_list ap)
{
    static int printit;	/* one copy per process */
    char *buf;
    char *fmt1;
    struct timeval tv;

    if (flags)
        printit = (map.logflags & flags);
    if (!printit)
        return;
    gettimeofday(&tv, NULL);
    if (flags != LOGUI)
        asprintf(&fmt1, "[%5ld.%06ld %2s] %s",
		tv.tv_sec %86400, tv.tv_usec, map.procname, fmt);
    else
        asprintf(&fmt1, "%s", fmt);
    vasprintf(&buf, fmt1, ap);
    if (map.supervisor_fd >= 0) {
	//como_writen(map.supervisor_fd, buf, 0);
        /* XXX */
        void send_string(char *str);
        send_string(buf);
    } else {
	/* do not print messages to stdout when we are in inline mode */
        if (!map.il_mode) {
            fprintf(stdout, "%s", buf);
            fflush(stdout);
        }
    }
    free(fmt1);
    free(buf);
}


/** 
 * -- logmsg
 * 
 * Prints a message to stdout or sends it to the 
 * SUPERVISOR depending on the running loglevel.
 *
 */ 
void
logmsg(int flags, const char *fmt, ...)
{
    va_list ap;
    
    va_start(ap, fmt);
    _logmsg(flags, fmt, ap);
    va_end(ap);
}


/**
 * -- _epanic
 *
 * Not to be called directly, but through panic().
 * Prints the message on LOGUI together with the errno message. 
 * It aborts the program.
 *
 */
void
_epanic(const char * file, const int line, const char *fmt, ...)
{           
    char *fmt1, *buf;
    va_list ap;
 
    asprintf(&fmt1, "[%2s]  **** PANIC: (%s:%d) %s: %s\n",
        map.procname, file, line, fmt, strerror(errno));
    va_start(ap, fmt);
    vasprintf(&buf, fmt1, ap);
    va_end(ap);
    logmsg(LOGUI, "%s", buf);
    free(fmt1);
    free(buf);   
    abort();
}


/**
 * -- _epanicx
 * 
 * Not to be called directly, but through panic().
 * Prints the message on LOGUI without errno message 
 * and aborts the program. 
 *
 */
void
_epanicx(const char * file, const int line, const char *fmt, ...)
{
    char *fmt1, *buf;
    va_list ap;

    asprintf(&fmt1, "[%2s]  **** PANIC: (%s:%d) %s\n",
	map.procname, file, line, fmt);
    va_start(ap, fmt);
    vasprintf(&buf, fmt1, ap);
    va_end(ap);
    logmsg(LOGUI, "%s", buf);
    free(fmt1);
    free(buf);
    abort();
}


#define RLIMIT_HASH_ENTRIES 16

struct rlimit_hash_entry {
    struct rlimit_hash_entry *next;
    const char *fmt;
    struct timeval last_printed;
};

static struct rlimit_hash_entry *
rlimit_hash[RLIMIT_HASH_ENTRIES];

static struct rlimit_hash_entry *
get_rlimit_hash_entry(const char *fmt)
{
    unsigned long x;
    struct rlimit_hash_entry *e, **pprev;

    x = (unsigned long)fmt;
    while (x > RLIMIT_HASH_ENTRIES)
	x = (x / RLIMIT_HASH_ENTRIES) ^ (x % RLIMIT_HASH_ENTRIES);
    pprev = &rlimit_hash[x];
    e = *pprev;
    while (e && e->fmt != fmt) {
	pprev = &e->next;
	e = *pprev;
    }
    if (e)
	return e;
    e = calloc(sizeof(*e), 1);
    if (e == NULL)
	return NULL;
    e->fmt = fmt;
    *pprev = e;
    return e;
}

/* Rate limited log messages.  If this is called more than once every
   <interval> ms for a given fmt, drop the messages. */
void
rlimit_logmsg(unsigned interval, int flags, const char *fmt, ...)
{
    struct rlimit_hash_entry *e;
    static struct rlimit_hash_entry fallback_e = {NULL, NULL, {0,0}};
    struct timeval now, delta;
    va_list ap;

    /* Force interval to be less than a day to avoid overflows. */
    assert(interval < 86400000);
    e = get_rlimit_hash_entry(fmt);
    if (e == NULL) {
	e = &fallback_e;
	fmt = "DISCARDING MESSAGES DUE TO LACK OF MEMORY\n";
	flags = LOGWARN;
	interval = 1000;
    }
    gettimeofday(&now, NULL);
    delta.tv_sec = now.tv_sec - e->last_printed.tv_sec;
    delta.tv_usec = now.tv_usec - e->last_printed.tv_usec - interval * 1000;
    while (delta.tv_usec < 0) {
	delta.tv_usec += 1000000;
	delta.tv_sec--;
    }
    if (delta.tv_sec >= 0) {
	e->last_printed = now;
	va_start(ap, fmt);
	_logmsg(flags, fmt, ap);
	va_end(ap);
    }
}

/* end of file */
