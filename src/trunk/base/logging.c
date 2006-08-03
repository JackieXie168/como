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
#include "ipc.h"

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

    sprintf(s, "%s%s%s%s%s%s%s%s", ui, wa, st, ca, ex, qu, sn, ti);
    return s;
}


void
displaymsg(FILE *f, procname_t sender, logmsg_t *lmsg)
{
    if (lmsg->flags != LOGUI) {
    	fprintf(f, "[%5ld.%06ld %2s] ",
		lmsg->tv.tv_sec % 86400, lmsg->tv.tv_usec,
		getprocname(sender));
    }
    fprintf(f, "%s", lmsg->msg);
}


/** 
 * -- _logmsg
 * 
 * Prints a message to stdout or sends it to the 
 * SUPERVISOR depending on the running loglevel.
 *
 */ 
void
_logmsg(const char * file, int line, int flags, const char *fmt, ...)
{
    va_list ap;
    static int printit;	/* one copy per process */
    int len;
#define STATIC_BUF_LEN 128
    static char static_buf[STATIC_BUF_LEN];
    static logmsg_t *lmsg = (logmsg_t *) static_buf;
    static int buf_len = STATIC_BUF_LEN - sizeof(logmsg_t);
    
    /* last msg variables */
    static char static_last[STATIC_BUF_LEN];
    static logmsg_t *last_lmsg = (logmsg_t *) static_last;
    static const char *last_file;
    static int last_line;
    static int seen_count;

    /* fmt = NULL causes logmsg to clean some state */
    if (fmt == NULL) {
	last_file = NULL;
	last_line = 0;
	seen_count = 0;
	return;
    }

    if (flags)
        printit = (map.logflags & flags);
    if (!printit)
        return;
    
    gettimeofday(&lmsg->tv, NULL);
    lmsg->flags = flags;
    
    va_start(ap, fmt);
    
    /* format the message */
    len = 1 + vsnprintf(lmsg->msg, buf_len, fmt, ap);
    
    /* manage the message buffer */
    if (len > buf_len) {
    	if (buf_len * 2 > len) {
	    buf_len *= 2;
    	} else {
	    buf_len = buf_len + len + (buf_len / 4);
	    if (buf_len % 4) {
		buf_len += 4 - buf_len % 4;
	    }
    	}
	if (lmsg != (logmsg_t *) static_buf) {
	    lmsg = safe_realloc(lmsg, buf_len + sizeof(logmsg_t));
	    last_lmsg = safe_realloc(last_lmsg, buf_len + sizeof(logmsg_t));
	} else {
	    lmsg = safe_malloc(buf_len + sizeof(logmsg_t));
	    memcpy(lmsg, static_buf, sizeof(logmsg_t));
	    last_lmsg = safe_malloc(buf_len + sizeof(logmsg_t));
	    memcpy(last_lmsg, static_last, sizeof(logmsg_t));
	    strcpy(last_lmsg->msg, ((logmsg_t *) static_last)->msg);
	}
	/* CHECKME: need va_end, va_start? */
	len = 1 + vsnprintf(lmsg->msg, buf_len, fmt, ap);
    }
    
    /* detect already printed messages */
    if (last_line == line && last_file == file) {
	if (strcmp(last_lmsg->msg, lmsg->msg) == 0) {
	    seen_count++;
	    va_end(ap);
	    return;
	}
    }
    
    if (seen_count > 0) {
	logmsg_t *seen_msg;
	int seen_len;
	int last_len;
	/* notify of previoulsy repeated message */
	last_len = strlen(last_lmsg->msg);
	seen_len = sizeof(logmsg_t) + last_len + 64;
	seen_msg = alloca(seen_len);
	seen_msg->tv = last_lmsg->tv;
	seen_msg->flags = last_lmsg->flags;
	strncpy(seen_msg->msg, last_lmsg->msg, last_len);
	if (*(seen_msg->msg + last_len - 1) != '\n') {
	    /* add a trailing \n to last msg if there's none */
	    *(seen_msg->msg + last_len) = '\n';
	    last_len++;
	}
	last_len += snprintf(seen_msg->msg + last_len, 64,
			     "    -- Last message repeated %d time%s.\n",
			     seen_count, (seen_count > 1) ? "s" : "");
	if (map.whoami != SUPERVISOR) 
	    ipc_send(SUPERVISOR, IPC_ECHO, seen_msg,
		     sizeof(logmsg_t) + last_len + 1); 
	else 
	    displaymsg(stdout, map.whoami, seen_msg);
	seen_count = 0;
    }
    
    /* save the message */
    memcpy(last_lmsg, lmsg, sizeof(logmsg_t));
    last_line = line;
    last_file = file;
    strncpy(last_lmsg->msg, lmsg->msg, len);
    
    
    if (map.whoami != SUPERVISOR) 
        ipc_send(SUPERVISOR, IPC_ECHO, lmsg, sizeof(logmsg_t) + len);
    else 
	displaymsg(stdout, map.whoami, lmsg);
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
_epanic(const char * file, int line, const char *fmt, ...)
{           
    char *fmt1, *buf;
    va_list ap;
 
    asprintf(&fmt1, "[%2s]  **** PANIC: (%s:%d) %s: %s\n",
        getprocname(map.whoami), file, line, fmt, strerror(errno));
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
_epanicx(const char * file, int line, const char *fmt, ...)
{
    char *fmt1, *buf;
    va_list ap;

    asprintf(&fmt1, "[%2s]  **** PANIC: (%s:%d) %s\n",
	getprocname(map.whoami), file, line, fmt);
    va_start(ap, fmt);
    vasprintf(&buf, fmt1, ap);
    va_end(ap);
    logmsg(LOGUI, "%s", buf);
    free(fmt1);
    free(buf);
    abort();
}

/* end of file */
