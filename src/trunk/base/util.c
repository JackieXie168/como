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
#include <sys/types.h>			/* inet_ntop */
#include <sys/socket.h>
#include <sys/un.h>			/* sockaddr unix */
#include <netinet/in.h>
#include <arpa/inet.h>
#undef __unused        /* XXX linux's netdb.h has a variable with this name */
#include <netdb.h>                     /* gethostbyname */

#ifdef linux
#include <netinet/ether.h> 		/* ether_ntoa */
#endif
#include <assert.h>

#include "como.h"

extern struct _como map;	/* root of the data */


/* 
 * keeps reading until complete. 
 */
int
como_readn(int fd, char *buf, size_t nbytes)
{
    int n = 0;
    
    while (n < (int) nbytes) {
        int ret = read(fd, buf + n, nbytes - n);
        if (ret == -1)
            return -1;
        if (ret == 0) /* EOF */
            break;
        
        n += ret;
    }
    
    return n; /* <= nbytes */
}

/*
 * keeps writing until complete. If nbytes = 0, we assume it is
 * a string and do a strlen here.
 */
int
como_writen(int fd, const char *buf, size_t nbytes)
{
    size_t n = 0;

    if (nbytes == 0)
	nbytes = strlen(buf);
    while (n < nbytes) {
	int ret = write(fd, buf + n, nbytes - n);

	if (ret == -1)
	    return -1;

        n += ret;
    }
   
    return n; /* == nbytes */
}

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
    char *db= flags & LOGDEBUG ? "DEBUG " : "";

    sprintf(s, "%s%s%s%s%s%s%s", ui, wa, st, ca, ex, qu, db);
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
	como_writen(map.supervisor_fd, buf, 0);
    } else {
	fprintf(stdout, "%s", buf);
	fflush(stdout);
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
        fprintf(stderr, "[%2s]  **** PANIC: malloc (%s:%d): %s\n",
            map.procname, file, line, strerror(errno));
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
	fprintf(stderr, "[%2s]  **** PANIC: calloc (%s:%d)\n", 
	    map.procname, file, line);
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
            map.procname, file, line);
        abort();
    }
    
    return v;
}


/**
 * -- load_object
 *
 * dynamically links a library in. used for all modules as
 * well as for the filters.
 * 
 * XXX in the future we may want to use it for sniffers as well.
 *
 */
void *
load_object(char *base_name, char *symbol)
{
    void *handle, *sym;

    handle = dlopen(base_name, RTLD_NOW);
    if (handle == NULL) {
        logmsg(LOGCONFIG, "dlopen(%s, RTLD_NOW) error [%s]\n",
                base_name, dlerror());
        return NULL;
    }
    sym = dlsym(handle, symbol);
    if (sym == NULL) {
        logmsg(LOGCONFIG, "module %s missing '%s' (%s)\n",
                base_name, symbol, dlerror());
        dlclose(handle);
        return NULL;
    }
    logmsg(LOGCONFIG, "loaded shared object %s\n", base_name);

    return (void *) sym;
}


/*
 * Create either a unix domain or tcp socket.
 * A prefix of S: indicates open in server mode, otherwise client.
 * Another prefix of http:// indicates inet, otherwise unix
 * Follows the ip:port/local part or the pathname relative to the
 * working directory.
 * If passed a URL (starting with http://), creates a sockets in client mode.
 * If arg is supplied, then returns a pointer to a malloced string
 * with the local part of the URL.
 * Otherwise creates a unix domain socket, in client or server mode.
 * XXX If the pathname does not start with / or ., we prepend map.workdir
 */
int
create_socket(const char *path, char **arg)
{
    struct sockaddr_un sun;
    struct sockaddr_in saddr;
    struct sockaddr *sa;
    int i, r, l;
    char *buf = NULL;
    int server = 0;

    if (strcasestr(path, "s:") == path) {
	server = 1;
	path += 2;
    }
    if (strcasestr(path, "http://") == path) {
	int opt;
	char *host = strdup(path+7);
	char *port;
	char *local = NULL;

	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	/* locate first : or / */
	for (port = host; *port && *port != '/' && *port != ':'; port++)
	    ;
	if (*port != ':') {
	    logmsg(LOGWARN, "missing port in %s\n", path);
error:
	    free(host);
	    return -1;
	}
	*port = '\0';
	if (server && strcasecmp(host, "localhost") == 0) {
	    logmsg(LOGWARN, "binding local port in %s\n", path);
	    saddr.sin_addr.s_addr = INADDR_ANY;
	} else if (!inet_aton(host, &saddr.sin_addr)) { /* not numeric */
	    struct hostent *hp = gethostbyname(host) ;

	    if (hp != NULL)
                saddr.sin_addr = *((struct in_addr *)hp->h_addr);
	}

	saddr.sin_port = htons(strtol(port+1, &local, 10));
	if (local == port+1) {
	    logmsg(LOGWARN, "missing port in %s\n", path);
	    goto error;
	}
	if (*local) {
	    if (*local != '/') {
		logmsg(LOGWARN, "bad local in %s\n", path);
		goto error;
	    }
	    local++;
	}
	i = socket(AF_INET, SOCK_STREAM, 0);
	/* allow local address reuse in TIME_WAIT */
	opt = 1;
	setsockopt(i, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (arg)
	    *arg = strdup(local);
	free(host);
	sa = (struct sockaddr *)&saddr;
	l = sizeof(saddr);
    } else {
	/* unix domain */
	i = socket(AF_UNIX, SOCK_STREAM, 0);
	if (path[0] != '/' && path[0] != '.')
	    asprintf(&buf, "%s/%s", map.workdir, path);
	path = buf;
	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));
	sa = (struct sockaddr *)&sun;
	l = sizeof(sun);
    }
    if (server) {
	r = bind(i, sa, l);
	if (r < 0)
	    panic("create_socket: cannot bind [%s] %d\n", path, r);
	listen(i, SOMAXCONN);
    } else { /* client mode */
	int done, retries;
	for (done = 0, retries = 0; !done && retries < 10; retries++) {
	    r = connect(i, sa, l);
	    if (r == 0)
		done = 1;
	}
	if (!done)
	    panic("create_socket: cannot connect [%s] %d\n", path, i);
    }
    logmsg(LOGDEBUG, "create_socket %s [%s] %d\n",
	server ? "SERVER":"CLIENT", path, i);
    if (buf)
	free(buf);
    return i;
}


/* 
 * -- getprotoname
 * 
 * this function is basically getprotobynumber() that needs to 
 * be redefined here because linux's netdb.h uses __unused as  
 * variable name (?!?). In order to avoid the mess, it is easier
 * to rewrite the function from scratch. 
 * 
 */
char *
getprotoname(int proto) 
{
    static char * alias[256] = {0}; 
    int i; 

    /* if alias array is not initialize, open /etc/protocols to 
     * read the protocol names.
     */
    if (alias[0] == NULL) { 
	FILE * fp; 
	char line[120];

	/* 
	 * set all protocol aliases to the number 
 	 */
	for (i = 0; i < 256; i++) 
	    asprintf(&alias[i], "%d", i); 

	/* open /etc/protocols and read all defined names */
	fp = fopen("/etc/protocols", "r"); 
	if (fp == NULL) 
	    panic("opening /etc/protocols"); 
	
	while (!feof(fp)) { 
	    char name[128]; 
	    char * wh; 
	    int number; 

	    fgets(line, 120, fp); 
	    wh = index(line, '#'); 
	    if (wh != NULL) 
		*wh = 0; 		/* remove comments */

	    if (sscanf(line, "%s %d", name, &number) == 2) 
		if (number < 256) 
		    alias[number] = strdup(name); 
	} 
    } 

    return alias[proto]; 
}
	    

#if 0 

/*
 * Debugging code.
 * XXX is never used in any part of the code. But we still keep it
 * in case it turns out to be useful (lr 2005.02.16)
 */
/*
 * op == 0: set counter to value
 * op != 0: add value to counter
 */
void
count_set(int off, int op, int value, char *name)
{
    ctr_t *ctr = &map.stats.base,
    *last = &map.last_stats.base,
    *t = &map.stats_times.base;

    ctr[off] = op ? ctr[off] + (uint)value : (uint)value;
    if ((uint)map.now.tv_sec != t[off]) {
        t[off] = map.now.tv_sec;
        logmsg(V_LOGDEBUG, "COUNT %8d [%8d] %s\n",
            ctr[off], ctr[off] - last[off], name);
        fflush(stdout);
        last[off] = ctr[off];
    }
}
#endif

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
