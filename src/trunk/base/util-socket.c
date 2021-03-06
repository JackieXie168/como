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
#include <err.h>
#include <unistd.h>     
#include <dlfcn.h>
#include <sys/types.h>			/* inet_ntop */
#include <sys/socket.h>
#include <sys/un.h>			/* sockaddr unix */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>

#include "como.h"

extern struct _como map; 

/*
 * -- create_socket()
 * 
 * Create either a unix domain or tcp socket.
 * A prefix of S: indicates open in server mode, otherwise client.
 * Another prefix of http:// indicates inet, otherwise unix
 * Follows the ip:port/local part or the pathname relative to the
 * working directory.
 * If passed a URL (starting with http://), creates a sockets in client mode.
 * If arg is supplied, then returns a pointer to a malloced string
 * with the local part of the URL.
 * Otherwise creates a unix domain socket, in client or server mode.
 * 
 * XXX If the pathname does not start with / or ., we prepend map.workdir
 * 
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
    int http = 1;

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
	if (*port != ':') 
	    errx(EXIT_FAILURE, "missing port in %s\n", path);

	*port = '\0';
	if (server && strcasecmp(host, "localhost") == 0) {
	    saddr.sin_addr.s_addr = INADDR_ANY;
	} else if (!inet_aton(host, &saddr.sin_addr)) { /* not numeric */
	    struct hostent *hp = gethostbyname(host) ;

	    if (hp != NULL)
                saddr.sin_addr = *((struct in_addr *)hp->h_addr);
	}

	saddr.sin_port = htons(strtol(port+1, &local, 10));
	if (local == port+1)
	    errx(EXIT_FAILURE, "missing port in %s\n", path);
	if (*local) {
	    if (*local != '/') 
		errx(EXIT_FAILURE, "bad local in %s\n", path);
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
	http = 0;
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
try_rebind:
	r = bind(i, sa, l);
	if (r < 0) {
	    if (http == 0) {
	    	/*
	    	 * try to unlink path before giving up. maybe the previous
	    	 * process has died without cleaning up the socket file
	    	 */
	    	 unlink(path);
	    	 http = 1; /* trick to exit if bind fails again */
	    	 goto try_rebind;
	    }
	    err(EXIT_FAILURE, "create_socket: cannot bind [%s] %d\n", path, r);
	}
	listen(i, SOMAXCONN);
    } else { /* client mode */
	int done, retries;
	for (done = 0, retries = 0; !done && retries < 10; retries++) {
	    r = connect(i, sa, l);
	    if (r == 0)
		done = 1;
	}
	if (!done)
	    err(EXIT_FAILURE, "create_socket: cannot connect [%s] %d", path, i);
    }
    logmsg(LOGIPC, "create_socket %s [%s] %d\n",
	server ? "SERVER":"CLIENT", path, i);
    if (buf)
	free(buf);
    return i;
}

int
destroy_socket(const char *path)
{
    char *buf = NULL;
    
    asprintf(&buf, "%s/%s", map.workdir, path);
	
    return unlink(buf);
}

/*
 * -- add_fd
 *
 * add a file descriptor to the interesting range;
 * return maxfd value to be used in select().
 */ 
int
add_fd(int i, fd_set * fds, int max_fd)
{
    if (i < 0) 
	return max_fd; 

    FD_SET(i, fds);
    return (i >= max_fd)? i + 1 : max_fd; 
}
       

/*
 * -- del_fd
 *
 * delete a file descriptor to the interesting range;
 * return maxfd value to be used in select().
 */ 
int
del_fd(int i, fd_set * fds, int max_fd)
{
    if (i < 0) 
	return max_fd; 

    FD_CLR(i, fds);
    if (i < max_fd - 1)
        return max_fd;

    /* we deleted the highest fd, so need to recompute the max */
    for (i = max_fd - 1; i >= 0; i--)
        if (FD_ISSET(i, fds))
            break;
    return i + 1; 
}


