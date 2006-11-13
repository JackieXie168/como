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
 * $Id: util-socket.c 978 2006-11-01 15:23:18 +0000 (Wed, 01 Nov 2006) m_canini $
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


/*
 * -- create_socket()
 * 
 * Create either a unix domain or tcp socket.
 * 
 */
int
create_socket(const char * path, int is_server)
{
    struct sockaddr_un sun;
    struct sockaddr_in saddr;
    struct sockaddr *sa;
    int fd, r;
    size_t l;
    int is_tcp = TRUE;
    char *cp;

    if (path[0] == '/') {
	is_tcp = FALSE;
    } else if (strncmp("http://", path, 7) == 0) {
	path += 7;
    }
    
    cp = como_strdup(path);

    if (is_tcp) {
	/* TCP socket */
	int opt;
	char *host;
	char *port;

	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	
	port = strchr(cp, ':');
	if (port == NULL) {
	    error("Missing port number in %s.\n", cp);
	}
	
	*port = '\0';
	port += 1;
	host = cp;
	
	if (is_server && strcmp(host, "localhost") == 0) {
	    saddr.sin_addr.s_addr = INADDR_ANY;
	} else if (!inet_aton(host, &saddr.sin_addr)) {
	    /* not numeric */
	    struct hostent *hp = gethostbyname(host) ;

	    if (hp == NULL) {
		warn("gethostbyname() failed: %s\n", hstrerror(h_errno));
		free(cp);
		return -1;
	    }

	    saddr.sin_addr = *((struct in_addr *) hp->h_addr);
	}

	
	saddr.sin_port = htons(atoi(port));

	fd = socket(AF_INET, SOCK_STREAM, 0);
	/* allow local address reuse in TIME_WAIT */
	opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	sa = (struct sockaddr *) &saddr;
	l = sizeof(saddr);
    } else {
	/* unix domain */
	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, cp, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	sa = (struct sockaddr *) &sun;
	l = sizeof(sun);
    }
    if (is_server) {
	int i;
	i = is_tcp ? 1 : 2;
	while (i--) {
	    r = bind(fd, sa, l);
	    if (r == 0)
		break;

	    /*
	     * try to unlink path before giving up. maybe the previous
	     * process has died without cleaning up the socket file
	     */
	    unlink(cp);
	}
	if (r < 0) {
	    warn("Can't bind socket: %s\n", strerror(errno));
	    free(cp);
	    return -1;
	}
	listen(fd, SOMAXCONN);
    } else {
	/* client mode */
	int i;
	i = 10;
	while (i--) {
	    r = connect(fd, sa, l);
	    if (r == 0)
		break;
	}
	if (r < 0) {
	    warn("Can't connect to %s: %s.\n", cp, strerror(errno));
	    free(cp);
	    return -1;
	}
    }
    free(cp);
    
    return fd;
}


int
destroy_socket(const char * path)
{
    int is_tcp = TRUE;

    assert(path != NULL);
    if (path[0] == '/') {
	is_tcp = FALSE;
    }

    if (is_tcp == FALSE) {
	int r;
	r = unlink(path);
	return r;
    }
    return 0;

}



