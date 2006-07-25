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

/*
 * Here we deal with all os-specific dependencies that can be
 * solved by the compiler.
 */
#ifndef _COMO_OS_H_
#define _COMO_OS_H_

    /***					***/
    /***		Linux			***/
    /***					***/

#ifdef linux
#define _GNU_SOURCE	/* Required to use asprintf in Linux */
/*
 * EPROGUNAVAIL is not defined in Linux
 */
#define EPROGUNAVAIL ENOTSUP
#endif

#if defined(linux) || defined(__CYGWIN32__)
/*
 * FreeBSD has __unused defined in the system's header.
 * We redefine it here as we need a shorter form for this anyways.
 */
#define __unused __attribute__((__unused__))

/*
 * MAP_NOSYNC is unavailble in Linux 
 * XXX: beware! This is not a general solution
 */
#define MAP_NOSYNC 0


/*
 * setproctitle(3) is unavailable in Linux; we provide one here
 * Please call init_setproctitle before calling setproctitle
 * for the first time.
 */
void setproctitle_init (int argc, char **argv);
void setproctitle      (const char *format, ...);

#endif /* linux */

    /***					***/
    /***		FreeBSD			***/
    /***					***/

#ifdef __FreeBSD__

/*
 * Unclear if there is a portable solution for NAMLEN. In the meantime
 * we use the one used in Linux
 */
#define _D_EXACT_NAMLEN(f) ((f)->d_namlen)

/* This function is a GNU extension */
char *strndup(const char *s, unsigned int n);

/*
 * ENODATA is not defined in Linux
 */
#define ENODATA EINVAL

#endif /* FreeBSD */

#if defined(__CYGWIN32__)

#include <sys/types.h>
#define _D_EXACT_NAMLEN(f) (strlen((f)->d_name)) /* XXX check this */
extern char *mkdtemp(char *template);
extern char *mktemp(char *template);

#include <sys/stat.h>	// mkdir
#define	ETHERTYPE_IP	0x0800
#define	ETHER_ADDR_LEN	6
struct ether_addr {
	unsigned char octet[ETHER_ADDR_LEN];
};

#define IPPROTO_ESP	50

extern char *ether_ntoa(const struct ether_addr *n);
const char *inet_ntop(int af, const void *src, char *dst, size_t size);

extern const char *strcasestr(const char *s1, const char *s2);
time_t timegm(struct tm * x); 

#endif
 
#endif /* _COMO_OS_H_ */
