/*
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
void init_setproctitle (int argc, char** argv);
int setproctitle (const char *fmt, ...);

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
#define	ETHERTYPE_IP	0x800
#define	ETHER_ADDR_LEN	6
struct ether_addr {
	unsigned char octet[ETHER_ADDR_LEN];
};

extern char *ether_ntoa(const struct ether_addr *n);
const char *inet_ntop(int af, const void *src, char *dst, size_t size);

extern const char *strcasestr(const char *s1, const char *s2);
#endif
 
#endif /* _COMO_OS_H_ */
