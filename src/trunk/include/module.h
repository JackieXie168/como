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
 */

#ifndef _COMO_MODULE_H
#define _COMO_MODULE_H

#include <string.h>		/* memcpy */

#include "stdpkt.h"
#include "comotypes.h"
#include "comofunc.h"

/*
 * Some useful macros to write modules
 */

/*
 * FLOWDESC/EFLOWDESC are supposed to be defined by individual
 * modules as the type to be used for flow descriptors. If so,
 * here we define an F()/EF() macro to cast a pointer to
 * (FLOWDESC/EFLOWDESC *) to make the writing of modules more
 * convenient.
 */
#define F(x)     ((FLOWDESC *)(((char *) x) + sizeof(rec_t)))
#define EF(x)    ((EFLOWDESC *)(((char *) x) + sizeof(rec_t)))

/*
 * One more indirection is needed within compare_fn()
 */
#define CMPEF(x) ((EFLOWDESC *)((*(char **) x) + sizeof(rec_t)))

/*
 * Macros to copy integers from host to network byte order. 
 * They advance the buffer pointer of the proper amount as well. 
 * This macros are supposed to be used by store()
 */
#define PUTH8(x, val) {         \
    uint8_t v = val;            \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 1; 	\
}

#define PUTH16(x, val) {        \
    uint16_t v = htons(val);    \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 2;	\
}

#define PUTH32(x, val) {        \
    uint32_t v = htonl(val);    \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 4; 	\
}

#define PUTH64(x, val) {        \
    uint64_t v = HTONLL(val);   \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 8; 	\
}

/*
 * Macros to copy integers directly in network byte order
 * They advance the buffer pointer of the proper amount as well. 
 * This macros are supposed to be used by store()
 */
#define PUTN8(x, val)   PUTH8(x, val)

#define PUTN16(x, val) {        \
    uint16_t v = val;           \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 2; 	\
}

#define PUTN32(x, val) {        \
    uint32_t v = val;           \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 4; 	\
}

#define PUTN64(x, val) {        \
    uint64_t v = val;           \
    memcpy(x, &v, sizeof(v));   \
    x = ((char *)x) + 8; 	\
}

#ifndef MAX
#define MAX(a,b) 	(((a) > (b))? (a) : (b))
#endif

#endif /* _COMO_MODULE_H */

