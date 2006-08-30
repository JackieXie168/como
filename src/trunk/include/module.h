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

#ifndef _COMO_MODULE_H
#define _COMO_MODULE_H

#include <string.h>		/* memcpy */

#include "como-build.h"

#include "stdpkt.h"
#include "comotypes.h"
#include "comofunc.h"

/*
 * Some useful macros to write modules
 */

#ifdef ENABLE_SHARED_MODULES
#  define MODULE(name)	module_cb_t callbacks
#else
#  define MODULE(name)	module_cb_t g_ ## name ## _module
#endif

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
 * CONFIG is defined by each individual module and stored 
 * somewhere in the module_t data structure (opaque to modules). 
 * we use CONFIG() to retrieve the state from that structure 
 */
#define CONFIG(x)	(((module_t *) (x))->config)

/* 
 * ESTATE is defined by each individual module and stored 
 * somewhere in the module_t data structure (opaque to modules). 
 * we use ESTATE() to retrieve the state from that structure 
 */

#define ESTATE(x)	(((module_t *) (x))->estate)

/* 
 * FSTATE is defined by each individual module and stored 
 * somewhere in the module_t data structure (opaque to modules). 
 * we use FSTATE() to retrieve the state from that structure 
 */
#define FSTATE(x)	(((module_t *) (x))->fstate)

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


/*
 * Macros to read values from a buf and convert them from network 
 * to host byte order. They advance the buffer pointer of the proper 
 * amount as well. This macros are supposed to be used by the 
 * print()/replay()/load() callbacks
 */
#define GETH8(x, val) {         	\
    memcpy(val, x, 1); 		  	\
    x = ((char *)x) + 1; 		\
}

#define GETH16(x, val) { 		\
    memcpy(val, x, 2);		   	\
    *val = ntohs(*val);			\
    x = ((char *)x) + 2; 		\
}

#define GETH32(x, val) { 		\
    memcpy(val, x, 4); 		  	\
    *val = ntohl(*val);			\
    x = ((char *)x) + 4; 		\
}

#define GETH64(x, val) { 		\
    memcpy(val, x, 8); 		  	\
    *val = NTOHLL(*val);		\
    x = ((char *)x) + 8; 		\
}


/*
 * Macros to read values from a buf and keep them in network byte order. 
 * They advance the buffer pointer of the proper amount as well. 
 * This macros are supposed to be used by the print()/replay()/load() 
 * callbacks.
 */
#define GETN8(x, val) 		GETH8(x, val)
 
#define GETN16(x, val) {                \
    memcpy(val, x, 2);                  \
    x = ((char *)x) + 2;                \
}

#define GETN32(x, val) {                \
    memcpy(val, x, 4);                  \
    x = ((char *)x) + 4;                \
}

#define GETN64(x, val) {                \
    memcpy(val, x, 8);                  \
    x = ((char *)x) + 8;                \
}


#ifndef MAX
#define MAX(a,b) 	(((a) > (b))? (a) : (b))
#endif

#endif /* _COMO_MODULE_H */

