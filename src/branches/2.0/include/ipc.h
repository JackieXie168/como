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

#ifndef _COMO_IPC_H_
#define _COMO_IPC_H_

#include <sys/time.h>

typedef uint16_t		ipc_type;

typedef struct ipc_peer_full_t	ipc_peer_full_t;
typedef struct ipc_peer_t	ipc_peer_t;

typedef int (*ipc_handler_fn) (ipc_peer_t * peer, void * buf, size_t len,
			       int swap, void * user_data);


#define IPC_OK		0
#define IPC_ERR		-1
#define IPC_EOF		-2
#define IPC_EAGAIN	-3

#define IPC_CLOSE	0xC105E
/* 
 * function prototypes 
 */
ipc_peer_full_t * ipc_peer_new     (uint8_t class, const char * code,
				    const char * name);
void              ipc_peer_destroy (ipc_peer_full_t * p);
ipc_peer_full_t * ipc_peer_at      (const ipc_peer_full_t * p,
				    const char * at);
int               ipc_peer_get_fd  (const ipc_peer_t * p_);



void ipc_init     (ipc_peer_full_t * me, const char * ipc_dir,
		   void * user_data);
void ipc_finish   ();
void ipc_register (ipc_type type, ipc_handler_fn fn);
int  ipc_listen   ();
int  ipc_connect  (ipc_peer_full_t * dst);
int  ipc_send     (ipc_peer_t * dst, ipc_type type, const void * data,
		   size_t sz);
int  ipc_handle   (int fd);
int  ipc_receive  (ipc_peer_t * peer, ipc_type * type, void * data,
		   size_t * sz, int * swap, const struct timeval * timeout);

#endif	/* _COMO_IPC_H_ */
