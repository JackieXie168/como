/*-
 * Copyright (c) 2004-2006, Intel Corporation 
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
 * $Id: ipc.h,v 1.4 2006/05/07 22:11:58 iannak1 Exp $
 */

#ifndef _COMO_IPC_H_
#define _COMO_IPC_H_

typedef enum _ipc_types		ipctype_t; 
typedef void (*ipc_handler_fn)(procname_t who, int fd, void *buf, size_t len);

enum _ipc_types {
   IPC_ERROR, 
   IPC_SYNC,
   IPC_ACK, 
   IPC_ECHO, 
   IPC_MODULE_ADD, 
   IPC_MODULE_DEL,
   IPC_MODULE_START, 
   IPC_FREEZE,
   IPC_FLUSH,
   IPC_RECORD, 
   IPC_DONE,
   IPC_EXIT,

  /* storage IPCs */
   S_ERROR, 
   S_NODATA, 
   S_ACK, 
   S_OPEN, 
   S_CLOSE, 
   S_REGION, 
   S_SEEK, 
   S_INFORM,

   IPC_MAX 	/* this must be last */
}; 

#define IPC_OK		0
#define IPC_ERR		-1
#define IPC_EOF		-2

/* 
 * function prototypes 
 */
int  ipc_listen();
int  ipc_connect(procname_t name);
void ipc_finish();
int  ipc_send(procname_t name, ipctype_t type, const void *data, size_t sz);
int  ipc_send_with_fd(int fd, ipctype_t type, const void *data, size_t sz);
int  ipc_send_blocking(procname_t name, ipctype_t type, const void *data,
		       size_t sz);
int  ipc_handle(int fd);
void ipc_register(ipctype_t type, ipc_handler_fn fn);
void ipc_clear();
int  ipc_getfd(procname_t who);
int  ipc_wait_reply_with_fd(int fd, ipctype_t *type, void *data, size_t *sz);

#endif	/* _COMO_IPC_H_ */
