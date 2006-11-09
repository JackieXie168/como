/*
 * Copyright (c) 2005-2006, Intel Corporation
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
 * Inter process communications. 
 *
 * This set of functions enable communications between processes. 
 * Each process initializes the IPC engine using the ipc_register() 
 * call to register the handlers for all IPC messages of interest. 
 * 
 * Each message carries a type to identify the handler and an id 
 * to identify the senders. Several types have been defined. 
 * All communications are asynchronous. 
 * 
 * Several additional helper functions have been provided to allow 
 * processes to send/receive complex data structures. 
 * 
 * Exception handling is managed by the individual processes
 * in the handlers. 
 */

#include <string.h>     /* strlen */
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>   /* FD_SET */
#include <sys/types.h>
#include <sys/select.h>

#include "como.h"
#include "ipc.h"

extern struct _como map;

/*
 * IPC messages exchanged between processes.
 */
typedef struct ipc_msg_t {
    ipctype_t type;             /* message type */
    procname_t sender;          /* sender's name */
    int len;                    /* payload length */
    char data[0];               /* payload */
} ipc_msg_t;

/* 
 * destinations. we keep track of their names 
 * and fd so that ipc_send can operate by just 
 * pointing to the process name. 
 *
 */
typedef struct ipc_dest_t {
    struct ipc_dest_t * next; 
    procname_t name; 
    int fd; 
} ipc_dest_t;


/* 
 * IPC messages handlers. 
 * if NULL, the message is ignored. 
 */
static ipc_handler_fn handlers[IPC_MAX] = {0}; 

/* 
 * IPC destinations. this is used to translate
 * process names to socket.  
 */
static ipc_dest_t * ipc_dests = NULL; 


/*
 * -- _ipc_write
 * 
 * keeps writing until complete.
 * 
 */
static ssize_t
_ipc_write(int fd, const void *buf, size_t count)
{
    size_t n = 0;

    while (n < count) {
	ssize_t ret = write(fd, buf + n, count - n);

	if (ret == -1)
	    return -1;

        n += ret;
    }
   
    return (ssize_t) n; /* == count */
}


/* 
 * -- _ipc_wait
 * 
 * wait for a message (any message) from the process 'who'. 
 * 
 * XXX we should probably wait only for specific messages (e.g., IPC_ACK)
 *     and discard all others in the meanwhile. check if this change would
 *     break anything in the program logic.
 *  
 */ 
static void
_ipc_wait(procname_t who) 
{
    fd_set rs;
    int r, fd;
    
    fd = ipc_getfd(who); 

    FD_ZERO(&rs);
    FD_SET(fd, &rs);

    r = -1;
    while (r < 0) {
        r = select(fd + 1, &rs, NULL, NULL, NULL);
        if (r < 0 && errno != EINTR)
            panic("select");
    }
}


/* 
 * -- _ipc_recv
 * 
 * blocking IPC to receive a message from a given process. 
 * it sits on a read from a socket and returns the message as is. 
 * this is used by ipc_handle.
 */ 
static int
_ipc_recv(int fd, ipc_msg_t * msg, int max_len) 
{
    ipc_dest_t * x;
    int r;
    
    /* read the message header first */
    r = como_read(fd, (char *) msg, sizeof(ipc_msg_t));
    if (r != sizeof(ipc_msg_t)) {
        if (r == 0)
            return IPC_EOF;
 
        /* find the name for this destination */
        for (x = ipc_dests; x && x->fd != fd; x = x->next)
            ;
 
        logmsg(LOGIPC, "error reading IPC (%s): %s\n",
               x ? getprocfullname(x->name) : "UNKNOWN",
               strerror(errno));

        return IPC_ERR;
    }
    
    /* check the message is not too big */ 
    if (msg->len > max_len) { 
        logmsg(LOGWARN, "IPC message from %s too large: %d\n", 
               getprocfullname(msg->sender), msg->len); 
        return IPC_ERR;
    } 
	
    /* read the data part now */
    if (msg->len > 0) 
        como_read(fd, msg->data, msg->len);   
    
    /*
     * check if we know about this sender. otherwise
     * add it to the list of possible destinations.
     */
    for (x = ipc_dests; x && x->name != msg->sender; x = x->next)
        ;
             
    if (x == NULL) {
        x = safe_calloc(1, sizeof(ipc_dest_t));
        x->name = msg->sender;
        x->fd = fd;
        x->next = ipc_dests;
        ipc_dests = x;
        logmsg(LOGIPC, "new connection from peer %s on fd %d\n",
               getprocfullname(msg->sender), fd);
    } else if (msg->type == IPC_SYNC) {
        x->fd = fd;
        logmsg(LOGIPC, "new connection from peer %s on fd %d\n",
               getprocfullname(msg->sender), fd);
    }

    return msg->type; 
}


/* 
 * -- ipc_getfd
 * 
 * get the socket descriptor from a process name 
 * 
 */ 
int 
ipc_getfd(procname_t who)
{
    ipc_dest_t * x; 

    /* find the socket for this destination */
    for (x = ipc_dests; x && x->name != who; x = x->next)
	;

    return x? x->fd : IPC_ERR; 
}

/* 
 * -- ipc_listen 
 * 
 * create a socket, bind it to a unix socket whose 
 * name depends on the process. then, register a handler 
 * for IPC_SYNC messages and return the socket. 
 * 
 */
int 
ipc_listen(procname_t who)
{
    char * sname; 
    int fd; 

    asprintf(&sname, "S:%s.sock", getprocfullname(who)); 
    fd = create_socket(sname, NULL); 
    free(sname); 
    return fd; 
}


/* 
 * -- ipc_finish 
 * 
 * destroy the accept socket if any and
 * close any file descriptor used for IPC. Free the memory
 * used to store known peers.
 */
void
ipc_finish()
{
    char *sname;
    ipc_dest_t * x;
    
    asprintf(&sname, "%s.sock", getprocfullname(map.whoami));
    destroy_socket(sname);
    free(sname);
    
    while (ipc_dests) {
	x = ipc_dests->next;
	close(ipc_dests->fd);
	free(ipc_dests);
	ipc_dests = x;
    }
}


/* 
 * -- ipc_connect
 * 
 * connect to process by name. it creates the socket
 * and sends an IPC_SYNC message to the destination. 
 * it returns the socket. 
 * 
 */
int 
ipc_connect(procname_t dst) 
{
    ipc_dest_t * x;
    char * sname; 

    /* set socket name */
    asprintf(&sname, "%s.sock", getprocfullname(dst)); 

    x = safe_calloc(1, sizeof(ipc_dest_t)); 
    x->name = dst; 
    x->fd = create_socket(sname, NULL); 
    free(sname); 

    /* link to existing list of destinations */
    x->next = ipc_dests; 
    ipc_dests = x; 

    /* send the SYNC message to the destination that 
     * can populate its database of destinations 
     */ 
    if (ipc_send(dst, IPC_SYNC, NULL, 0) != IPC_OK) {
	logmsg(LOGWARN, "Can't send IPC_SYNC from ipc_connect.\n");
	ipc_dests = ipc_dests->next;
	free(x);
	return IPC_ERR;
    }

    return x->fd; 
}


/* 
 * -- ipc_send
 * 
 * package a ipcmsg_t and send it to destination. 
 * it returns 0 in case of success and 1 in case of failure.
 *
 */
int
ipc_send(procname_t dst, ipctype_t type, const void *data, size_t sz)
{
    ipc_dest_t * x; 
    ipc_msg_t * msg;

    /* find the socket for this destination */
    for (x = ipc_dests; x && x->name != dst; x = x->next)
	;

    /* unknown destination */
    if (x == NULL) {
	if (dst != SUPERVISOR) { 
	    /* 
	     * if the destination is not SUPERVISOR we can try 
	     * to write something in the logs. otherwise, there
	     * is no way we can get to SUPERVISOR (we failed right here)
	     * and therefore we have to fail silently. 
	     */
	    logmsg(LOGIPC, "unknown destination (%d)\n", dst); 
	} 
	return IPC_ERR; 
    }
    
    msg = alloca(sizeof(ipc_msg_t) + sz);
    
    msg->type = type;
    msg->sender = map.whoami;
    msg->len = sz;
    
    memcpy(msg->data, data, sz);
    
    if (_ipc_write(ipc_getfd(dst), msg, sizeof(ipc_msg_t) + sz) == -1) 
        return IPC_ERR;
    
#if 0
    /* 
     * NOTE: this implementation doesn't copy memory however causes deadlock!
     * It's better to not use it until the reason for the deadlock is found.
     */
    ipc_msg_t msg;

    msg.type = type;
    msg.sender = map.whoami;
    msg.len = sz;

    if (_ipc_write(fd, &msg, sizeof(ipc_msg_t)) == -1) {
       return IPC_ERR;
    }
    
    if (sz > 0 && _ipc_write(fd, data, sz) == -1) {
       return IPC_ERR;
    }

#endif
    return IPC_OK; 
}


/* 
 * -- ipc_send_blocking
 * 
 * package a ipcmsg_t and send it to destination. wait for 
 * an acknowledgement from the destination. 
 * it returns 0 in case of success and 1 in case of failure.
 * 
 */
int 
ipc_send_blocking(procname_t dst, ipctype_t type, const void *data, size_t sz) 
{
    /* first send the message */
    if (ipc_send(dst, type, data, sz) != IPC_OK) 
	return IPC_ERR; 

    /* now wait for an IPC_ACK from the destination. 
     * 
     * XXX we don't have sequence numbers in messages so 
     *     there is no way to tell if this ACK is related 
     *     to the message sent. 
     * 
     */ 
    _ipc_wait(dst);
    return ipc_handle(ipc_getfd(dst));
} 


/* 
 * -- ipc_receive
 * 
 * receive a message from a given process and within a certain 
 * timeout. 
 * 
 */
void *
ipc_receive(procname_t who, ipctype_t *type, size_t *sz, struct timeval *tout)
{
    static char buf[MAX_IPC_LEN + sizeof(ipc_msg_t)];
    ipc_msg_t * msg;
    fd_set rs;
    int r, fd;
    
    fd = ipc_getfd(who);
 
    FD_ZERO(&rs);
    FD_SET(fd, &rs);

    r = select(fd + 1, &rs, NULL, NULL, tout);
    if (r == 0) 
	return NULL;

    msg = (ipc_msg_t *) buf; 
    if (_ipc_recv(fd, msg, MAX_IPC_LEN) == IPC_ERR) 
	return NULL; 

    *type = msg->type;
    *sz = msg->len;
    return (void *) msg->data; 
}


/* 
 * -- ipc_handle 
 * 
 * reads one full message from fd and calls the appropriate
 * handler as registered by the process. 
 * 
 */
int 
ipc_handle(int fd)
{
    char buf[MAX_IPC_LEN + sizeof(ipc_msg_t)]; 
    ipc_msg_t * msg = (ipc_msg_t *) buf; 
    int ret; 

    ret = _ipc_recv(fd, msg, MAX_IPC_LEN); 
    if (ret == IPC_EOF) 
	return IPC_EOF; 
    if (ret == IPC_ERR) 
	return IPC_ERR; 
	    
    /* find the right handler if any */
    if (handlers[msg->type] != NULL) 
	handlers[msg->type](msg->sender, msg->data, msg->len); 

    return IPC_OK;
}
    

/* 
 * -- ipc_register
 * 
 * copy the information of the handle functions in the 
 * global handlers variable. 
 * 
 */ 
void 
ipc_register(ipctype_t type, ipc_handler_fn fn)
{
    assert(type < IPC_MAX); 
    handlers[type] = fn; 
}


/* 
 * -- ipc_clear
 * 
 * clear all information we know about handlers. this is 
 * used before starting to register new handlers (very useful
 * after a fork). 
 * 
 * XXX note that we don't clear the list of known destination. 
 *     we can still make use of those given that the we still 
 *     have the file descriptors open. 
 * 
 */ 
void 
ipc_clear()
{
    bzero(handlers, sizeof(handlers)); 
}


/* 
 * -- ipc_getdest
 * 
 * get the process name from a socket descriptor 
 * 
 */ 
int 
ipc_getdest(int fd, procname_t * who)
{
    ipc_dest_t * x; 

    /* find the socket for this destination */
    for (x = ipc_dests; x && x->fd != fd; x = x->next)
	;

    if (x != NULL) {
	*who = x->name;
	return IPC_OK;
    }
    
    return IPC_ERR; 
}
