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
 * call to register the s_handlers for all IPC messages of interest. 
 * 
 * Each message carries a type to identify the handler and an id 
 * to identify the senders. Several types have been defined. 
 * All communications are asynchronous. 
 * 
 * Several additional helper functions have been provided to allow 
 * processes to send/receive complex data structures. 
 * 
 * Exception handling is managed by the individual processes
 * in the s_handlers. 
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>     /* strlen */
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>   /* FD_SET */
#include <sys/types.h>
#include <sys/select.h>

#define LOG_DOMAIN	"IPC"

#include "como.h"
#include "ipc.h"

#define IPC_CONNECT	0

#include "ipc_peer_list.h"


#define SIZEOF_IPC_PEER_CODE	4
#define SIZEOF_IPC_PEER_NAME	12

struct ipc_peer_full_t {
    uint8_t			class;
    uint8_t			parent_class;
    uint16_t			id;
    char			code[SIZEOF_IPC_PEER_CODE];
    char			name[SIZEOF_IPC_PEER_NAME];
    char *			at;
    int				fd;
    int				swap;
    ipc_peer_list_entry_t	next;
};

/*
 * IPC messages exchanged between processes.
 */
typedef struct PACKED ipc_msg {
    ipc_type	type;		/* message type */
    ipc_peer_t	sender;		/* sender */
    uint32_t	len;		/* payload length */
    uint8_t	data[0];	/* payload */
} ipc_msg_t;


typedef struct PACKED ipc_connect_msg {
    char	code[SIZEOF_IPC_PEER_CODE]; /* code of connecting peer */
    char	name[SIZEOF_IPC_PEER_NAME]; /* name of connecting peer */
} ipc_connect_msg_t;


static ipc_peer_full_t * s_me;
static void * s_user_data;

/* 
 * IPC peers.
 * information about connected peers.
 */

static ipc_peer_list_t s_peers;

/* 
 * IPC messages s_handlers. 
 * if NULL, the message is ignored. 
 */
/* TODO: replace with hash table */
static ipc_handler_fn s_handlers[65536] = {0};


ipc_peer_full_t *
ipc_peer_new(uint8_t class, const char * code, const char * name)
{
    ipc_peer_full_t *p;
    p = como_new0(ipc_peer_full_t);
    p->class = class;
    snprintf(p->code, SIZEOF_IPC_PEER_CODE, code);
    snprintf(p->name, SIZEOF_IPC_PEER_NAME, name);
    return p;
}


void
ipc_peer_destroy(ipc_peer_full_t * p)
{
    if (p == NULL)
	return;
    free(p->at);
    if (p->fd != -1)
	close(p->fd);
    free(p);
}


ipc_peer_full_t *
ipc_peer_at(const ipc_peer_full_t * p, const char * at)
{
    ipc_peer_full_t *p2;
    p2 = como_new(ipc_peer_full_t);
    *p2 = *p;
    p2->fd = -1;
    p2->at = como_strdup(at);
    p2->swap = FALSE;
    memset(&p2->next, 0, sizeof(p2->next));
    return p2;
}


/* 
 * -- ipc_peer_get_fd
 * 
 * get the socket descriptor from a peer
 * 
 */ 
int
ipc_peer_get_fd(const ipc_peer_t * p_)
{
    ipc_peer_full_t * p = (ipc_peer_full_t *) p_;

    return p->fd;
}


const char *
ipc_peer_get_name(const ipc_peer_t * p_)
{
    ipc_peer_full_t * p = (ipc_peer_full_t *) p_;

    return p->name;
}


const char *
ipc_peer_get_code(const ipc_peer_t * p_)
{
    ipc_peer_full_t * p = (ipc_peer_full_t *) p_;

    return p->code;
}


ipc_peer_full_t *
ipc_peer_child(const ipc_peer_full_t * kind, uint16_t id)
{
    ipc_peer_full_t *p;
    p = como_new(ipc_peer_full_t);
    *p = *kind;
    p->parent_class = s_me->class;
    p->id = id;
    p->at = como_strdup(s_me->at);
    memset(&p->next, 0, sizeof(p->next));
    return p;
}


static char *
ipc_peer_connection_point(const ipc_peer_full_t * p)
{
    char *cp;
    assert(p->at != NULL);
    if (p->at[0] == '/') {
	if (p->parent_class == 0) {
	    asprintf(&cp, "%s/%s.sock", p->at, p->name);
	} else {
	    asprintf(&cp, "%s/%s-%d.sock", p->at, p->name, p->id);
	}
    } else {
	cp = strdup(p->at);
    }
    return cp;
}

/*
 * -- ipc_write
 * 
 * keeps writing until complete.
 */
static ssize_t
ipc_write(int fd, const void * buf, size_t count)
{
    size_t n = 0;

    while (n < count) {
	ssize_t ret = write(fd, buf + n, count - n);

	if (ret == -1)
	    return -1;

        n += (size_t) ret;
    }
   
    return (ssize_t) n; /* == count */
}


static inline void
swap_msg(ipc_msg_t * msg)
{
    msg->type = SWAP16(msg->type);
    msg->sender.id = SWAP16(msg->sender.id);
    msg->len = SWAP32(msg->len);
}


static inline ipc_peer_full_t *
lookup_peer(int fd)
{
    ipc_peer_full_t *x;
    ipc_peer_list_foreach(x, &s_peers) {
	if (x->fd == fd)
	    return x;
    }
    return NULL;
}


static int
ipc_create_socket(const ipc_peer_full_t * p, int is_server)
{
    int fd;
    char *cp;
    
    cp = ipc_peer_connection_point(p);
    
    fd = create_socket(cp, is_server);
    
    free(cp);
    return fd;
}


static int
ipc_destroy_socket(const ipc_peer_full_t * p)
{
    int r;
    char *cp;
    
    cp = ipc_peer_connection_point(p);
    r = destroy_socket(cp);
    free(cp);
    
    return r;
}


/*
 * -- ipc_read
 * 
 * keeps writing until complete.
 */
static ssize_t
ipc_read(int fd, void * buf, size_t count)
{
    size_t n = 0;
    
    while (n < count) {
        ssize_t ret = read(fd, buf + n, count - n);
        if (ret == -1)
            return -1;
        if (ret == 0) /* EOF */
            break;
        
        n += (size_t) ret;
    }
    
    return (ssize_t) n; /* <= count */
}



void
ipc_init(ipc_peer_full_t * me, void * user_data)
{
    memset(s_handlers, 0, sizeof(s_handlers));

    s_me = me;
    s_me->fd = -1;
    s_user_data = user_data;
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
ipc_listen()
{
    assert(s_me->fd == -1);
    s_me->fd = ipc_create_socket(s_me, TRUE);
    if (s_me->fd != -1) {
	notice("Listening connections on %s@%s.\n", s_me->name, s_me->at);
    }
    return s_me->fd;
}

/* 
 * -- ipc_finish 
 * 
 * destroy the process accept socket if any and
 * close any file descriptor used for IPC. Free the memory
 * used to store known peers.
 */
void
ipc_finish(int destroy)
{
    ipc_peer_full_t *x;
    
    if (s_me->fd != -1) {
	if (destroy) {
	    ipc_destroy_socket(s_me);
	}
	close(s_me->fd);
	s_me->fd = -1;
    }
    free(s_me->at);
    free(s_me);    
    
    while (!ipc_peer_list_empty(&s_peers)) {
	x = ipc_peer_list_first(&s_peers);
	ipc_peer_list_remove_head(&s_peers);
	ipc_peer_destroy(x); /* also closes fd */
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
ipc_connect(ipc_peer_full_t * dst)
{
    if (dst->at == NULL) {
	dst->at = como_strdup(s_me->at);
    }

    dst->fd = ipc_create_socket(dst, FALSE);
    if (dst->fd != -1) {
	notice("Connected to peer %s@%s.\n", dst->name, dst->at);
	/* add to existing list of destinations */
	ipc_peer_list_insert_head(&s_peers, dst);
    }

    return dst->fd;
}


/* 
 * -- ipc_send
 * 
 * sends a message to a peer
 * it returns IPC_OK in case of success and IPC_ERR in case of failure.
 *
 */
int
ipc_send(ipc_peer_t * dst_, ipc_type type, const void * data, size_t sz)
{
    ipc_msg_t *msg;
    ipc_peer_full_t * dst = (ipc_peer_full_t *) dst_;
    ipc_peer_t *me = (ipc_peer_t *) &s_me;
    
    assert(type != IPC_CONNECT);
    
    msg = alloca(sizeof(ipc_msg_t) + sz);
    
    msg->type = type;
    msg->sender = *me;
    msg->len = sz;
    
    memcpy(msg->data, data, sz);
    
    if (ipc_write(dst->fd, msg, sizeof(ipc_msg_t) + sz) == -1) {
	return IPC_ERR;
    }
    
#if 0
    /* 
     * NOTE: this implementation doesn't copy memory however causes deadlock!
     * It's better to not use it until the reason for the deadlock is found.
     */
    ipc_msg_t msg;
    ipc_peer_full_t * dst = (ipc_peer_full_t *) dst_;
    ipc_peer_t *me = (ipc_peer_t *) s_me;
    
    assert(type != IPC_CONNECT);

    msg.type = type;
    msg.sender = *me;
    msg.len = sz;

    if (ipc_write(dst->fd, &msg, sizeof(ipc_msg_t)) == -1) {
	return IPC_ERR;
    }
    
    if (sz > 0 && ipc_write(dst->fd, data, sz) == -1) {
	return IPC_ERR;
    }

#endif
    return IPC_OK; 

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
    ipc_peer_full_t *x = NULL;
    ipc_msg_t msg;
    void *buf = NULL;
    size_t r;
    int swap = FALSE;

    /* read the message header first */
    r = (size_t) ipc_read(fd, &msg, sizeof(ipc_msg_t)); 
    if (r != sizeof(ipc_msg_t)) {
	if (r == 0)
	    return IPC_EOF;
    	
	/* find the sender of the message */
	x = lookup_peer(fd);
	if (x != NULL) {
	    warn("Malformed IPC message received from %s@%s on fd %d.\n",
		 x->name, x->at, fd);
	} else {
	    warn("Invalid IPC message received on fd %d.\n", fd);
	    debug("Have you callend ipc_handle on a non-IPC fd?\n");
	}
	return IPC_ERR;
    }
	    
    if (msg.type == IPC_CONNECT) {
	/* NOTE: this works regardless of byte ordering as IPC_CONNECT is 0 */
	if (msg.len != sizeof(ipc_connect_msg_t)) {
	    if (ntohl(msg.len) != sizeof(ipc_connect_msg_t)) {
		warn("Invalid IPC connection message received on fd %d.\n",
		     fd);
		return IPC_ERR;
	    }
	    swap = TRUE;
	}
    } else {
	/* find the sender of the message */
	x = lookup_peer(fd);
	if (x == NULL) {
	    warn("IPC message received from unknown peer on fd %d.\n", fd);
	    debug("Have you callend ipc_handle on a non-IPC fd?\n");
	    return IPC_ERR;
	}
	swap = x->swap;
    }
    
    if (swap == TRUE) {
	swap_msg(&msg);
    }

    /* read the data part now */ 
    if (msg.len > 0) {
	/*
	 * NOTE: the assumption is that msgs are small, so alloca is used in
	 * place of safe_malloc. In future a possible generalization could be
	 * to use a threshold to split between small and big msgs.
	 */
	//buf = como_malloc(msg.len);
	buf = alloca(msg.len);
	r = (size_t) ipc_read(fd, buf, msg.len);
	if (r != msg.len) {
	    if (x != NULL) {
		warn("Can't read entire IPC message from %s@%s on fd %d.\n",
		     x->name, x->at, fd);
	    } else {
		warn("Can't read entire IPC message from fd %d.\n", fd);
	    }
	}
    }
    
    if (msg.type == IPC_CONNECT) {
	/* this is the connection message */
	ipc_connect_msg_t *cm;
	
	cm = (ipc_connect_msg_t *) buf;
	x = ipc_peer_new(msg.sender.class, cm->code, cm->name);
	x->fd = fd;
	x->at = strdup("unknown");
	ipc_peer_list_insert_head(&s_peers, x);
	
	notice("New connection from peer %s on fd %d\n", x->name, fd);
	return IPC_OK;
    }
    
    if (x->class != msg.sender.class) {
	warn("Sender class mismatch in IPC message from %s@%s on fd %d.\n",
	     x->name, x->at, fd);
    }

    /* find the right handler if any */
    if (s_handlers[msg.type] != NULL) {
	int ic;
	ic = s_handlers[msg.type](&msg.sender, buf, msg.len, swap, s_user_data);
	if (ic == IPC_CLOSE) {
	    notice("Closing connection to peer %s on fd %d\n", x->name, fd);
	    ipc_peer_list_remove(&s_peers, x);
	    ipc_peer_destroy(x); /* calls close */
	}
	assert(ic == IPC_OK);
	
	//free(buf);
	return ic;
    } else {
	notice("Unhandled IPC message type %hd.\n", msg.type);

	//free(buf);
	return IPC_OK;
    }
}


/* 
 * -- ipc_receive
 * 
 * receive a message from a given peer and within a certain 
 * timeout. 
 * 
 */
int
ipc_receive(ipc_peer_t * peer, ipc_type * type, void * data, size_t * sz,
	    int * swap, const struct timeval * timeout)
{
    ipc_peer_full_t *x = (ipc_peer_full_t *) peer;
    ipc_msg_t msg;
    fd_set rs;
    int n;
    struct timeval to, *toptr;
    size_t r;
    
    assert(type != NULL);
    /* if data != NULL then sz must not be NULL */
    assert(data == NULL || sz != NULL);
    
    FD_ZERO(&rs);
    FD_SET(x->fd, &rs);

    for (;;) {
	if (timeout != NULL) {
	    to = *timeout;
	    toptr = &to;
	} else {
	    toptr = NULL;
	}
        n = select(x->fd + 1, &rs, NULL, NULL, toptr);
        if (n == 1) {
	    break;
        }
        if (n < 0) {
	    if (errno == EAGAIN) {
		return IPC_EAGAIN;
	    } else if (errno != EINTR) {
		return IPC_ERR;
	    }
        }
    }

    /* read the message header first */
    r = (size_t) ipc_read(x->fd, &msg, sizeof(ipc_msg_t)); 
    if (r != sizeof(ipc_msg_t)) {
	if (r == 0)
	    return IPC_EOF;
    	
	warn("Malformed IPC message received from %s@%s on fd %d.\n",
	     x->name, x->at, x->fd);
	return IPC_ERR;
    }
    
    if (x->swap == TRUE) {
	swap_msg(&msg);
    }
    assert(msg.type != IPC_CONNECT);

    *type = msg.type;
    if (swap) {
	*swap = x->swap;
    }
	    
    /* read the data part now */ 
    if (msg.len > 0) {
	if (msg.len <= *sz) {
	    /* user provided buffer is suitable to contain the message */
	    r = (size_t) ipc_read(x->fd, data, msg.len);
	} else {
	    /* user provided buffer is NOT suitable to contain the message */
	    r = (size_t) ipc_read(x->fd, data, *sz);
	    if (r == *sz) {
		void *buf;
		size_t r2;
		buf = alloca(msg.len - *sz);
		r2 = (size_t) ipc_read(x->fd, buf, msg.len - *sz);
		if (r2 == msg.len - *sz) {
		    r += r2;
		} else {
		    r = (size_t) -1;
		}
	    }
	}
	if (r != msg.len) {
	    warn("Can't read entire IPC message from %s@%s on fd %d.\n",
		 x->name, x->at, x->fd);
	}
    }
    if (sz) {
	*sz = msg.len;
    }
    
    return IPC_OK;
}

/* 
 * -- ipc_register
 * 
 * register a user provided handler for a given ipc type. 
 * 
 */ 
void 
ipc_register(ipc_type type, ipc_handler_fn fn)
{
    assert(type != IPC_CONNECT);
    s_handlers[type] = fn;
}

void
ipc_set_user_data(void * user_data)
{
    s_user_data = user_data;
}
