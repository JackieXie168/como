/* File automatically generated from slist.h.typetpl. Do not modify! */
#ifndef ipc_peer_list_H_
#define ipc_peer_list_H_

#include "c_queue.h"

/*
 * Singly-linked List definitions.
 */

typedef struct ipc_peer_list {
	ipc_peer_full_t *slh_first;	/* first element */
} ipc_peer_list_t;
 
#define	ipc_peer_list_head_initializer(head)					\
	{ NULL }
 
typedef struct ipc_peer_list_entry {
	ipc_peer_full_t *sle_next;	/* next element */
} ipc_peer_list_entry_t;
 
/*
 * Singly-linked List access methods.
 */
#define	ipc_peer_list_first(head)		C_SLIST_FIRST(head)
#define	ipc_peer_list_end(head)		C_SLIST_END(head)
#define	ipc_peer_list_empty(head)		C_SLIST_EMPTY(head)
#define	ipc_peer_list_next(elm)		C_SLIST_NEXT(elm, next)

#define	ipc_peer_list_foreach(var, head)	\
	C_SLIST_FOREACH(var, head, next)

#define	ipc_peer_list_foreach_prevptr(var, varp, head)	\
	C_SLIST_FOREACH_PREVPTR(var, varp, head, next)

/*
 * Singly-linked List functions.
 */
#define	ipc_peer_list_init(head)	C_SLIST_INIT(head)

#define	ipc_peer_list_insert_after(slistelm, elm)	\
	C_SLIST_INSERT_AFTER(slistelm, elm, next)

#define	ipc_peer_list_insert_head(head, elm)	\
	C_SLIST_INSERT_HEAD(head, elm, next)

#define	ipc_peer_list_remove_next(head, elm)	\
	C_SLIST_REMOVE_NEXT(head, elm, next)

#define	ipc_peer_list_remove_head(head)	\
	C_SLIST_REMOVE_HEAD(head, next)

#define ipc_peer_list_remove(head, elm)	\
	C_SLIST_REMOVE(head, elm, ipc_peer_full_t, next)

#endif /*ipc_peer_list_H_*/
