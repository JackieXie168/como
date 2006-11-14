/* File automatically generated from slist.h.typetpl. Do not modify! */
#ifndef sniffer_list_H_
#define sniffer_list_H_

#include "c_queue.h"

/*
 * Singly-linked List definitions.
 */

typedef struct sniffer_list {
	sniffer_t *slh_first;	/* first element */
} sniffer_list_t;
 
#define	sniffer_list_head_initializer(head)					\
	{ NULL }
 
typedef struct sniffer_list_entry {
	sniffer_t *sle_next;	/* next element */
} sniffer_list_entry_t;
 
/*
 * Singly-linked List access methods.
 */
#define	sniffer_list_first(head)		C_SLIST_FIRST(head)
#define	sniffer_list_end(head)		C_SLIST_END(head)
#define	sniffer_list_empty(head)		C_SLIST_EMPTY(head)
#define	sniffer_list_next(elm)		C_SLIST_NEXT(elm, entry)

#define	sniffer_list_foreach(var, head)	\
	C_SLIST_FOREACH(var, head, entry)

#define	sniffer_list_foreach_prevptr(var, varp, head)	\
	C_SLIST_FOREACH_PREVPTR(var, varp, head, entry)

/*
 * Singly-linked List functions.
 */
#define	sniffer_list_init(head)	C_SLIST_INIT(head)

#define	sniffer_list_insert_after(slistelm, elm)	\
	C_SLIST_INSERT_AFTER(slistelm, elm, entry)

#define	sniffer_list_insert_head(head, elm)	\
	C_SLIST_INSERT_HEAD(head, elm, entry)

#define	sniffer_list_remove_next(head, elm)	\
	C_SLIST_REMOVE_NEXT(head, elm, entry)

#define	sniffer_list_remove_head(head)	\
	C_SLIST_REMOVE_HEAD(head, entry)

#define sniffer_list_remove(head, elm)	\
	C_SLIST_REMOVE(head, elm, sniffer_t, entry)

#endif /*sniffer_list_H_*/
