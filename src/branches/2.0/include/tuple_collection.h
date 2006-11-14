/* File automatically generated from dlist.h.typetpl. Do not modify! */
#ifndef tuple_collection_H_
#define tuple_collection_H_

#include "c_queue.h"

/*
 * Doubly-linked List definitions.
 */

typedef struct tuple_collection {
	tuple_collection_item_t *lh_first;	/* first element */
} tuple_collection_t;
 
#define	tuple_collection_head_initializer(head)					\
	{ NULL }
 
typedef struct tuple_collection_entry {
        tuple_collection_item_t *le_next;   /* next element */                      \
        tuple_collection_item_t **le_prev;  /* address of previous next element */  
} tuple_collection_entry_t;
 
/*
 * Singly-linked List access methods.
 */
#define	tuple_collection_first(head)		C_LIST_FIRST(head)
#define	tuple_collection_end(head)		C_LIST_END(head)
#define	tuple_collection_empty(head)		C_LIST_EMPTY(head)
#define	tuple_collection_next(elm)		C_LIST_NEXT(elm, entry)

#define	tuple_collection_foreach(var, head)	\
	C_LIST_FOREACH(var, head, entry)

#define	tuple_collection_foreach_prevptr(var, varp, head)	\
	C_LIST_FOREACH_PREVPTR(var, varp, head, entry)

/*
 * Doubly-linked List functions.
 */
#define	tuple_collection_init(head)	C_SLIST_INIT(head)

#define	tuple_collection_insert_after(dlistelm, elm)	\
	C_LIST_INSERT_AFTER(dlistelm, elm, entry)
#
#define	tuple_collection_insert_before(dlistelm, elm)	\
	C_LIST_INSERT_BEFORE(dlistelm, elm, entry)

#define	tuple_collection_insert_head(head, elm)	\
	C_LIST_INSERT_HEAD(head, elm, entry)

#define tuple_collection_remove(elm)	\
	C_LIST_REMOVE(elm, entry)
#
#define tuple_collection_replace(elm, elm2)	\
	C_LIST_REPLACE(elm, elm2, entry)

#endif /*tuple_collection_H_*/
