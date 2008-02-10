/* File automatically generated from slist.h.typetpl. Do not modify! */
#ifndef ppbuf_list_H_
#define ppbuf_list_H_

#include "c_queue.h"

/*
 * Singly-linked List definitions.
 */

typedef struct ppbuf_list {
	ppbuf_t *slh_first;	/* first element */
} ppbuf_list_t;
 
#define	ppbuf_list_head_initializer(head)					\
	{ NULL }
 
typedef struct ppbuf_list_entry {
	ppbuf_t *sle_next;	/* next element */
} ppbuf_list_entry_t;
 
/*
 * Singly-linked List access methods.
 */
#define	ppbuf_list_first(head)		C_SLIST_FIRST(head)
#define	ppbuf_list_end(head)		C_SLIST_END(head)
#define	ppbuf_list_empty(head)		C_SLIST_EMPTY(head)
#define	ppbuf_list_next(elm)		C_SLIST_NEXT(elm, next)

#define	ppbuf_list_foreach(var, head)	\
	C_SLIST_FOREACH(var, head, next)

#define	ppbuf_list_foreach_prevptr(var, varp, head)	\
	C_SLIST_FOREACH_PREVPTR(var, varp, head, next)

/*
 * Singly-linked List functions.
 */
#define	ppbuf_list_init(head)	C_SLIST_INIT(head)

#define	ppbuf_list_insert_after(slistelm, elm)	\
	C_SLIST_INSERT_AFTER(slistelm, elm, next)

#define	ppbuf_list_insert_head(head, elm)	\
	C_SLIST_INSERT_HEAD(head, elm, next)

#define	ppbuf_list_remove_next(head, elm)	\
	C_SLIST_REMOVE_NEXT(head, elm, next)

#define	ppbuf_list_remove_head(head)	\
	C_SLIST_REMOVE_HEAD(head, next)

#define ppbuf_list_remove(head, elm)	\
	C_SLIST_REMOVE(head, elm, ppbuf_t, next)

#endif /*ppbuf_list_H_*/
