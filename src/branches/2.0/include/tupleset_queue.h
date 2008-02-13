/* File automatically generated from tailq.h.typetpl. Do not modify! */
/* $Id: tailq.h.typetpl 1211 2007-09-26 15:01:49Z jsanjuas $ */
#ifndef tupleset_queue_H_
#define tupleset_queue_H_

#include "c_queue.h"

/*
 * Tail queue definitions.
 */
typedef struct tupleset_queue {
	struct tupleset *tqh_first;	/* first element */
	struct tupleset **tqh_last;	/* addr of last next element */
} tupleset_queue_t;

#define	tupleset_queue_head_initializer(head)					\
	{ NULL, &(head).tqh_first }

typedef struct tupleset_queue_entry {
	struct tupleset *tqe_next;	/* next element */
	struct tupleset **tqe_prev;	/* address of previous next element */
} tupleset_queue_entry_t;

/* 
 * tail queue access methods 
 */
#define	tupleset_queue_first(head)		C_TAILQ_FIRST(head)
#define	tupleset_queue_end(head)		C_TAILQ_END(head)
#define	tupleset_queue_empty(head)		C_TAILQ_EMPTY(head)
#define	tupleset_queue_next(elm)		C_TAILQ_NEXT(elm, list)
#define	tupleset_queue_last(head)		C_TAILQ_LAST(head, tupleset_queue)
#define	tupleset_queue_prev(elm)		C_TAILQ_PREV(elm, tupleset_queue, list)

#define	tupleset_queue_foreach(var, head)	\
	C_TAILQ_FOREACH(var, head, list)

#define	tupleset_queue_foreach_reverse(var, head)	\
	C_TAILQ_FOREACH_REVERSE(var, head, tupleset_queue, list)

/*
 * Tail queue functions.
 */
#define	tupleset_queue_init(head)	C_TAILQ_INIT(head)

#define	tupleset_queue_insert_head(head, elm)	\
	C_TAILQ_INSERT_HEAD(head, elm, list)

#define	tupleset_queue_insert_tail(head, elm)	\
	C_TAILQ_INSERT_TAIL(head, elm, list)

#define	tupleset_queue_insert_after(head, listelm, elm)	\
	C_TAILQ_INSERT_AFTER(head, listelm, elm, list)

#define	tupleset_queue_insert_before(listelm, elm)	\
	C_TAILQ_INSERT_BEFORE(listelm, elm, list)

#define tupleset_queue_remove(head, elm)	\
	C_TAILQ_REMOVE(head, elm, list)

#define tupleset_queue_replace(head, elm, elm2)	\
	C_TAILQ_REPLACE(head, elm, elm2, list)


#endif /*tupleset_queue_H_*/
