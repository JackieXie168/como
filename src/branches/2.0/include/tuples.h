/* File automatically generated from tailq.h.typetpl. Do not modify! */
#ifndef tuples_H_
#define tuples_H_

#include "c_queue.h"

/*
 * Tail queue definitions.
 */
typedef struct tuples {
	struct tuple *tqh_first;	/* first element */
	struct tuple **tqh_last;	/* addr of last next element */
} tuples_t;

#define	tuples_head_initializer(head)					\
	{ NULL, &(head).tqh_first }

typedef struct tuples_entry {
	struct tuple *tqe_next;	/* next element */
	struct tuple **tqe_prev;	/* address of previous next element */
} tuples_entry_t;

/* 
 * tail queue access methods 
 */
#define	tuples_first(head)		C_TAILQ_FIRST(head)
#define	tuples_end(head)		C_TAILQ_END(head)
#define	tuples_empty(head)		C_TAILQ_EMPTY(head)
#define	tuples_next(elm)		C_TAILQ_NEXT(elm, entry)
#define	tuples_last(head)		C_TAILQ_LAST(head, tuples)
#define	tuples_prev(elm)		C_TAILQ_PREV(elm, tuples, entry)

#define	tuples_foreach(var, head)	\
	C_TAILQ_FOREACH(var, head, entry)

#define	tuples_foreach_reverse(var, head)	\
	C_TAILQ_FOREACH_REVERSE(var, head, tuples, entry)

/*
 * Tail queue functions.
 */
#define	tuples_init(head)	C_TAILQ_INIT(head)

#define	tuples_insert_head(head, elm)	\
	C_TAILQ_INSERT_HEAD(head, elm, entry)

#define	tuples_insert_tail(head, elm)	\
	C_TAILQ_INSERT_TAIL(head, elm, entry)

#define	tuples_insert_after(head, listelm, elm)	\
	C_TAILQ_INSERT_AFTER(head, listelm, elm, entry)

#define	tuples_insert_before(listelm, elm)	\
	C_TAILQ_INSERT_BEFORE(listelm, elm, entry)

#define tuples_remove(head, elm)	\
	C_TAILQ_REMOVE(head, elm, entry)

#define tuples_replace(head, elm, elm2)	\
	C_TAILQ_REPLACE(head, elm, elm2, entry)


#endif /*tuples_H_*/
