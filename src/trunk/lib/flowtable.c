/*
 * Copyright (c) 2006, Intel Corporation
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
 * This file is derived from Tcl (http://tcl.sourceforge.net/)
 * which holds the following copyright notice and license:
 * 
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., Scriptics Corporation, ActiveState
 * Corporation and other parties.  The following terms apply to all files
 * associated with the software unless explicitly disclaimed in
 * individual files.
 * 
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 * 
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 * 
 * GOVERNMENT USE: If you are acquiring this software on behalf of the
 * U.S. government, the Government shall have only "Restricted Rights"
 * in the software and related documentation as defined in the Federal 
 * Acquisition Regulations (FARs) in Clause 52.227.19 (c) (2).  If you
 * are acquiring the software on behalf of the Department of Defense, the
 * software shall be classified as "Commercial Computer Software" and the
 * Government shall have only "Restricted Rights" as defined in Clause
 * 252.227-7013 (c) (1) of DFARs.  Notwithstanding the foregoing, the
 * authors grant the U.S. Government and others acting in its behalf
 * permission to use and distribute the software in accordance with the
 * terms specified in this license. 
 */

/* Portions are:
 * 
 * Copyright (C) 2002  Red Hat, Inc.
 * Copyright (c) 1991-1993 The Regents of the University of California.
 * Copyright (c) 1994 Sun Microsystems, Inc.
 * 
 * Licensed under the Academic Free License version 2.1
 */

#include <string.h>
#include <assert.h>

#include "corlib.h"

/*
 * When there are this many entries per bucket, on average, rebuild
 * the hash table to make it larger.
 */

#define REBUILD_MULTIPLIER	3

/*
 * Structure definition for an entry in a hash table.  No-one outside
 * Tcl should access any of these fields directly;  use the macros
 * defined below.
 */

typedef struct flowtable_entry_t {
    struct flowtable_entry_t *nextPtr;	/* Pointer to next entry in this
					 * hash bucket, or NULL for end of
					 * chain. */
    flowtable_t *ftable;	/* Pointer to table containing entry. */
    flow_t *flow;		/* Entry value. */
} flowtable_entry_t;

/*
 * Structure definition for a hash table.
 */

struct flowtable_t {
    allocator_t *alc;		/* Allocator of the hash table. */
    flowtable_entry_t **buckets;	/* Pointer to bucket array.  Each
					 * element points to first entry in
					 * bucket's hash chain, or NULL. */
    int firstBucket;
    int lastBucket;
    int numBuckets;		/* Total number of buckets allocated
				 * at **bucketPtr. */
    int numEntries;		/* Total number of entries present
				 * in table. */
    int rebuildSize;		/* Enlarge table when numEntries gets
				 * to be this large. */
    int downShift;		/* Shift count used in hashing
				 * function.  Designed to use high-
				 * order bits of randomized keys. */
    int mask;			/* Mask value used in hashing
				 * function. */
    flow_equal_fn flowEqualFn;
    pkt_in_flow_fn pktInFlowFn;
    destroy_notify_fn flowDestroyFn;
};

/* 
 * Hash iterator
 */
typedef struct flowtable_real_iter_t {
    flowtable_t *table;		/* Pointer to table containing entry. */
    flowtable_entry_t **bucket;	/* Pointer to bucket that points to
				 * first entry in this entry's chain:
				 * used for deleting the entry.
				 */
    flowtable_entry_t *entry;	/* Current hash entry */
    flowtable_entry_t *next_entry;	/* Next entry to be iterated onto
					 * in current bucket
					 */
    int next_bucket;		/* index of next bucket */
    int n_entries_on_init;	/* used to detect table resize since
				 * initialization
				 */
} flowtable_real_iter_t;

/*
 * Procedure prototypes for static procedures in this file:
 */

static void rebuild_table(flowtable_t * ftable);

/*
 *----------------------------------------------------------------------
 *
 * flowtable_new --
 *
 *	Given storage for a hash table, set up the fields to prepare
 *	the hash table for use.
 *
 * Arguments:
 *	ftable - Pointer to table record, which is supplied by the caller.
 *	keyType - Type of keys to use in table: HASHKEYS_STRING,
 *	          HASHKEYS_ULONG, or an integer >= 2.
 *	typePtr - Pointer to structure which defines the behaviour of this
 *	          table.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	ftable is now ready to be passed to flowtable_lookup and
 *	flowtable_insert.
 *
 *----------------------------------------------------------------------
 */

flowtable_t *
flowtable_new_full(allocator_t * alc, int size,
		   flow_equal_fn flowEqualFn,
		   pkt_in_flow_fn pktInFlowFn, destroy_notify_fn flowDestroyFn)
{
    flowtable_t *ftable;
    int numBuckets;

    assert(alc != NULL);
    ftable = alc_calloc(alc, 1, sizeof(flowtable_t));

    ftable->alc = alc;

    /* given size determines numBuckets */
    for (numBuckets = 1; numBuckets < size; numBuckets = numBuckets << 1);
    ftable->numBuckets = numBuckets;
    ftable->buckets = alc_calloc(ftable->alc, ftable->numBuckets,
				 sizeof(flowtable_entry_t *));

    ftable->numEntries = 0;
    ftable->rebuildSize = numBuckets * REBUILD_MULTIPLIER;
    ftable->downShift = 28;
    ftable->mask = numBuckets - 1;
    ftable->firstBucket = numBuckets;
    ftable->lastBucket = -1;
    ftable->flowEqualFn = flowEqualFn;
    ftable->pktInFlowFn = pktInFlowFn;
    ftable->flowDestroyFn = flowDestroyFn;

    return ftable;
}


int
flowtable_size(flowtable_t * ftable)
{
    return ftable->numEntries;
}


flow_t *
flowtable_lookup(flowtable_t * ftable, flowhash_t hash, pkt_t * pkt)
{
    flowtable_entry_t *hPtr;
    int i;

    i = hash & ftable->mask;

    /*
     * Search all of the entries in the appropriate bucket.
     */
    pkt_in_flow_fn pktInFlowFn = ftable->pktInFlowFn;
    for (hPtr = ftable->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	if (hash != hPtr->flow->hash) {
	    continue;
	}
	if (pktInFlowFn(pkt, hPtr->flow)) {
	    return hPtr->flow;
	}
    }

    return NULL;
}

flow_t *
flowtable_lookup_flow(flowtable_t * ftable, flow_t * flow)
{
    flowtable_entry_t *hPtr;
    int i;

    i = flow->hash & ftable->mask;

    /*
     * Search all of the entries in the appropriate bucket.
     */
    flow_equal_fn flowEqualFn = ftable->flowEqualFn;
    for (hPtr = ftable->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	if (flow->hash != hPtr->flow->hash) {
	    continue;
	}
	if (flowEqualFn(flow, hPtr->flow)) {
	    return hPtr->flow;
	}
    }

    return NULL;
}


int
flowtable_insert(flowtable_t * ftable, flow_t * flow)
{
    flowtable_entry_t *hPtr;
    int i;

    i = flow->hash & ftable->mask;

    if (i < ftable->firstBucket)
	ftable->firstBucket = i;

    if (i > ftable->lastBucket)
	ftable->lastBucket = i;

    /*
     * Search all of the entries in the appropriate bucket.
     */

    flow_equal_fn flowEqualFn = ftable->flowEqualFn;
    for (hPtr = ftable->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	if (flow->hash != (unsigned int) hPtr->flow->hash) {
	    continue;
	}
	if (flowEqualFn(flow, hPtr->flow)) {
	    if (ftable->flowDestroyFn && flow != hPtr->flow)
		ftable->flowDestroyFn(hPtr->flow);

	    hPtr->flow = flow;
	    return 0;
	}
    }

    /*
     * Entry not found.  Add a new one to the bucket.
     */
    hPtr = alc_calloc(ftable->alc, 1, sizeof(flowtable_entry_t));
    hPtr->flow = flow;
    hPtr->ftable = ftable;
    hPtr->nextPtr = ftable->buckets[i];
    ftable->buckets[i] = hPtr;
    ftable->numEntries++;

    /*
     * If the table has exceeded a decent size, rebuild it with many
     * more buckets.
     */

    if (ftable->numEntries >= ftable->rebuildSize) {
	rebuild_table(ftable);
    }
    return 1;
}


/*
 *----------------------------------------------------------------------
 *
 * flowtable_remove --
 *
 *	Remove a single entry from a hash table.
 *
 * Arguments:
 *	ftable - Table in which to remove entry.
 *	key - Key to use to find matching entry.
 *
 * Results:
 *	Returns 1 if the entry existed and was removed; otherwise 0.
 *
 * Side effects:
 *	The entry given by entryPtr is deleted from its table and
 *	should never again be used by the caller.
 *
 *----------------------------------------------------------------------
 */

static int
flowtable_remove_entry_internal(flowtable_t * ftable,
				flowtable_entry_t ** bucketPtr,
				flowtable_entry_t * entryPtr)
{
    if (*bucketPtr == entryPtr) {
	*bucketPtr = entryPtr->nextPtr;
    } else {
	flowtable_entry_t *prevPtr;

	for (prevPtr = *bucketPtr;; prevPtr = prevPtr->nextPtr) {
	    if (prevPtr == NULL) {
		/* malformed bucket chain in flowtable_remove */
		assert_not_reached();
	    }
	    if (prevPtr->nextPtr == entryPtr) {
		prevPtr->nextPtr = entryPtr->nextPtr;
		break;
	    }
	}
    }

    ftable->numEntries--;

    if (ftable->flowDestroyFn)
	ftable->flowDestroyFn(entryPtr->flow);

    alc_free(ftable->alc, entryPtr);

    return 1;
}

int
flowtable_remove(flowtable_t * ftable, flow_t * flow)
{
    flowtable_entry_t *hPtr;
    int i;

    i = flow->hash & ftable->mask;

    /*
     * Search all of the entries in the appropriate bucket.
     */

    flow_equal_fn flowEqualFn = ftable->flowEqualFn;
    for (hPtr = ftable->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	if (flow->hash != (unsigned int) hPtr->flow->hash) {
	    continue;
	}
	if (flowEqualFn(flow, hPtr->flow)) {
	    break;
	}
    }

    if (hPtr == NULL)
	return 0;

    return flowtable_remove_entry_internal(ftable, &(ftable->buckets[i]),
					   hPtr);
}


/*
 *----------------------------------------------------------------------
 *
 * flowtable_destroy --
 *
 *	Free up everything associated with a hash table except for
 *	the record for the table itself.
 *
 * Arguments:
 *	ftable - Table to delete.
 * Results:
 *	None.
 *
 * Side effects:
 *	The hash table is no longer useable.
 *
 *----------------------------------------------------------------------
 */

void
flowtable_destroy(flowtable_t * ftable)
{
    flowtable_entry_t *hPtr, *nextPtr;
    int i;

    /*
     * Free up all the entries in the table.
     */
    for (i = 0; i < ftable->numBuckets; i++) {
	hPtr = ftable->buckets[i];
	while (hPtr != NULL) {
	    nextPtr = hPtr->nextPtr;

	    if (ftable->flowDestroyFn)
		ftable->flowDestroyFn(hPtr->flow);

	    alc_free(ftable->alc, hPtr);
	    hPtr = nextPtr;
	}
    }

    /*
     * Free up the bucket array.
     */
    alc_free(ftable->alc, ftable->buckets);

    alc_free(ftable->alc, ftable);
}

/**
 * Initializes a hash table iterator. To iterate over all entries in a
 * hash table, use the following code (the printf assumes a hash
 * from strings to strings obviously):
 *
 * @code
 * flowtable_iter_t iter;
 *
 * flowtable_iter_init (table, &iter);
 * while (flowtable_iter_next (&iter))
 *   {
 *      printf ("The first key is %s and value is %s\n",
 *              flowtable_iter_get_string_key (&iter),
 *              flowtable_iter_get_value (&iter));
 *   }
 * 
 * 
 * @endcode
 *
 * The iterator is initialized pointing "one before" the first hash
 * entry. The first call to flowtable_iter_next() moves it onto
 * the first valid entry or returns 0 if the hash table is
 * empty. Subsequent calls move to the next valid entry or return
 * 0 if there are no more entries.
 *
 * Note that it is guaranteed to be safe to remove a hash entry during
 * iteration, but it is not safe to add a hash entry.
 * 
 * @param table the hash table to iterate over.
 * @param iter the iterator to initialize.
 */
void
flowtable_iter_init(flowtable_t * table, flowtable_iter_t * iter)
{
    flowtable_real_iter_t *real;

    assert(sizeof(flowtable_iter_t) == sizeof(flowtable_real_iter_t));

    real = (flowtable_real_iter_t *) iter;

    real->table = table;
    real->bucket = NULL;
    real->entry = NULL;
    real->next_entry = NULL;
    real->next_bucket = table->firstBucket;
    real->n_entries_on_init = table->numEntries;
}

/**
 * Move the hash iterator forward one step, to the next hash entry.
 * The documentation for flowtable_iter_init() explains in more
 * detail.
 *
 * @param iter the iterator to move forward.
 * @returns 0 if there are no more entries to move to.
 */
int
flowtable_iter_next(flowtable_iter_t * iter)
{
    flowtable_real_iter_t *real;

    assert(sizeof(flowtable_iter_t) == sizeof(flowtable_real_iter_t));

    real = (flowtable_real_iter_t *) iter;

    /* if this assertion failed someone probably added hash entries
     * during iteration, which is bad.
     */
    assert(real->n_entries_on_init >= real->table->numEntries);

    /* Remember that real->entry may have been deleted */

    while (real->next_entry == NULL) {
	if (real->next_bucket >= real->table->lastBucket) {
	    /* invalidate iter and return false */
	    real->entry = NULL;
	    real->table = NULL;
	    real->bucket = NULL;
	    return 0;
	}

	real->bucket = &(real->table->buckets[real->next_bucket]);
	real->next_entry = *(real->bucket);
	real->next_bucket += 1;
    }

    assert(real->next_entry != NULL);
    assert(real->bucket != NULL);

    real->entry = real->next_entry;
    real->next_entry = real->entry->nextPtr;

    return 1;
}

/**
 * Removes the current entry from the hash table.
 * If a key_free_function or value_free_function
 * was provided to flowtable_table_new(),
 * frees the key and/or value for this entry.
 *
 * @param iter the hash table iterator.
 */
void
flowtable_iter_remove(flowtable_iter_t * iter)
{
    flowtable_real_iter_t *real;

    real = (flowtable_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);
    assert(real->bucket != NULL);

    flowtable_remove_entry_internal(real->table, real->bucket, real->entry);

    real->entry = NULL;		/* make it crash if you try to use this entry */
}

/**
 * Gets the value of the current entry.
 *
 * @param iter the hash table iterator.
 */
flow_t *
flowtable_iter_get(flowtable_iter_t * iter)
{
    flowtable_real_iter_t *real;

    real = (flowtable_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    return real->entry->flow;
}

#ifdef DEBUG

const char *
flowtable_dbg_stats(flowtable_t *ftable)
{
#define NUM_COUNTERS 10
    int count[NUM_COUNTERS], overflow, i, j;
    double average, tmp;
    flowtable_entry_t *hPtr;
    char *result, *p;

    /*
     * Compute a histogram of bucket usage.
     */

    for (i = 0; i < NUM_COUNTERS; i++) {
	count[i] = 0;
    }
    overflow = 0;
    average = 0.0;
    for (i = 0; i < ftable->numBuckets; i++) {
	j = 0;
	for (hPtr = ftable->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    j++;
	}
	if (j < NUM_COUNTERS) {
	    count[j]++;
	} else {
	    overflow++;
	}
	tmp = j;
	average += (tmp + 1.0) * (tmp / ftable->numEntries) / 2.0;
    }

    /*
     * Print out the histogram and a few other pieces of information.
     */

    result = (char *) safe_malloc((NUM_COUNTERS * 60) + 300);
    sprintf(result, "%d entries in table, %d buckets\n",
	    ftable->numEntries, ftable->numBuckets);
    p = result + strlen(result);
    for (i = 0; i < NUM_COUNTERS; i++) {
	sprintf(p, "number of buckets with %d entries: %d\n", i, count[i]);
	p += strlen(p);
    }
    sprintf(p, "number of buckets with %d or more entries: %d\n",
	    NUM_COUNTERS, overflow);
    p += strlen(p);
    sprintf(p, "average search distance for entry: %.1f", average);
    return result;
}

#endif

/*
 *----------------------------------------------------------------------
 *
 * rebuild_table --
 *
 *	This procedure is invoked when the ratio of entries to hash
 *	buckets becomes too large.  It creates a new table with a
 *	larger bucket array and moves all of the entries into the
 *	new table.
 *
 * Arguments:
 *	ftable - Table to enlarge.
 * Results:
 *	None.
 *
 * Side effects:
 *	Memory gets reallocated and entries get re-hashed to new
 *	buckets.
 *
 *----------------------------------------------------------------------
 */

static void
rebuild_table(flowtable_t * ftable)
{
    int oldSize, count, i;
    flowtable_entry_t **oldBuckets;
    flowtable_entry_t **oldChainPtr, **newChainPtr;
    flowtable_entry_t *hPtr;
    void *key;

    oldSize = ftable->numBuckets;
    oldBuckets = ftable->buckets;

    /*
     * Allocate and initialize the new bucket array, and set up
     * hashing constants for new array size.
     */

    ftable->numBuckets *= 4;
    ftable->buckets = alc_calloc(ftable->alc, ftable->numBuckets,
				 sizeof(flowtable_entry_t *));

    for (count = ftable->numBuckets, newChainPtr = ftable->buckets;
	 count > 0; count--, newChainPtr++) {
	*newChainPtr = NULL;
    }
    ftable->rebuildSize *= 4;
    ftable->mask = (ftable->mask << 2) + 3;

    /*
     * Rehash all of the existing entries into the new bucket array.
     */

    for (oldChainPtr = oldBuckets; oldSize > 0; oldSize--, oldChainPtr++) {
	for (hPtr = *oldChainPtr; hPtr != NULL; hPtr = *oldChainPtr) {
	    *oldChainPtr = hPtr->nextPtr;

	    i = hPtr->flow->hash & ftable->mask;
	    hPtr->nextPtr = ftable->buckets[i];
	    ftable->buckets[i] = hPtr;
	}
    }

    /*
     * Free up the old bucket array.
     */
    alc_free(ftable->alc, oldBuckets);
}
