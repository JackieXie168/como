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

#include "como.h"
#include "comopriv.h"

/*
 * When there are this many entries per bucket, on average, rebuild
 * the hash table to make it larger.
 */

#define REBUILD_MULTIPLIER	3

/*
 * The following macro takes a preliminary integer hash value and
 * produces an index into a hash tables bucket list.  The idea is
 * to make it so that preliminary values that are arbitrarily similar
 * will end up in different buckets.  The hash function was taken
 * from a random-number generator.
 */

#define RANDOM_INDEX(tablePtr, i) \
    (((((long) (i))*1103515245) >> (tablePtr)->downShift) & (tablePtr)->mask)

/*
 * Structure definition for an entry in a hash table.  No-one outside
 * Tcl should access any of these fields directly;  use the macros
 * defined below.
 */

typedef struct hash_entry_t {
    struct hash_entry_t *nextPtr;	/* Pointer to next entry in this
					 * hash bucket, or NULL for end of
					 * chain. */
    hash_t *tablePtr;		/* Pointer to table containing entry. */
    unsigned int hash;		/* Hash value. */
    void *key;			/* Key. */
    void *value;		/* Entry value. */
} hash_entry_t;

/*
 * Structure definition for a hash table.
 */

#define SMALL_HASH_TABLE 4
struct hash_t {
    hash_entry_t **buckets;	/* Pointer to bucket array.  Each
				 * element points to first entry in
				 * bucket's hash chain, or NULL. */
    hash_entry_t *staticBuckets[SMALL_HASH_TABLE];
    /* Bucket array used for small tables
     * (to avoid mallocs and frees). */
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
    int keyType;		/* Type of keys used in this table. 
				 * It's either TCL_CUSTOM_KEYS,
				 * HASHKEYS_STRING, HASHKEYS_ULONG,
				 * or an integer giving the number of
				 * ints that is the size of the key.
				 */
    hash_key_fn hashKeyFn;
    compare_hash_keys_fn compareKeysFn;
    destroy_notify_fn keyDestroyFn;
    destroy_notify_fn valueDestroyFn;
    alc_t *alc;			/* Allocator of the hash table. */
};

/* 
 * Hash iterator
 */
typedef struct hash_real_iter_t {
    hash_t *table;		/* Pointer to table containing entry. */
    hash_entry_t **bucket;	/* Pointer to bucket that points to
				 * first entry in this entry's chain:
				 * used for deleting the entry.
				 */
    hash_entry_t *entry;	/* Current hash entry */
    hash_entry_t *next_entry;	/* Next entry to be iterated onto in current
				 * bucket
				 */
    int next_bucket;		/* index of next bucket */
    int n_entries_on_init;	/* used to detect table resize since
				 * initialization
				 */
} hash_real_iter_t;

/*
 * Prototypes for the string hash key methods.
 */

static unsigned int string_hash(const void *keyPtr);

/*
 * Procedure prototypes for static procedures in this file:
 */

static void rebuild_table(hash_t * tablePtr);

/*
 *----------------------------------------------------------------------
 *
 * hash_new --
 *
 *	Given storage for a hash table, set up the fields to prepare
 *	the hash table for use.
 *
 * Arguments:
 *	tablePtr - Pointer to table record, which is supplied by the caller.
 *	keyType - Type of keys to use in table: HASHKEYS_STRING,
 *	          HASHKEYS_ULONG, or an integer >= 2.
 *	typePtr - Pointer to structure which defines the behaviour of this
 *	          table.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	TablePtr is now ready to be passed to hash_lookup and
 *	hash_insert.
 *
 *----------------------------------------------------------------------
 */

hash_t *
hash_new(alc_t * alc, int keyType, hash_key_fn hashKeyFn,
	 compare_hash_keys_fn compareKeysFn)
{
    return hash_new_full(alc, keyType, hashKeyFn, compareKeysFn, NULL, NULL);
}

hash_t *
hash_new_full(alc_t * alc, int keyType, hash_key_fn hashKeyFn,
	      compare_hash_keys_fn compareKeysFn,
	      destroy_notify_fn keyDestroyFn, destroy_notify_fn valueDestroyFn)
{
    hash_t *tablePtr;

    if (alc == NULL)
        alc = como_alc();
        
    tablePtr = alc_new0(alc, hash_t);

#if (SMALL_HASH_TABLE != 4)
#error "SMALL_HASH_TABLE must be 4!"
#endif

    tablePtr->buckets = tablePtr->staticBuckets;
    tablePtr->staticBuckets[0] = tablePtr->staticBuckets[1] = 0;
    tablePtr->staticBuckets[2] = tablePtr->staticBuckets[3] = 0;
    tablePtr->numBuckets = SMALL_HASH_TABLE;
    tablePtr->numEntries = 0;
    tablePtr->rebuildSize = SMALL_HASH_TABLE * REBUILD_MULTIPLIER;
    tablePtr->downShift = 28;
    tablePtr->mask = 3;
    tablePtr->keyType = keyType;
    tablePtr->alc = alc;
    tablePtr->hashKeyFn = hashKeyFn;
    tablePtr->compareKeysFn = compareKeysFn;

    if (keyType == HASHKEYS_STRING) {
	if (hashKeyFn == NULL) {
	    tablePtr->hashKeyFn = string_hash;
	}

	if (compareKeysFn == NULL) {
	    tablePtr->compareKeysFn = (compare_hash_keys_fn) strcmp;
	}
    }

    tablePtr->keyDestroyFn = keyDestroyFn;
    tablePtr->valueDestroyFn = valueDestroyFn;

    return tablePtr;
}


int
hash_size(hash_t * tablePtr)
{
    return tablePtr->numEntries;
}


static hash_entry_t *
hash_lookup_internal(hash_t * tablePtr, void *key)
{
    hash_entry_t *hPtr;
    unsigned int hash;
    int i;

    if (tablePtr->hashKeyFn) {
	hash = tablePtr->hashKeyFn(key);
	i = hash & tablePtr->mask;
    } else {
	hash = (unsigned int) key;
	i = RANDOM_INDEX(tablePtr, hash);
    }

    /*
     * Search all of the entries in the appropriate bucket.
     */
    if (tablePtr->compareKeysFn) {
	compare_hash_keys_fn compareKeysFn = tablePtr->compareKeysFn;
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (compareKeysFn(key, hPtr->key) == 0) {
		return hPtr;
	    }
	}
    } else {
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (key == hPtr->key) {
		return hPtr;
	    }
	}
    }

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * hash_lookup_string --
 *
 *	Given a hash table find the entry with a matching key.
 *
 * Arguments:
 *	tablePtr - Table in which to lookup entry.
 *	key - Key to use to find matching entry.
 *
 * Results:
 *	The return value is the value of the matching entry in the
 *	hash table, or NULL if there was no matching entry.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

void *
hash_lookup_string(hash_t * tablePtr, const char *key)
{
    hash_entry_t *hPtr;

    assert(tablePtr->keyType == HASHKEYS_STRING);

    hPtr = hash_lookup_internal(tablePtr, (void *) key);

    return (hPtr) ? hPtr->value : NULL;
}

void *
hash_lookup_ulong(hash_t * tablePtr, unsigned long key)
{
    hash_entry_t *hPtr;

    assert(tablePtr->keyType == HASHKEYS_ULONG);

    hPtr = hash_lookup_internal(tablePtr, (void *) key);

    return (hPtr) ? hPtr->value : NULL;
}

void *
hash_lookup(hash_t * tablePtr, void *key)
{
    hash_entry_t *hPtr;

    assert(tablePtr->keyType == HASHKEYS_POINTER);

    hPtr = hash_lookup_internal(tablePtr, key);

    return (hPtr) ? hPtr->value : NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * hash_insert_internal --
 *
 *	Given a hash table with string keys, and a string key, find
 *	the entry with a matching key.  If there is no matching entry,
 *	then create a new entry that does match.
 *
 * Arguments:
 *	tablePtr - Table in which to lookup entry.
 *	key - Key to use to find or create matching entry.
 *	value - Value associated to Key.
 *
 * Results:
 *	If this is a newly-created entry, then the functions returns 1;
 *	otherwise returns 0.
 *
 * Side effects:
 *	A new entry may be added to the hash table.
 *
 *----------------------------------------------------------------------
 */

static int
hash_insert_internal(hash_t * tablePtr, void *key, void *value)
{
    hash_entry_t *hPtr;
    unsigned int hash;
    int i;

    if (tablePtr->hashKeyFn) {
	hash = tablePtr->hashKeyFn(key);
	i = hash & tablePtr->mask;
    } else {
	hash = (unsigned int) key;
	i = RANDOM_INDEX(tablePtr, hash);
    }

    /*
     * Search all of the entries in the appropriate bucket.
     */

    if (tablePtr->compareKeysFn) {
	compare_hash_keys_fn compareKeysFn = tablePtr->compareKeysFn;
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (compareKeysFn(key, hPtr->key) == 0) {
		if (tablePtr->valueDestroyFn && value != hPtr->value)
		    tablePtr->valueDestroyFn(hPtr->value);

		hPtr->value = value;
		return 0;
	    }
	}
    } else {
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (key == hPtr->key) {
		if (tablePtr->valueDestroyFn && value != hPtr->value)
		    tablePtr->valueDestroyFn(hPtr->value);

		hPtr->value = value;
		return 0;
	    }
	}
    }

    /*
     * Entry not found.  Add a new one to the bucket.
     */
    hPtr = alc_calloc(tablePtr->alc, 1, sizeof(hash_entry_t));
    hPtr->key = key;
    hPtr->value = value;
    hPtr->tablePtr = tablePtr;
    hPtr->hash = hash;
    hPtr->nextPtr = tablePtr->buckets[i];
    tablePtr->buckets[i] = hPtr;
    tablePtr->numEntries++;

    /*
     * If the table has exceeded a decent size, rebuild it with many
     * more buckets.
     */

    if (tablePtr->numEntries >= tablePtr->rebuildSize) {
	rebuild_table(tablePtr);
    }
    return 1;
}

int
hash_insert_string(hash_t * tablePtr, const char *key, void *value)
{
    assert(tablePtr->keyType == HASHKEYS_STRING);

    return hash_insert_internal(tablePtr, (void *) key, value);
}

int
hash_insert_ulong(hash_t * tablePtr, unsigned long key, void *value)
{
    assert(tablePtr->keyType == HASHKEYS_ULONG);

    return hash_insert_internal(tablePtr, (void *) key, value);
}

int
hash_insert(hash_t * tablePtr, void *key, void *value)
{
    assert(tablePtr->keyType == HASHKEYS_POINTER);

    return hash_insert_internal(tablePtr, key, value);
}

/*
 *----------------------------------------------------------------------
 *
 * hash_remove --
 *
 *	Remove a single entry from a hash table.
 *
 * Arguments:
 *	tablePtr - Table in which to remove entry.
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
hash_remove_entry_internal(hash_t * tablePtr, hash_entry_t ** bucketPtr,
			   hash_entry_t * entryPtr)
{
    if (*bucketPtr == entryPtr) {
	*bucketPtr = entryPtr->nextPtr;
    } else {
	hash_entry_t *prevPtr;

	for (prevPtr = *bucketPtr;; prevPtr = prevPtr->nextPtr) {
	    if (prevPtr == NULL) {
		/* malformed bucket chain in hash_remove */
		assert_not_reached();
	    }
	    if (prevPtr->nextPtr == entryPtr) {
		prevPtr->nextPtr = entryPtr->nextPtr;
		break;
	    }
	}
    }

    tablePtr->numEntries--;

    if (tablePtr->keyDestroyFn)
	tablePtr->keyDestroyFn(entryPtr->key);
    if (tablePtr->valueDestroyFn)
	tablePtr->valueDestroyFn(entryPtr->value);

    alc_free(tablePtr->alc, entryPtr);

    return 1;
}

static int
hash_remove_internal(hash_t * tablePtr, void *key)
{
    hash_entry_t *entryPtr;
    hash_entry_t **bucketPtr;
    int i;

    entryPtr = hash_lookup_internal(tablePtr, key);
    if (entryPtr == NULL)
	return 0;

    if (tablePtr->hashKeyFn) {
	i = ((unsigned int) entryPtr->hash) & tablePtr->mask;
    } else {
	i = RANDOM_INDEX(tablePtr, entryPtr->hash);
    }

    bucketPtr = &(tablePtr->buckets[i]);

    return hash_remove_entry_internal(tablePtr, bucketPtr, entryPtr);
}

int
hash_remove_string(hash_t * tablePtr, const char *key)
{
    assert(tablePtr->keyType == HASHKEYS_STRING);

    return hash_remove_internal(tablePtr, (void *) key);
}

int
hash_remove_ulong(hash_t * tablePtr, unsigned long key)
{
    assert(tablePtr->keyType == HASHKEYS_ULONG);

    return hash_remove_internal(tablePtr, (void *) key);
}

int
hash_remove(hash_t * tablePtr, void *key)
{
    assert(tablePtr->keyType == HASHKEYS_POINTER);

    return hash_remove_internal(tablePtr, key);
}

/*
 *----------------------------------------------------------------------
 *
 * hash_destroy --
 *
 *	Free up everything associated with a hash table except for
 *	the record for the table itself.
 *
 * Arguments:
 *	tablePtr - Table to delete.
 * Results:
 *	None.
 *
 * Side effects:
 *	The hash table is no longer useable.
 *
 *----------------------------------------------------------------------
 */

void
hash_destroy(hash_t * tablePtr)
{
    hash_entry_t *hPtr, *nextPtr;
    int i;

    /*
     * Free up all the entries in the table.
     */
    for (i = 0; i < tablePtr->numBuckets; i++) {
	hPtr = tablePtr->buckets[i];
	while (hPtr != NULL) {
	    nextPtr = hPtr->nextPtr;

	    if (tablePtr->keyDestroyFn)
		tablePtr->keyDestroyFn(hPtr->key);
	    if (tablePtr->valueDestroyFn)
		tablePtr->valueDestroyFn(hPtr->value);

	    alc_free(tablePtr->alc, hPtr);
	    hPtr = nextPtr;
	}
    }

    /*
     * Free up the bucket array, if it was dynamically allocated.
     */
    if (tablePtr->buckets != tablePtr->staticBuckets) {
	alc_free(tablePtr->alc, tablePtr->buckets);
    }

    alc_free(tablePtr->alc, tablePtr);
}

/**
 * Initializes a hash table iterator. To iterate over all entries in a
 * hash table, use the following code (the printf assumes a hash
 * from strings to strings obviously):
 *
 * @code
 * hash_iter_t iter;
 *
 * hash_iter_init (table, &iter);
 * while (hash_iter_next (&iter))
 *   {
 *      printf ("The first key is %s and value is %s\n",
 *              hash_iter_get_string_key (&iter),
 *              hash_iter_get_value (&iter));
 *   }
 * 
 * 
 * @endcode
 *
 * The iterator is initialized pointing "one before" the first hash
 * entry. The first call to hash_iter_next() moves it onto
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
hash_iter_init(hash_t * table, hash_iter_t * iter)
{
    hash_real_iter_t *real;

    assert(sizeof(hash_iter_t) == sizeof(hash_real_iter_t));

    real = (hash_real_iter_t *) iter;

    real->table = table;
    real->bucket = NULL;
    real->entry = NULL;
    real->next_entry = NULL;
    real->next_bucket = 0;
    real->n_entries_on_init = table->numEntries;
}

/**
 * Move the hash iterator forward one step, to the next hash entry.
 * The documentation for hash_iter_init() explains in more
 * detail.
 *
 * @param iter the iterator to move forward.
 * @returns 0 if there are no more entries to move to.
 */
int
hash_iter_next(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    assert(sizeof(hash_iter_t) == sizeof(hash_real_iter_t));

    real = (hash_real_iter_t *) iter;

    /* if this assertion failed someone probably added hash entries
     * during iteration, which is bad.
     */
    assert(real->n_entries_on_init >= real->table->numEntries);

    /* Remember that real->entry may have been deleted */

    while (real->next_entry == NULL) {
	if (real->next_bucket >= real->table->numBuckets) {
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
 * was provided to hash_table_new(),
 * frees the key and/or value for this entry.
 *
 * @param iter the hash table iterator.
 */
void
hash_iter_remove_entry(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);
    assert(real->bucket != NULL);

    hash_remove_entry_internal(real->table, real->bucket, real->entry);

    real->entry = NULL; /* make it crash if you try to use this entry */
}

/**
 * Gets the value of the current entry.
 *
 * @param iter the hash table iterator.
 */
void *
hash_iter_get_value(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    return real->entry->value;
}

/**
 * Sets the value of the current entry.
 * If the hash table has a value_free_function
 * it will be used to free the previous value.
 * The hash table will own the passed-in value
 * (it will not be copied).
 *
 * @param iter the hash table iterator.
 * @param value the new value.
 */
void
hash_iter_set_value(hash_iter_t * iter, void *value)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    if (real->table->valueDestroyFn && value != real->entry->value)
	real->table->valueDestroyFn(real->entry->value);

    real->entry->value = value;
}

/**
 * Gets the key for the current entry.
 * Only works for hash tables of type #HASHKEYS_POINTER.
 *
 * @param iter the hash table iterator.
 */
void *
hash_iter_get_key(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    return real->entry->key;
}

/**
 * Gets the key for the current entry.
 * Only works for hash tables of type #HASHKEYS_ULONG.
 *
 * @param iter the hash table iterator.
 */
unsigned long
hash_iter_get_ulong_key(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    return (unsigned long) real->entry->key;
}

/**
 * Gets the key for the current entry.
 * Only works for hash tables of type #HASHKEYS_STRING
 * @param iter the hash table iterator.
 */
const char *
hash_iter_get_string_key(hash_iter_t * iter)
{
    hash_real_iter_t *real;

    real = (hash_real_iter_t *) iter;

    assert(real->table != NULL);
    assert(real->entry != NULL);

    return real->entry->key;
}

#if 0
/*
 *----------------------------------------------------------------------
 *
 * Tcl_HashStats --
 *
 *	Return statistics describing the layout of the hash table
 *	in its hash buckets.
 *
 * Results:
 *	The return value is a malloc-ed string containing information
 *	about tablePtr.  It is the caller's responsibility to free
 *	this string.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

const char *
Tcl_HashStats(tablePtr)
hash_t *tablePtr;		/* Table for which to produce stats. */
{
#define NUM_COUNTERS 10
    int count[NUM_COUNTERS], overflow, i, j;
    double average, tmp;
    hash_entry_t *hPtr;
    char *result, *p;

    /*
     * Compute a histogram of bucket usage.
     */

    for (i = 0; i < NUM_COUNTERS; i++) {
	count[i] = 0;
    }
    overflow = 0;
    average = 0.0;
    for (i = 0; i < tablePtr->numBuckets; i++) {
	j = 0;
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL; hPtr = hPtr->nextPtr) {
	    j++;
	}
	if (j < NUM_COUNTERS) {
	    count[j]++;
	} else {
	    overflow++;
	}
	tmp = j;
	average += (tmp + 1.0) * (tmp / tablePtr->numEntries) / 2.0;
    }

    /*
     * Print out the histogram and a few other pieces of information.
     */

    result = (char *) ckalloc((unsigned) ((NUM_COUNTERS * 60) + 300));
    sprintf(result, "%d entries in table, %d buckets\n",
	    tablePtr->numEntries, tablePtr->numBuckets);
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
 * string_alloc --
 *
 *	Allocate space for a hash_entry_t containing the string key.
 *
 * Results:
 *	The return value is a pointer to the created entry.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static unsigned int
string_hash(const void *str)
{
    const char *p = (const char *) str;
    unsigned int h = *p;

    if (h)
	for (p += 1; *p != '\0'; p++)
	    h = (h << 5) - h + *p;

    return h;
}

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
 *	tablePtr - Table to enlarge.
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
rebuild_table(hash_t * tablePtr)
{
    int oldSize, count, i;
    hash_entry_t **oldBuckets;
    hash_entry_t **oldChainPtr, **newChainPtr;
    hash_entry_t *hPtr;
    void *key;

    oldSize = tablePtr->numBuckets;
    oldBuckets = tablePtr->buckets;

    /*
     * Allocate and initialize the new bucket array, and set up
     * hashing constants for new array size.
     */

    tablePtr->numBuckets *= 4;
    tablePtr->buckets = alc_calloc(tablePtr->alc, tablePtr->numBuckets,
				   sizeof(hash_entry_t *));

    for (count = tablePtr->numBuckets, newChainPtr = tablePtr->buckets;
	 count > 0; count--, newChainPtr++) {
	*newChainPtr = NULL;
    }
    tablePtr->rebuildSize *= 4;
    tablePtr->downShift -= 2;
    tablePtr->mask = (tablePtr->mask << 2) + 3;

    /*
     * Rehash all of the existing entries into the new bucket array.
     */

    for (oldChainPtr = oldBuckets; oldSize > 0; oldSize--, oldChainPtr++) {
	for (hPtr = *oldChainPtr; hPtr != NULL; hPtr = *oldChainPtr) {
	    *oldChainPtr = hPtr->nextPtr;

	    key = hPtr->key;

	    if (tablePtr->hashKeyFn) {
		i = ((unsigned int) hPtr->hash) & tablePtr->mask;
	    } else {
		i = RANDOM_INDEX(tablePtr, hPtr->hash);
	    }
	    hPtr->nextPtr = tablePtr->buckets[i];
	    tablePtr->buckets[i] = hPtr;
	}
    }

    /*
     * Free up the old bucket array, if it was dynamically allocated.
     */

    if (oldBuckets != tablePtr->staticBuckets) {
	alc_free(tablePtr->alc, oldBuckets);
    }
}
