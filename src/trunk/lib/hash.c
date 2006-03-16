/*
 * Copyright (c) 2006 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#include <string.h>
#include <assert.h>

#include "como.h"
#include "hash.h"

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


typedef void (*free_key_fn) (void *key);
typedef void (*free_value_fn) (void *value);

/*
 * Structure definition for an entry in a hash table.  No-one outside
 * Tcl should access any of these fields directly;  use the macros
 * defined below.
 */

typedef struct hash_entry_t hash_entry_t;

struct hash_entry_t {
    hash_entry_t *nextPtr;		/* Pointer to next entry in this
					 * hash bucket, or NULL for end of
					 * chain. */
    hash_t *tablePtr;			/* Pointer to table containing entry. */
    unsigned int hash;			/* Hash value. */
    void *key;				/* Key. */
    void *value;			/* Entry value. */
};

#if 0
/*
 * Structure definition for the methods associated with a hash table
 * key type.
 */
struct hash_key_t {

    /* Calculates a hash value for the key. If this is NULL then the pointer
     * itself is used as a hash value.
     */
    hash_key_fn *hashKeyFn;

    /* Compares two keys and returns zero if they do not match, and non-zero
     * if they do. If this is NULL then the pointers are compared.
     */
    compare_hash_keys_fn *compareKeysFn;

    /* Called to allocate memory for a new entry, i.e. if the key is a
     * string then this could allocate a single block which contains enough
     * space for both the entry and the string. Only the key field of the
     * allocated hash_entry_t structure needs to be filled in. If something
     * else needs to be done to the key, i.e. incrementing a reference count
     * then that should be done by this function. If this is NULL then
     * como_alloc is used to allocate enough space for a hash_entry_t and the
     * key pointer is assigned to key.oneWordValue.
     */
    alloc_hash_entry_fn *allocEntryFn;

    /* Called to free memory associated with an entry. If something else needs
     * to be done to the key, i.e. decrementing a reference count then that
     * should be done by this function. If this is NULL then como_free is used
     * to free the hash_entry_t.
     */
    free_hash_entry_fn *freeEntryFn;
};
#endif

/*
 * Structure definition for a hash table.
 */

#define SMALL_HASH_TABLE 4
struct hash_t {
    hash_entry_t **buckets;		/* Pointer to bucket array.  Each
					 * element points to first entry in
					 * bucket's hash chain, or NULL. */
    hash_entry_t *staticBuckets[SMALL_HASH_TABLE];
					/* Bucket array used for small tables
					 * (to avoid mallocs and frees). */
    int numBuckets;			/* Total number of buckets allocated
					 * at **bucketPtr. */
    int numEntries;			/* Total number of entries present
					 * in table. */
    int rebuildSize;			/* Enlarge table when numEntries gets
					 * to be this large. */
    int downShift;			/* Shift count used in hashing
					 * function.  Designed to use high-
					 * order bits of randomized keys. */
    int mask;				/* Mask value used in hashing
					 * function. */
    int keyType;			/* Type of keys used in this table. 
					 * It's either TCL_CUSTOM_KEYS,
					 * HASHKEYS_STRING, HASHKEYS_ULONG,
					 * or an integer giving the number of
					 * ints that is the size of the key.
					 */
    hash_key_fn hashKeyFn;
    compare_hash_keys_fn compareKeysFn;
    module_t *mdl;			/* Module owner of the hash table. */
};

/*
 * Structure definition for information used to keep track of searches
 * through hash tables:
 */

typedef struct hash_search_t {
    hash_t *tablePtr;		/* Table being searched. */
    int nextIndex;		/* Index of next bucket to be
				 * enumerated after present one. */
    hash_entry_t *nextEntryPtr;	/* Next entry to be enumerated in the
				 * the current bucket. */
} hash_search_t;


/*
 * Prototypes for the string hash key methods.
 */

static unsigned int string_hash (const void *keyPtr);

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
 *	typePtr - Pointer to structure which defines the behaviour of this table.
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
hash_new(module_t *mdl, int keyType, hash_key_fn hashKeyFn,
	 compare_hash_keys_fn compareKeysFn)
{
    hash_t *tablePtr;
    
    if (mdl) {
	tablePtr = mdl_mem_alloc(mdl, sizeof(hash_t));
	memset(tablePtr, 0, sizeof(hash_t));
    } else {
	tablePtr = safe_calloc(1, sizeof(hash_t));
    }

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
    tablePtr->mdl = mdl;
    
    if (keyType == HASHKEYS_STRING) {
	if (hashKeyFn == NULL) {
    	    tablePtr->hashKeyFn = string_hash;
	}
    	
	if (compareKeysFn == NULL) {
    	    tablePtr->compareKeysFn = (compare_hash_keys_fn) strcmp;
	}
    }

    return tablePtr;
}

static hash_entry_t *
hash_lookup_internal(hash_t *tablePtr, void *key)
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
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL;
	     hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (compareKeysFn(key, hPtr->key) == 0) {
		return hPtr->value;
	    }
	}
    } else {
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL;
	     hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (key == hPtr->key) {
		return hPtr->value;
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
hash_lookup_string(hash_t *tablePtr, const char *key)
{
    hash_entry_t *hPtr;
    
    assert(tablePtr->keyType = HASHKEYS_STRING);
    
    hPtr = hash_lookup_internal(tablePtr, (void *) key);
    
    return (hPtr) ? hPtr->value : NULL;
}


void *
hash_lookup_ulong(hash_t *tablePtr, unsigned long key)
{
    hash_entry_t *hPtr;
    
    assert(tablePtr->keyType = HASHKEYS_ULONG);
    
    hPtr = hash_lookup_internal(tablePtr, (void *) key);
    
    return (hPtr) ? hPtr->value : NULL;
}

void *
hash_lookup(hash_t *tablePtr, void *key)
{
    hash_entry_t *hPtr;
    
    assert(tablePtr->keyType = HASHKEYS_POINTER);
    
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
hash_insert_internal(hash_t *tablePtr, void *key, void *value)
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
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL;
	     hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (compareKeysFn(key, hPtr->key) == 0) {
		hPtr->value = value;
		/* TODO: free value */
		return 0;
	    }
	}
    } else {
	for (hPtr = tablePtr->buckets[i]; hPtr != NULL;
	     hPtr = hPtr->nextPtr) {
	    if (hash != (unsigned int) hPtr->hash) {
		continue;
	    }
	    if (key == hPtr->key) {
		hPtr->value = value;
		/* TODO: free value */
		return 0;
	    }
	}
    }

    /*
     * Entry not found.  Add a new one to the bucket.
     */
    if (tablePtr->mdl) {
	hPtr = mdl_mem_alloc(tablePtr->mdl, sizeof(hash_entry_t));
	memset(hPtr, 0, sizeof(hash_entry_t));
    } else {
	hPtr = safe_calloc(1, sizeof(hash_entry_t));
    }
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
hash_insert_string(hash_t *tablePtr, const char *key, void *value)
{
    assert(tablePtr->keyType = HASHKEYS_STRING);
    
    return hash_insert_internal(tablePtr, (void *) key, value);
}

int
hash_insert_ulong(hash_t *tablePtr, unsigned long key, void *value)
{
    assert(tablePtr->keyType = HASHKEYS_ULONG);
    
    return hash_insert_internal(tablePtr, (void *) key, value);
}

int
hash_insert(hash_t *tablePtr, void *key, void *value)
{
    assert(tablePtr->keyType = HASHKEYS_POINTER);
    
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
hash_remove_internal(hash_t *tablePtr, void *key)
{
    hash_entry_t *entryPtr;
    hash_entry_t *prevPtr;
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

    if (*bucketPtr == entryPtr) {
	*bucketPtr = entryPtr->nextPtr;
    } else {
	for (prevPtr = *bucketPtr;; prevPtr = prevPtr->nextPtr) {
	    if (prevPtr == NULL) {
		assert_not_reached(); /* malformed bucket chain in hash_remove */
	    }
	    if (prevPtr->nextPtr == entryPtr) {
		prevPtr->nextPtr = entryPtr->nextPtr;
		break;
	    }
	}
    }

    tablePtr->numEntries--;
    if (tablePtr->mdl) {
	mdl_mem_free(tablePtr->mdl, entryPtr);
    } else {
    	free(entryPtr);
    }
    
    return 1;
}

int
hash_remove_string(hash_t *tablePtr, const char *key)
{
    assert(tablePtr->keyType = HASHKEYS_STRING);
    
    return hash_remove_internal(tablePtr, (void *) key);
}

int
hash_remove_ulong(hash_t *tablePtr, unsigned long key)
{
    assert(tablePtr->keyType = HASHKEYS_ULONG);
    
    return hash_remove_internal(tablePtr, (void *) key);
}

int
hash_remove(hash_t *tablePtr, void *key)
{
    assert(tablePtr->keyType = HASHKEYS_POINTER);
    
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
hash_destroy(hash_t *tablePtr)
{
    hash_entry_t *hPtr, *nextPtr;
    int i;
    
    /*
     * Free up all the entries in the table.
     */
    if (tablePtr->mdl) {
	for (i = 0; i < tablePtr->numBuckets; i++) {
	    hPtr = tablePtr->buckets[i];
	    while (hPtr != NULL) {
		nextPtr = hPtr->nextPtr;
		/* TODO: free value */
		mdl_mem_free(tablePtr->mdl, hPtr);
		hPtr = nextPtr;
	    }
	}
	
	/*
	 * Free up the bucket array, if it was dynamically allocated.
	 */
	if (tablePtr->buckets != tablePtr->staticBuckets) {
	    mdl_mem_free(tablePtr->mdl, tablePtr->buckets);
	}

	mdl_mem_free(tablePtr->mdl, tablePtr);
    } else {
	for (i = 0; i < tablePtr->numBuckets; i++) {
	    hPtr = tablePtr->buckets[i];
	    while (hPtr != NULL) {
		nextPtr = hPtr->nextPtr;
		/* TODO: free value */
		free(hPtr);
		hPtr = nextPtr;
	    }
	}
	
	/*
	 * Free up the bucket array, if it was dynamically allocated.
	 */
	if (tablePtr->buckets != tablePtr->staticBuckets) {
	    free(tablePtr->buckets);
	}

	free(tablePtr);
    }
}

#if 0
/*
 *----------------------------------------------------------------------
 *
 * hash_get_first_entry --
 *
 *	Locate the first entry in a hash table and set up a record
 *	that can be used to step through all the remaining entries
 *	of the table.
 *
 * Arguments:
 *	tablePtr - Table to search.
 *	searchPtr - Place to store information about progress through the
 *	            table.
 *
 * Results:
 *	The return value is a pointer to the first entry in tablePtr,
 *	or NULL if tablePtr has no entries in it.  The memory at
 *	*searchPtr is initialized so that subsequent calls to
 *	hash_get_next_entry will return all of the entries in the table,
 *	one at a time.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

hash_entry_t *
hash_get_first_entry(hash_t *tablePtr, hash_search_t *searchPtr)
{
    searchPtr->tablePtr = tablePtr;
    searchPtr->nextIndex = 0;
    searchPtr->nextEntryPtr = NULL;
    return hash_get_next_entry(searchPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * hash_get_next_entry --
 *
 *	Once a hash table enumeration has been initiated by calling
 *	hash_get_first_entry, this procedure may be called to return
 *	successive elements of the table.
 *
 * Arguments:
 *	searchPtr - Place to store information about progress through the
 *	            table. Must have been initialized by calling
 *	            hash_get_first_entry.
 *
 * Results:
 *	The return value is the next entry in the hash table being
 *	enumerated, or NULL if the end of the table is reached.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

hash_entry_t *
hash_get_next_entry(hash_search_t *searchPtr)
{
    hash_entry_t *hPtr;
    hash_t *tablePtr = searchPtr->tablePtr;

    while (searchPtr->nextEntryPtr == NULL) {
	if (searchPtr->nextIndex >= tablePtr->numBuckets) {
	    return NULL;
	}
	searchPtr->nextEntryPtr = tablePtr->buckets[searchPtr->nextIndex];
	searchPtr->nextIndex++;
    }
    hPtr = searchPtr->nextEntryPtr;
    searchPtr->nextEntryPtr = hPtr->nextPtr;
    return hPtr;
}

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
hash_t *tablePtr;	/* Table for which to produce stats. */
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
string_hash (const void *str)
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
rebuild_table(hash_t *tablePtr)
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
    if (tablePtr->mdl) {
	tablePtr->buckets = mdl_mem_alloc(tablePtr->mdl, (tablePtr->numBuckets
					  * sizeof(hash_entry_t *)));
	memset(tablePtr->buckets, 0, (tablePtr->numBuckets *
	       sizeof(hash_entry_t *)));
    } else {
	tablePtr->buckets = safe_calloc(tablePtr->numBuckets,
					sizeof(hash_entry_t *));
    }
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
	if (tablePtr->mdl) {
	    mdl_mem_free(tablePtr->mdl, oldBuckets);
	} else {
	    free(oldBuckets);
	}
    }
}
