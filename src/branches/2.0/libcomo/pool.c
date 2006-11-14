#include <stdlib.h>     /* for malloc, free and abort */
#include <stdint.h>
#include <sys/types.h>
#include <string.h>

#include <stdio.h>
#include <sys/time.h>

#include "como.h"

/** the allocator structure */
typedef struct allocator_t allocator_t;
/** the structure which holds information about the allocation */
typedef struct memnode_t memnode_t;

/** basic memory node structure
 * @note The next, ref and first_avail fields are available for use by the
 *       caller of allocator_alloc(), the remaining fields are read-only.
 *       The next field has to be used with caution and sensibly set when the
 *       memnode is passed back to allocator_free().  See allocator_free()
 *       for details.  
 *       The ref and first_avail fields will be properly restored by
 *       allocator_free().
 */
struct memnode_t {
    memnode_t *next;            /**< next memnode */
    memnode_t **ref;            /**< reference to self */
    uint32_t   index;           /**< size */
    uint32_t   free_index;      /**< how much free */
    char      *first_avail;     /**< pointer to first free memory */
    char      *endp;            /**< pointer to end of free memory */
};

/** The base size of a memory node - aligned.  */
#define MEMNODE_T_SIZE ALIGN_DEFAULT(sizeof(memnode_t))

/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */





/*
 * Magic numbers
 */

#define MIN_ALLOC 8192
#define MAX_INDEX   20

#define BOUNDARY_INDEX 12
#define BOUNDARY_SIZE (1 << BOUNDARY_INDEX)


/*
 * Allocator
 */

struct allocator_t {
    uint32_t        max_index;
    uint32_t        max_free_index;
    uint32_t        current_free_index;
    memnode_t      *free[MAX_INDEX];
};

#define SIZEOF_ALLOCATOR_T  ALIGN_DEFAULT(sizeof(allocator_t))


/*
 * Allocator
 */

#define ALLOCATOR_MAX_FREE_UNLIMITED 0

static allocator_t *
allocator_create()
{
    allocator_t *new_allocator;

    if ((new_allocator = malloc(SIZEOF_ALLOCATOR_T)) == NULL)
        return NULL;

    memset(new_allocator, 0, SIZEOF_ALLOCATOR_T);
    new_allocator->max_free_index = ALLOCATOR_MAX_FREE_UNLIMITED;

    return new_allocator;
}

static void
allocator_destroy(allocator_t *allocator)
{
    uint32_t idx;
    memnode_t *node, **ref;

    for (idx = 0; idx < MAX_INDEX; idx++) {
        ref = &allocator->free[idx];
        while ((node = *ref) != NULL) {
            *ref = node->next;
            free(node);
        }
    }

    free(allocator);
}

void
allocator_max_free_set(allocator_t *allocator, size_t in_size)
{
    uint32_t max_free_index;
    uint32_t size = (uint32_t) in_size;


    max_free_index = ALIGN(size, BOUNDARY_SIZE) >> BOUNDARY_INDEX;
    allocator->current_free_index += max_free_index;
    allocator->current_free_index -= allocator->max_free_index;
    allocator->max_free_index = max_free_index;
    if (allocator->current_free_index > max_free_index)
        allocator->current_free_index = max_free_index;

}

static memnode_t *
allocator_alloc(allocator_t *allocator, size_t size)
{
    memnode_t *node, **ref;
    uint32_t max_index;
    size_t i, idx;

    /* Round up the block size to the next boundary, but always
     * allocate at least a certain size (MIN_ALLOC).
     */
    size = ALIGN(size + MEMNODE_T_SIZE, BOUNDARY_SIZE);
    if (size < MIN_ALLOC)
        size = MIN_ALLOC;

    /* Find the index for this node size by
     * dividing its size by the boundary size
     */
    idx = (size >> BOUNDARY_INDEX) - 1;
    
    if (idx > UINT32_MAX) {
        return NULL;
    }

    /* First see if there are any nodes in the area we know
     * our node will fit into.
     */
    if (idx <= allocator->max_index) {

        /* Walk the free list to see if there are
         * any nodes on it of the requested size
         *
         * NOTE: an optimization would be to check
         * allocator->free[index] first and if no
         * node is present, directly use
         * allocator->free[max_index].  This seems
         * like overkill though and could cause
         * memory waste.
         */
        max_index = allocator->max_index;
        ref = &allocator->free[idx];
        i = idx;
        while (*ref == NULL && i < max_index) {
           ref++;
           i++;
        }

        if ((node = *ref) != NULL) {
            /* If we have found a node and it doesn't have any
             * nodes waiting in line behind it _and_ we are on
             * the highest available index, find the new highest
             * available index
             */
            if ((*ref = node->next) == NULL && i >= max_index) {
                do {
                    ref--;
                    max_index--;
                }
                while (*ref == NULL && max_index > 0);

                allocator->max_index = max_index;
            }

            allocator->current_free_index += node->index;
            if (allocator->current_free_index > allocator->max_free_index)
                allocator->current_free_index = allocator->max_free_index;


            node->next = NULL;
            node->first_avail = (char *)node + MEMNODE_T_SIZE;

            return node;
        }

    }

    /* If we found nothing, seek the sink (at index 0), if
     * it is not empty.
     */
    else if (allocator->free[0]) {

        /* Walk the free list to see if there are
         * any nodes on it of the requested size
         */
        ref = &allocator->free[0];
        while ((node = *ref) != NULL && idx > node->index)
            ref = &node->next;

        if (node) {
            *ref = node->next;

            allocator->current_free_index += node->index;
            if (allocator->current_free_index > allocator->max_free_index)
                allocator->current_free_index = allocator->max_free_index;


            node->next = NULL;
            node->first_avail = (char *)node + MEMNODE_T_SIZE;

            return node;
        }

    }

    /* If we haven't got a suitable node, malloc a new one
     * and initialize it.
     */
    if ((node = malloc(size)) == NULL)
        return NULL;

    node->next = NULL;
    node->index = (uint32_t)idx;
    node->first_avail = (char *)node + MEMNODE_T_SIZE;
    node->endp = (char *)node + size;

    return node;
}

static void
allocator_free(allocator_t *allocator, memnode_t *node)
{
    memnode_t *next, *freelist = NULL;
    uint32_t idx, max_idx;
    uint32_t max_free_index, current_free_index;


    max_idx = allocator->max_index;
    max_free_index = allocator->max_free_index;
    current_free_index = allocator->current_free_index;

    /* Walk the list of submitted nodes and free them one by one,
     * shoving them in the right 'size' buckets as we go.
     */
    do {
        next = node->next;
        idx = node->index;

        if (max_free_index != ALLOCATOR_MAX_FREE_UNLIMITED
            && idx > current_free_index) {
            node->next = freelist;
            freelist = node;
        }
        else if (idx < MAX_INDEX) {
            /* Add the node to the appropiate 'size' bucket.  Adjust
             * the max_index when appropiate.
             */
            if ((node->next = allocator->free[idx]) == NULL
                && idx > max_idx) {
                max_idx = idx;
            }
            allocator->free[idx] = node;
            current_free_index -= idx;
        }
        else {
            /* This node is too large to keep in a specific size bucket,
             * just add it to the sink (at index 0).
             */
            node->next = allocator->free[0];
            allocator->free[0] = node;
            current_free_index -= idx;
        }
    } while ((node = next) != NULL);

    allocator->max_index = max_idx;
    allocator->current_free_index = current_free_index;


    while (freelist != NULL) {
        node = freelist;
        freelist = node->next;
        free(node);
    }
}


/*
 * Structures
 */


/* The ref field in the pool_t struct holds a
 * pointer to the pointer referencing this pool.
 * It is used for parent, child, sibling management.
 * Look at pool_create_ex() and pool_destroy()
 * to see how it is used.
 */
struct pool_t {
    allocator_t      *allocator;
    memnode_t        *active;
    memnode_t        *self; /* The node containing the pool itself */
    char             *self_first_avail;
};

#define SIZEOF_POOL_T       ALIGN_DEFAULT(sizeof(pool_t))


/* Node list management helper macros; list_insert() inserts 'node'
 * before 'point'. */
#define list_insert(node, point) do {           \
    node->ref = point->ref;                     \
    *node->ref = node;                          \
    node->next = point;                         \
    point->ref = &node->next;                   \
} while (0)

/* list_remove() removes 'node' from its list. */
#define list_remove(node) do {                  \
    *node->ref = node->next;                    \
    node->next->ref = node->ref;                \
} while (0)

/*
 * Memory allocation
 */

static void *
pool_malloc(size_t size, UNUSED const char * file, UNUSED int line,
	    pool_t * pool)
{
    memnode_t *active, *node;
    void *mem;
    size_t free_index;

    size = ALIGN_DEFAULT(size);
    active = pool->active;

    /* If the active node has enough bytes left, use it. */
    if (size < (size_t)(active->endp - active->first_avail)) {
        mem = active->first_avail;
        active->first_avail += size;

        return mem;
    }

    node = active->next;
    if (size < (size_t)(node->endp - node->first_avail)) {
        list_remove(node);
    }
    else {
        if ((node = allocator_alloc(pool->allocator, size)) == NULL) {
            return NULL;
        }
    }

    node->free_index = 0;

    mem = node->first_avail;
    node->first_avail += size;

    list_insert(node, active);

    pool->active = node;

    free_index = (ALIGN(active->endp - active->first_avail + 1,
                            BOUNDARY_SIZE) - BOUNDARY_SIZE) >> BOUNDARY_INDEX;

    active->free_index = (uint32_t)free_index;
    node = active->next;
    if (free_index >= node->free_index)
        return mem;

    do {
        node = node->next;
    }
    while (free_index < node->free_index);

    list_remove(active);
    list_insert(active, node);

    return mem;
}

static void *
pool_calloc(size_t nmemb, size_t size, UNUSED const char * file,
	    UNUSED int line, pool_t * pool)
{
    void *mem;

    size *= nmemb;
    size = ALIGN_DEFAULT(size);
    if ((mem = pool_malloc(size, file, line, pool)) != NULL) {
        memset(mem, 0, size);
    }

    return mem;
}

static void
pool_free(UNUSED void * p, UNUSED const char * file, UNUSED int line,
	  UNUSED pool_t * pool)
{
}


/*
 * Pool creation/destruction
 */

void
pool_clear(pool_t *pool)
{
    memnode_t *active;

    /* Find the node attached to the pool structure, reset it, make
     * it the active node and free the rest of the nodes.
     */
    active = pool->active = pool->self;
    active->first_avail = pool->self_first_avail;

    if (active->next == active)
        return;

    *active->ref = NULL;
    allocator_free(pool->allocator, active->next);
    active->next = active;
    active->ref = &active->next;
}

void
pool_destroy(pool_t *pool)
{
    memnode_t *active;
    allocator_t *allocator;

    /* Find the block attached to the pool structure.  Save a copy of the
     * allocator pointer, because the pool struct soon will be no more.
     */
    allocator = pool->allocator;
    active = pool->self;
    *active->ref = NULL;


    /* Free all the nodes in the pool (including the node holding the
     * pool struct), by giving them back to the allocator.
     */
    allocator_free(allocator, active);
    
    allocator_destroy(allocator);
}

pool_t *
pool_create()
{
    pool_t *pool;
    memnode_t *node;
    allocator_t *allocator;

    allocator = allocator_create();

    if ((node = allocator_alloc(allocator,
                                MIN_ALLOC - MEMNODE_T_SIZE)) == NULL) {
        return NULL;
    }

    node->next = node;
    node->ref = &node->next;

    pool = (pool_t *)node->first_avail;
    node->first_avail = pool->self_first_avail = (char *)pool + SIZEOF_POOL_T;

    pool->allocator = allocator;
    pool->active = pool->self = node;

    return pool;
}


void
pool_alc_init(pool_t * pool, alc_t * alc)
{
    alc->malloc = (alc_malloc_fn) pool_malloc;
    alc->calloc = (alc_calloc_fn) pool_calloc;
    alc->free = (alc_free_fn) pool_free;
    alc->data = pool;
}

#if 0

#define ALLOCS 600
#define DO_FREES

int
main(int argc, char **argv)
{
    pool_t *m;
    alc_t alc;
    int i;
    void *p[ALLOCS];
    
    struct timeval t1, t2;
    uint64_t d1, d2;
    double imp;
    
    m = pool_create();
    
    pool_alc_init(m, &alc);
    
    gettimeofday(&t1, NULL);
    
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 4);
    }
#ifdef DO_FREES
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }
#endif
    pool_clear(m);
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 2);
    }
#ifdef DO_FREES
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }
#endif
    pool_clear(m);
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 4);
    }
#ifdef DO_FREES
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }
#endif
    pool_clear(m);

    gettimeofday(&t2, NULL);

    d1 = TIMEVAL2TS(&t2) - TIMEVAL2TS(&t1);
    printf("pool: %lu:%lu\n", TS2SEC(d1), TS2USEC(d1));

    gettimeofday(&t1, NULL);
    
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 2);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }

    gettimeofday(&t2, NULL);

    d2 = TIMEVAL2TS(&t2) - TIMEVAL2TS(&t1);
    printf("stdlib: %lu:%lu\n", TS2SEC(d2), TS2USEC(d2));
    
    imp = (double) d1 / (double) d2;
    
    if (imp < 1)
	printf("improvement: %%%.0f\n", imp * 100);
    else
	printf("worsening: %%%.0f\n", imp * 100);
    
    return 0;
}

#endif
