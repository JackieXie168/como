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
 * $Id: modules.c,v 1.9 2006/05/07 22:46:19 iannak1 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>	/* strdup, strerror */
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>	/* dlopen, dlclose, etc. */

#include "como.h"
#include "comopriv.h"


/*
 * -- load_object
 *
 * dynamically links a library. it returns a pointer to the 
 * symbol looked for and it stores in "handle" the handle 
 * for later unlinking the library.
 *
 */
static void *
load_object(char * base_name, char * symbol, void ** handle)
{
    void * sym;

    *handle = dlopen(base_name, RTLD_NOW);
    if (*handle == NULL) {
        logmsg(LOGWARN, "dlopen(%s, RTLD_NOW) error [%s]\n",
                base_name, dlerror());
        return NULL;
    }
    sym = dlsym(*handle, symbol);
    if (sym == NULL) {
        logmsg(LOGWARN, "module %s missing '%s' (%s)\n",
                base_name, symbol, dlerror());
        dlclose(*handle);
        return NULL;
    }

    return (void *) sym;
}


/*
 * -- activate_module
 *
 * load the callbacks of a module and makes a set of 
 * consistency checks, i.e. make sure that all mandatory 
 * combinations of callbacks are actually there. 
 * 
 * returns 0 in case of failure, 1 in case of success. 
 * 
 */
int
activate_module(module_t * mdl, char * libdir)
{
    callbacks_t * cb;
    char * filename;
    void * handle;

    /* load the shared object */
    if (libdir == NULL || mdl->source[0] == '/')
        filename = strdup(mdl->source);
    else
        asprintf(&filename, "%s/%s", libdir, mdl->source);
    cb = load_object(filename, "callbacks", &handle);

    /* perform some checks on the callbacks */

    if (cb == NULL) {
        logmsg(LOGWARN, "cannot load %s: %s\n", filename, strerror(errno));
        free(filename);
        return 1;
    }
    free(filename);

    /* update(), store() and load() should definitely be there */
    if (cb->update == NULL) {
	logmsg(LOGWARN, "module %s misses update()\n", mdl->name);
	dlclose(handle);
        return 1;
    }

    if (cb->store == NULL) {
	logmsg(LOGWARN, "module %s misses store()\n", mdl->name);
	dlclose(handle);
        return 1;
    }

    if (cb->load == NULL) {
	logmsg(LOGWARN, "module %s misses load()\n", mdl->name);
	dlclose(handle);
        return 1;
    }

    /* 
     * either both or none of action() and export() are required 
     */
    if (cb->export == NULL) {
	/*
	 * no export(), then we we don't want
	 * action(), ematch() and compare().
	 */
	if (cb->action || cb->ematch || cb->compare ) {
	    logmsg(LOGWARN, "module %s has %s%s%s without export()\n",
			mdl->name,
			cb->action ? "action() " : "",
			cb->ematch ? "ematch() " : "",
			cb->compare ? "compare() " : ""
		);
	    dlclose(handle);
            return 1;
        }
    } else {
	if (cb->action == NULL) { /* export() requires action() too */
	    logmsg(LOGWARN, "module %s has export() w/out action()\n", 
		mdl->name);
	    dlclose(handle);
            return 1;
        }
    }

    if (cb->formats == NULL) 
	asprintf(&cb->formats, "plain"); 

    mdl->inprocess_map = memmap_new(allocator_safe(), 32,
				    POLICY_HOLD_IN_USE_BLOCKS);
    allocator_init_module(mdl);
    
    /* store the callbacks */
    mdl->callbacks = *cb;
    mdl->cb_handle = handle;
    mdl->status = MDL_ACTIVE; 
    return 0;
}


/*
 * -- check_module 
 * 
 * makes sure the values in the configuration of the module are 
 * correct and in the valid ranges. 
 * 
 */
int
check_module(como_t * m, module_t *mdl)
{
    if (m->basedir && mdl->output[0] != '/') { /* prepend basedir */
	char *p = mdl->output;
	asprintf(&mdl->output, "%s/%s", m->basedir, p);
	free(p);
    }

    if (mdl->ex_hashsize == 0) { /* hash size */
	logmsg(LOGWARN, "config: module %s needs a hash size\n", mdl->name);
        return 1;
    }

    if (mdl->streamsize < 2 * m->maxfilesize) { /* filesize */
	mdl->streamsize = 2*m->maxfilesize; 
	logmsg(LOGWARN, 
	    "module %s streamsize too small. set to %dMB\n", 
	    mdl->name, mdl->streamsize/(1024*1024)); 
    } 

    return 0;
}


/* 
 * -- new_module 
 * 
 * allocates a new module data structure and initializes it 
 * with default values. returns the pointer to the new module. 
 *
 */
module_t *
new_module(como_t * m, char *name, int node, int idx)
{
    module_t * mdl; 
    int i; 

    assert (idx < m->module_max); 

    /* check if this module exists already */
    for (i = 0; i <= m->module_last; i++) { 
	mdl = &m->modules[i]; 

	if (mdl->status == MDL_UNUSED) 
	    continue; 

	if (!strcmp(mdl->name, name) && mdl->node == node)
	    panicx("module name '%s' (node %d) already present\n", name, node);
    } 

    /* find an available slot unless the user request one */
    if (idx == -1) { 
	for (i = 0; i < m->module_max; i++) { 
	    if (m->modules[i].status == MDL_UNUSED) { 
		idx = i; 
		break; 
	    } 
	} 
	if (idx == -1)
	    panicx("too many modules (%d), cannot create %s", 
		m->module_max, name);
    } 
	
    m->module_used++;
    if (idx > m->module_last) 
	m->module_last = idx; 

    /* allocate new module */
    mdl = &m->modules[idx]; 
    bzero(mdl, sizeof(module_t));
    mdl->name = strdup(name);
    mdl->index = idx;
    mdl->node = node;
    mdl->description = NULL; 
    mdl->status = MDL_LOADING; 

    /* set some default values */
    mdl->streamsize = DEFAULT_STREAMSIZE; 
    mdl->ex_hashsize = mdl->ca_hashsize = 1; 
    mdl->args = NULL;
    mdl->priority = 5;
    mdl->filter_str = strdup("all");
    mdl->filter_tree = NULL;
    mdl->output = strdup(mdl->name); /* TODO: canonized name */
    asprintf(&mdl->source, "%s.so", mdl->name);
    
    mdl->running = RUNNING_NORMAL;

    return mdl;
}


/* 
 * -- copy_module
 * 
 * create a new module that is an exact copy of the module
 * pointed by "src". this is called to replicate modules for multiple
 * virtual nodes as well as when a reconfiguration takes place. 
 *
 */
module_t *
copy_module(como_t * m, module_t * src, int node, int idx, char **extra_args) 
{
    module_t * mdl; 
    char * nm; 
    int assigned; 

    mdl = new_module(m, src->name, node, idx); 
    nm = mdl->name; 
    assigned = mdl->index; 
    *mdl = *src; 		/* XXX maybe there is a better way */
    mdl->node = node;
    mdl->index = assigned; 
    mdl->name = nm; 
    mdl->description = safe_strdup(src->description);
    mdl->filter_str = safe_strdup(src->filter_str);
    mdl->output = safe_strdup(src->output);
    mdl->source = safe_strdup(src->source);
    mdl->ca_hashtable = NULL;
    mdl->ex_hashtable = NULL;
 
    mdl->args = NULL; 
    if (src->args || extra_args) {
	int i = 0, i2 = 0, j; 

	if (src->args)
	    for (; src->args[i]; i++)
		; 

	if (extra_args)
	    for (; extra_args[i2]; i2++)
		;

	mdl->args = safe_calloc(i + i2 + 1, sizeof(char *)); 

	for (j = 0; j < i; j++)
	    mdl->args[j] = safe_strdup(src->args[j]); 

	for (j = 0; j < i2; j++)
	    mdl->args[i + j] = safe_strdup(extra_args[j]); 

	mdl->args[i + i2] = NULL;
    } 

    return mdl; 
}


/*
 * -- clean_module
 *
 * free all process memory allocated internally to
 * a module.
 *
 */
void
clean_module(module_t * mdl)
{
    char *arg;
    int i;

    free(mdl->name);
    if (mdl->description != NULL)
        free(mdl->description);
    free(mdl->output);
    free(mdl->source);

    if (mdl->args) {
        i = 0;
        arg = mdl->args[i];
        while (arg != NULL) {
            free(arg);
            i++;
            arg = mdl->args[i];
        }
        free(mdl->args);
    }

}

         
/*
 * -- remove_module 
 *
 * free all memory allocated for this module, and
 * unload the shared object and inform all processes
 * of this decision.
 *
 */
void
remove_module(como_t * m, module_t *mdl)
{
    /* free in process memory */
    clean_module(mdl);

    /* unlink the shared library */ 
    if (mdl->cb_handle) {
        dlclose(mdl->cb_handle);
    }

    /* zero out all the rest and mark the module as free */
    bzero(mdl, sizeof(module_t));
    mdl->status = MDL_UNUSED;
    
    /* update the map */ 
    m->module_used--; 
    if (mdl == &m->modules[m->module_last]) { 
	int i; 

	/* 
	 * this was the last module. find out who is 
	 * the new last module. 
	 */
        for (i = m->module_last; i >= 0; i--) 
            if (m->modules[i].status != MDL_UNUSED) 
		break; 

	m->module_last = i; 
    }
    
    /* XXX we don't free the shared memory. this should be done 
     *     in another function (destroy_module). remove_module 
     *     is just in charge of cleaning all structures in process 
     *     memory.	 
     */
}


/* 
 * -- add_string()
 * 
 * helper function to serialize strings
 * 
 */
static __inline__ int 
add_string(char ** dst, char * src, int wh, char * buf)
{
    if (src) {
	*dst = (char *) wh; 
	bcopy(src, buf + (int) *dst, strlen(src) + 1); 
	wh += strlen(src) + 1;
    } else { 
	*dst = 0;
    } 

    return wh; 
}

/* 
 * -- pack_module
 * 
 * this function takes a module as input and creates a 
 * self-contained data structure that allows for this 
 * module to be exchanged between processes. this means 
 * that all pointers in the module are rewritten so to 
 * point somewhere in the "packed" data structure. In 
 * order to unpack the module one has to use the 
 * unpack_module() function. 
 * 
 * it returns a pointer to a region of memory allocated
 * in this function and that needs to be freed by the 
 * caller. it also returns the size of the memory returned. 
 * 
 */
char *
pack_module(module_t * mdl, int * len)
{
    module_t * x; 
    char * buf; 
    int wh; 
    int sz;
    int i, k;

    /* check how big a buffer we need */
    sz = sizeof(module_t); 
    sz += mdl->name? strlen(mdl->name) + 1: 0; 
    sz += mdl->description? strlen(mdl->description) + 1 : 0; 
    sz += mdl->filter_str? strlen(mdl->filter_str) + 1: 0; 
    sz += mdl->output? strlen(mdl->output) + 1 : 0; 
    sz += mdl->source? strlen(mdl->source) + 1 : 0; 
    
    for (i = 0, k = 0; mdl->args && mdl->args[i]; i++, k++)
	sz += strlen(mdl->args[i]) + 1; 

    if (k > 0) 
	sz += (k + 1) * sizeof(char *); 

    buf = safe_malloc(sz); 
    bzero(buf, sz); 

    x = (module_t *) buf; 
    *x = *mdl; 
    wh = sizeof(module_t); 
    wh = add_string(&x->name, mdl->name, wh, buf); 
    wh = add_string(&x->description, mdl->description, wh, buf); 
    wh = add_string(&x->filter_str, mdl->filter_str, wh, buf); 
    wh = add_string(&x->output, mdl->output, wh, buf); 
    wh = add_string(&x->source, mdl->source, wh, buf); 

    /* remove the callbacks */
    bzero(&x->callbacks, sizeof(x->callbacks));
    x->cb_handle = NULL;

    x->args = NULL; 
    if (mdl->args && mdl->args[0]) {
	char * p; 

	x->args = (char **) wh; 

	/* make the space for the array of pointers */
	wh += (k + 1) * sizeof(char *); 

	for (i = 0; mdl->args[i]; i++) {
	    p = buf + (int) x->args + i * sizeof(char *); 
	    wh = add_string((char **) p, mdl->args[i], wh, buf); 
	} 

	p = buf + (int) x->args + k * sizeof(char *); 
	*p = 0; 
    }

    /* we should have used the entire buf */
    assert(wh == sz); 
    *len = sz; 
    return buf; 
}


/* 
 * -- unpack_module
 * 
 * takes a packed module and expands it in the module_t 
 * data structure provided as input. it returns 0 in case 
 * of success and -1 in case of failures. this function will
 * allocate additional memory as needed. 
 * 
 */
int
unpack_module(char * p, __unused size_t len, module_t * mdl)
{
    module_t * x = (module_t *) p; 

    /* copy all variables */
    *mdl = *x; 

    /* copy all strings */
    mdl->name = x->name? safe_strdup(p + (int) x->name) : NULL; 
    mdl->description = x->description? 
		       safe_strdup(p + (int) x->description) : NULL; 
    mdl->filter_str = x->filter_str? 
		      safe_strdup(p + (int) x->filter_str) : NULL; 
    mdl->output = x->output? safe_strdup(p + (int) x->output) : NULL; 
    mdl->source = x->source? safe_strdup(p + (int) x->source) : NULL; 

    /* copy all arguments */
    mdl->args = NULL;
    if (x->args) { 
	char * t; 
	int k; 

	/* 
	 * the arguments are organized first as an array of pointers.
    	 * this pointers are just integer to let us know where in the 
 	 * packed array the actual strings are. 
	 */

	/* first count the number of arguments */
	t = p + (int) x->args; 
	for (k = 0; *(int*)t; k++, t += sizeof(char *))
	    ; 

	if (k > 0) { 
	    int j; 

	    /* prepare the array of pointers to char */
	    mdl->args = safe_calloc(k + 1, sizeof(char *)); 
	    
	    /* 
	     * fetch the strings where they are in the packed array. 
	     * we need two levels of indirection. first find where the 
	     * location of the strings is stored in the array (written in 
	     * x->args). then, read the strings themselves. 
	     */
	    t = p + (int) x->args; 
	    for (j = 0; j < k; j++) { 
		mdl->args[j] = safe_strdup(p + *(int *)t); 
		t += sizeof(char *);
	    }
	    mdl->args[j] = NULL;
	} 
    } 

    return 0;
}


/* 
 * -- init_module
 * 
 * allocates memory for running the module and calls the 
 * init() callback. this function is used only by SUPERVISOR. 
 *
 */
int 
init_module(module_t * mdl)
{
    if (mdl->callbacks.init != NULL) {
	/*
	 * create a memory list for this module to
	 * keep track of memory allocated inside init().
	 */
	mdl->shared_map = memmap_new(allocator_shared(), 32,
				     POLICY_HOLD_IN_USE_BLOCKS);
	
	mdl->flush_ivl = mdl->callbacks.init(mdl, mdl->args);
	if (mdl->flush_ivl == 0)
	    panicx("could not initialize %s\n", mdl->name);
	
	/*
	 * save the initial map in init_map and set shared map to NULL
	 */
	mdl->init_map = mdl->shared_map;
	mdl->shared_map = NULL;
    } else {
	mdl->flush_ivl = DEFAULT_CAPTURE_IVL;
    }

    return 0; 
}


/* 
 * -- match_module
 * 
 * return 1 if the two modules are the same (according to 
 * name and node id). return 0 otherwise. 
 *
 */
int  
match_module(module_t * a, module_t * b) 
{ 
    return (!strcmp(a->name, b->name) && a->node == b->node); 
}
