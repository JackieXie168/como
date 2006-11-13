/*
 * Copyright (c) 2004-2006, Intel Corporation
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
#define _GNU_SOURCE
#include <stdio.h>

#include <string.h>
#include <dlfcn.h>	/* dlopen, dlclose, etc. */

#include "como.h"

#ifdef WIN32
#  define SHOBJ_SUFFIX		"dll"
#else
#  ifdef __APPLE__
#    define SHOBJ_SUFFIX	"dynlib"
#  else
#    define SHOBJ_SUFFIX	"so"
#  endif
#endif

struct shobj {
    char *	name;
    void *	handle;
};

char *
shobj_build_path(const char * directory, const char * name)
{
    char *res;
    asprintf(&res, "%s/%s.%s", directory, name, SHOBJ_SUFFIX);
    return res;
}


shobj_t *
shobj_open(const char * filename)
{
    shobj_t *shobj;
    void *handle;
    
    handle = dlopen(filename, RTLD_NOW);
    if (handle == NULL) {
	warn("Can't open shared object %s: %s\n", filename, dlerror());
	return NULL;
    }
    
    shobj = como_new(shobj_t);
    shobj->name = como_strdup(como_basename(filename));
    shobj->handle = handle;
    
    return shobj;
}


void *
shobj_symbol(shobj_t * shobj, const char * symbol)
{
    void *sym;
    sym = dlsym(shobj->handle, symbol);
    if (sym == NULL) {
        warn("Can't find symbol %s in shared object %s: %s\n",
	     symbol, shobj->name, dlerror());
    }
    return sym;
}


int
shobj_close(shobj_t * shobj)
{
    int res;
    res = dlclose(shobj->handle);
    free(shobj->name);
    free(shobj);
    return res;
}
