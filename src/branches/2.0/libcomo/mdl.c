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
 *
 */

#include <string.h>
#include <assert.h>

#define LOG_DISABLE
#define LOG_DOMAIN "MDL"
#include "como.h"
#include "comopriv.h"
#include "storage.h"

typedef struct strec strec_t;

struct strec {
    size_t	size;
    timestamp_t	ts;
    uint8_t	data[0];
};

/*
strec_t *
strec_put_uint64(strec_t * r, uint64_t val)
{
    *((uint64_t *) r) = val;
    return ((uint64_t *) r) + 1;
}

strec_t *
strec_get_uint64(strec_t * r, uint64_t *val)
{
    *val = *((uint64_t *) r);
    return ((uint64_t *) r) + 1;
}

strec_t * strec_put_uint64(strec_t * r, uint64_t val) WARN_UNUSED_RESULT;
strec_t * strec_get_uint64(strec_t * r, uint64_t *val) WARN_UNUSED_RESULT;

*/

serializable_t *
mdl_get_config_ser(const mdl_t * mdl)
{
    return &mdl->priv->mdl_config;
}


/* serialization/deserialization of mdl_t */
void
mdl_serialize(uint8_t ** sbuf, const mdl_t * mdl)
{
    serializable_t *config;
    
    config = mdl_get_config_ser(mdl);
    
    serialize_timestamp_t(sbuf, mdl->flush_ivl);
    serialize_string(sbuf, mdl->name);
    serialize_string(sbuf, mdl->description);
#ifdef LOADSHED
    serialize_string(sbuf, mdl->shed_method);
    serialize_double(sbuf, mdl->minimum_srate);
#endif
    serialize_string(sbuf, mdl->filter);
    serialize_string(sbuf, mdl->mdlname);
    serialize_uint64_t(sbuf, mdl->streamsize);
    config->serialize(sbuf, mdl->config);
}

size_t
mdl_sersize(const mdl_t * mdl)
{
    size_t sz;
    serializable_t *config;
    
    config = mdl_get_config_ser(mdl);

    sz = sizeof(mdl->flush_ivl) +
	 sersize_string(mdl->name) +
	 sersize_string(mdl->description) +
#ifdef LOADSHED
	 sersize_string(mdl->shed_method) +
	 sersize_double(mdl->minimum_srate) +
#endif
	 sersize_string(mdl->filter) +
	 sersize_string(mdl->mdlname) +
         sersize_uint64_t(mdl->streamsize) +
	 config->sersize(mdl->config);

    return sz;
}

void
mdl_deserialize(uint8_t ** sbuf, mdl_t ** mdl_out, alc_t * alc,
		mdl_priv_t priv)
{
    mdl_t *mdl;
    serializable_t *config;
    
    mdl = alc_new0(alc, mdl_t);
    
    deserialize_timestamp_t(sbuf, &mdl->flush_ivl);
    deserialize_string(sbuf, &mdl->name, alc);
    deserialize_string(sbuf, &mdl->description, alc);
#ifdef LOADSHED
    deserialize_string(sbuf, &mdl->shed_method, alc);
    deserialize_double(sbuf, &mdl->minimum_srate);
#endif
    deserialize_string(sbuf, &mdl->filter, alc);
    deserialize_string(sbuf, &mdl->mdlname, alc);
    deserialize_uint64_t(sbuf, &mdl->streamsize);

    if (mdl_load(mdl, priv) < 0) {
	alc_free(alc, mdl);
	*mdl_out = NULL;
	return;
    }

    config = mdl_get_config_ser(mdl);
    config->deserialize(sbuf, &mdl->config, alc);
    
    *mdl_out = mdl;
}


mdl_icapture_t *
mdl_get_icapture(mdl_t * mdl)
{
    assert(mdl->priv->type == PRIV_ICAPTURE);
    return mdl->priv->proc.ca;
}


mdl_isupervisor_t *
mdl_get_isupervisor(mdl_t * mdl)
{
    assert(mdl->priv->type == PRIV_ISUPERVISOR);
    return mdl->priv->proc.su;
}


mdl_iexport_t *
mdl_get_iexport(mdl_t * mdl)
{
    assert(mdl->priv->type == PRIV_IEXPORT);
    return mdl->priv->proc.ex;
}


mdl_iquery_t *
mdl_get_iquery(mdl_t * mdl)
{
    assert(mdl->priv->type == PRIV_IQUERY);
    return mdl->priv->proc.qu;
}

int
mdl_load_serializable(serializable_t *out, shobj_t *shobj, char *what)
{
    void *sym;
    char *structname;
    int i;

    sym = shobj_symbol(shobj, what, FALSE);
    if (sym == NULL) {
        return -1;
    }
    
    structname = *((char **) sym);

    for (i = 0; i < 3; i++) {
        char *opts[] = { "serialize", "deserialize", "sersize" };
        char *str;
        int ret;

        ret = asprintf(&str, "%s_%s", opts[i], structname);
        if (ret < 0)
            error("out of memory\n");
        sym = shobj_symbol(shobj, str, FALSE);
        if (sym == NULL) {
            free(str);
            return -1;
        }
        free(str);

        switch(i) {
        case 0: out->serialize = (serialize_fn) sym; break;
        case 1: out->deserialize = (deserialize_fn) sym; break;
        case 2: out->sersize = (sersize_fn) sym; break;
        }
    }

    return 0;
}

int
mdl_load(mdl_t * mdl, mdl_priv_t priv)
{
    mdl_ibase_t *ib;
    char *filename;
    const char *libdir;
    int ret;
    ex_impl_t *ex_impl;
    qu_impl_t *qu_impl;

    ib = como_new0(mdl_ibase_t);
    mdl->priv = ib;
    ib->type = priv;
    
    ib->alc = *como_alc();
    
    switch (priv) {
    case PRIV_ISUPERVISOR:
	ib->proc.su = como_new0(mdl_isupervisor_t);
	break;
    case PRIV_ICAPTURE:
	ib->proc.ca = como_new0(mdl_icapture_t);
	break;
    case PRIV_IEXPORT:
	ib->proc.ex = como_new0(mdl_iexport_t);
	break;
    case PRIV_IQUERY:
	ib->proc.qu = como_new0(mdl_iquery_t);
	break;
    }
    
    libdir = como_env_libdir();
    filename = shobj_build_path(libdir, mdl->mdlname);
    ib->shobj = shobj_open(filename);
    if (ib->shobj == NULL) {
	free(ib);
	return -1;
    }


    ret = mdl_load_serializable(&ib->mdl_config, ib->shobj, "config_type");
    ret += mdl_load_serializable(&ib->mdl_tuple, ib->shobj, "tuple_type");
    ret += mdl_load_serializable(&ib->mdl_record, ib->shobj, "record_type");
    if (ret < 0) { /* any at least one of the above failed */
        warn("module `%s' misses functions to handle its struct types",
	     mdl->name);
        return -1;
    }

    switch (priv) {
    case PRIV_ISUPERVISOR:
	ib->proc.su->init = shobj_symbol(ib->shobj, "init", FALSE);
	break;
    case PRIV_ICAPTURE:
	ib->proc.ca->init = shobj_symbol(ib->shobj, "ca_init", TRUE);
	ib->proc.ca->capture = shobj_symbol(ib->shobj, "capture", FALSE);
	ib->proc.ca->flush = shobj_symbol(ib->shobj, "flush", TRUE);
	break;
    case PRIV_IEXPORT:
	ex_impl = shobj_symbol(ib->shobj, "ex_impl", FALSE);
	switch (*ex_impl) {
	case EX_IMPL_NONE:
	break;
	case EX_IMPL_C:
	    ib->proc.ex->init = shobj_symbol(ib->shobj, "ex_init", TRUE);
	    ib->proc.ex->export = shobj_symbol(ib->shobj, "export", FALSE);
	    if (ib->proc.ex->export == NULL &&
                    ib->mdl_tuple.serialize != ib->mdl_record.serialize) {
		warn("module `%s' doesn't implement export but tuple and "
		     "record are not identical.\n", mdl->name);
		return -1;
	    }
	    break;
	case EX_IMPL_MONO:
	    #ifdef MONO_SUPPORT
	    if (proxy_mono_load_export(mdl) == -1)
		return -1;
	    ib->proc.ex->init = proxy_mono_ex_init;
	    ib->proc.ex->export = proxy_mono_export;
	    break;
            #else
	    warn("module `%s' implemented in mono, but mono support not "
			    "complied in\n", mdl->name);
	    return -1;
            #endif
	}
	break;
    case PRIV_IQUERY:
	qu_impl = shobj_symbol(ib->shobj, "qu_impl", FALSE);
	switch (*qu_impl) {
	case QU_IMPL_NONE:
            break;
	case QU_IMPL_C: {
            char **strptr;
	    ib->proc.qu->init = shobj_symbol(ib->shobj, "qu_init", TRUE);
	    ib->proc.qu->finish = shobj_symbol(ib->shobj, "qu_finish", FALSE);
	    ib->proc.qu->print_rec = shobj_symbol(ib->shobj, "print_rec", TRUE);
	    ib->proc.qu->formats = shobj_symbol(ib->shobj, "qu_formats", TRUE);
	    ib->proc.qu->replay = shobj_symbol(ib->shobj, "replay", TRUE);

            strptr = shobj_symbol(ib->shobj, "qu_dflt_fmt", TRUE);
	    ib->proc.qu->dflt_format = strptr ? *strptr : NULL;

	    break;
        }
	case QU_IMPL_MONO: {
	    #ifdef MONO_SUPPORT
            /*MonoProperty *prop;
            gpointer iter = NULL;*/
	    if (proxy_mono_load_query(mdl) == -1)
		return -1;

	    ib->proc.qu->init = proxy_mono_qu_init;
	    ib->proc.qu->finish = proxy_mono_qu_finish;
	    ib->proc.qu->print_rec = proxy_mono_qu_print_rec;

            ib->proc.qu->formats = proxy_mono_get_formats(mdl,
                &ib->proc.qu->dflt_format);
	    break;
            #else
	    warn("module `%s' implemented in mono, but mono support not "
			    "complied in\n", mdl->name);
	    return -1;
            #endif
        }
	}
	break;
    }
    

    return 0;
}


void *
mdl__alloc_config(mdl_t * mdl, size_t sz)
{
    /* allocate the config state of size sz and keep track of it */
    alc_t *alc = &mdl->priv->alc;
    return alc_calloc(alc, 1, sz);
}

alc_t *
mdl_alc(mdl_t * mdl)
{
    return &mdl->priv->alc;
}

/* CAPTURE */

void *
mdl__alloc_tuple(mdl_t * mdl, size_t sz)
{
    mdl_icapture_t *ic;
    struct tuple *t;

    ic = mdl_get_icapture(mdl);
    ic->tuple_count++;

    /* allocate sz + space for the tuple collection-specific fields */
    t = alc_calloc(&ic->tuple_alc, 1, sz + sizeof(struct tuple));

    tuples_insert_tail(&ic->tuples, t);

    return t->data;
}

void
mdl_free_tuple(mdl_t *mdl, void *ptr)
{
    mdl_icapture_t *ic;
    struct tuple *it;

    ic = mdl_get_icapture(mdl);
    ic->tuple_count--;

    it = (struct tuple *) (ptr - sizeof(struct tuple));

    assert(it->data == ptr);
    assert(! tuples_empty(&ic->tuples));

    tuples_remove(&ic->tuples, it);
    
    alc_free(&ic->tuple_alc, it);
}


/* EXPORT */
void
mdl_store_rec(mdl_t * mdl, void * rec)
{
    mdl_iexport_t *ie;
    size_t sz;
    uint8_t *sbuf;
    
    /* the timestamp is the first 64-bit integer of the record */
#if DEBUG
    timestamp_t ts;
    ts = *((timestamp_t *) rec);
    debug("mdl_store_rec: mdl = `%s' ts = %u\n", mdl->name, TS2SEC(ts));
#endif

    ie = mdl_get_iexport(mdl);

    sz = mdl->priv->mdl_record.sersize(rec) + sizeof(size_t);

    sbuf = (uint8_t *) csmap(ie->cs_writer, ie->woff, (ssize_t *) &sz);
    if (sbuf == NULL)
	error("csmap() failed for module `%s'\n", mdl->name);

    if ((ssize_t) sz == -1)
	error("Can't write to disk for module `%s'\n", mdl->name);

    serialize_uint32_t(&sbuf, sz);
    mdl->priv->mdl_record.serialize(&sbuf, rec);

    ie->woff += sz;
    cscommit(ie->cs_writer, ie->woff);
}

mdl_t *
mdl_lookup(array_t *mdls, const char *name)
{
    mdl_t *mdl;
    int i;

    for (i = 0; i < mdls->len; i++) {
        mdl = array_at(mdls, mdl_t *, i);
        if (! strcmp(mdl->name, name))
            return mdl;
    }
    return NULL;
}

void
mdl_printf(mdl_t * mdl, const char * fmt, ...)
{
    mdl_iquery_t *iq = mdl_get_iquery(mdl);
    FILE *f = iq->clientfile;
    va_list ap;

    debug("vfprintf to client\n");
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    debug("vfprintf done\n");

    fflush(f);
}

void
mdl_print(mdl_t *mdl, const char *str)
{
    mdl_printf(mdl, "%s", str);
}

void
mdl_write(mdl_t *mdl, const char *str, size_t len)
{
    mdl_iquery_t *iq = mdl_get_iquery(mdl);
    FILE *f = iq->clientfile;
    fwrite(str, len, 1, f);
    fflush(f);
}


/* QUERY */
#if 0
strec_t *
mdl_load_rec(mdl_t * h, size_t sz, timestamp_t * ts)
{

}
#endif

/* SUPERVISOR */
#if 0
/* 
 * -- mdl_init
 * 
 * allocates memory for running the module and calls the 
 * init() callback. this function is used only by SUPERVISOR. 
 *
 */
int 
mdl_init(mdl_t * mdl)
{
    mdl_isupervisor_t *is;
    
    is = mdl_get_isupervisor(mdl);
    
    mdl->config = is->init(mdl);
    if (mdl->config == NULL) {
	warn("Initialization of module `%s` failed.\n", mdl->name);
    }
    
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
#endif

