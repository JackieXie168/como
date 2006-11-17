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

#include "como.h"
#include "comopriv.h"
#include "storage.h"
#include "serialize.h"
#include "shobj.h"

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

    /*switch (*type) {
    case PRIV_ISUPERVISOR:
	return ((mdl_isupervisor_t *) h->priv)->mdl_config;
    case PRIV_ICAPTURE:
	return ((mdl_icapture_t *) h->priv)->mdl_config;
    case PRIV_IEXPORT:
	return ((mdl_iexport_t *) h->priv)->mdl_config;
    case PRIV_IQUERY:
	return ((mdl_iquery_t *) h->priv)->mdl_config;
    }

    error("Can't access config serialization info\n");
    return NULL;*/
}


/* serialization/deserialization of mdl_t */
void
mdl_serialize(uint8_t ** sbuf, const mdl_t * h)
{
    serializable_t *config;
    
    config = mdl_get_config_ser(h);
    
    serialize_timestamp_t(sbuf, h->flush_ivl);
    serialize_string(sbuf, h->name);
    serialize_string(sbuf, h->description);
    serialize_string(sbuf, h->filter);
    serialize_string(sbuf, h->mdlname);
    serialize_uint64_t(sbuf, h->streamsize);
    config->serialize(sbuf, h->config);
}

size_t
mdl_sersize(const mdl_t * src)
{
    size_t sz;
    serializable_t *config;
    
    config = mdl_get_config_ser(src);

    sz = sizeof(src->flush_ivl) +
	 sersize_string(src->name) +
	 sersize_string(src->description) +
	 sersize_string(src->filter) +
	 sersize_string(src->mdlname) +
         sersize_uint64_t(src->streamsize) +
	 config->sersize(src->config);

    return sz;
}

void
mdl_deserialize(uint8_t ** sbuf, mdl_t ** h_out, alc_t * alc,
		mdl_priv_t priv)
{
    mdl_t *h;
    serializable_t *config;
    
    h = alc_new0(alc, mdl_t);
    
    deserialize_timestamp_t(sbuf, &h->flush_ivl);
    deserialize_string(sbuf, &h->name, alc);
    deserialize_string(sbuf, &h->description, alc);
    deserialize_string(sbuf, &h->filter, alc);
    deserialize_string(sbuf, &h->mdlname, alc);
    deserialize_uint64_t(sbuf, &h->streamsize);

    if (mdl_load(h, priv) < 0) {
	alc_free(alc, h);
	*h_out = NULL;
	return;
    }

    config = mdl_get_config_ser(h);
    config->deserialize(sbuf, &h->config, alc);
    
    *h_out = h;
}


mdl_icapture_t *
mdl_get_icapture(mdl_t * h)
{
    return h->priv->proc.ca;
}


mdl_isupervisor_t *
mdl_get_isupervisor(mdl_t * h)
{
    return h->priv->proc.su;
}


mdl_iexport_t *
mdl_get_iexport(mdl_t * h)
{
    return h->priv->proc.ex;
}


mdl_iquery_t *
mdl_get_iquery(mdl_t * h)
{
    return h->priv->proc.qu;
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
        case 0: out->serialize = (serialize_fn *) sym; break;
        case 1: out->deserialize = (deserialize_fn *) sym; break;
        case 2: out->sersize = (sersize_fn *) sym; break;
        }
    }

    return 0;
}

int
mdl_load(mdl_t * h, mdl_priv_t priv)
{
    mdl_ibase_t *ib;
    char *filename;
    const char *libdir;
    int ret;

    ib = como_new0(mdl_ibase_t);
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
    filename = shobj_build_path(libdir, h->mdlname);
    ib->shobj = shobj_open(filename);
    if (ib->shobj == NULL) {
	free(ib);
	return -1;
    }


    ret = mdl_load_serializable(&ib->mdl_config, ib->shobj, "config_type");
    ret += mdl_load_serializable(&ib->mdl_tuple, ib->shobj, "tuple_type");
    ret += mdl_load_serializable(&ib->mdl_record, ib->shobj, "record_type");
    if (ret < 0) { /* any at least one of the above failed */
        warn("module %s misses functions to handle its struct types");
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
        tuples_init(&ib->proc.ca->tuples);
	break;
    case PRIV_IEXPORT:
	ib->proc.ex = como_new0(mdl_iexport_t);
	ib->proc.ex->init = shobj_symbol(ib->shobj, "ex_init", TRUE);
	ib->proc.ex->export = shobj_symbol(ib->shobj, "export", TRUE);
	break;
    case PRIV_IQUERY:
	ib->proc.qu = como_new0(mdl_iquery_t);
	break;
    }
    
    h->priv = ib;

    return 0;
}


void *
mdl__alloc_config(mdl_t * h, size_t sz)
{
    /* allocate the config state of size sz and keep track of it */
    alc_t *alc = &h->priv->alc;
    return alc_calloc(alc, 1, sz);
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


#if 0


int
mdl_capture_batch(mdl_t * h, batch_t * batch, char * fltmap, onflush_fn onflush)
{
    pkt_t **pktptr;
    int i, c, l;

    mdl_icapture_t *ic;
    
    ic = mdl_get_icapture(h);

    for (c = 0, pktptr = batch->pkts0, l = MIN(batch->pkts0_len, batch->count);
	 c < batch->count;
	 pktptr = batch->pkts1, l = batch->pkts1_len)
    {
	for (i = 0; i < l; i++, pktptr++, c++) {
	    pkt_t *pkt = *pktptr;
	    int res;
	    
	    /* check whether the state has to be flushed */
	    if (ic->ivl_state && pkt->ts >= ic->ivl_end) {
		onflush(h, ic->records);
		/* TODO: free all memory allocated in the interval except records */
		ic->ivl_state = NULL;
	    }
	    if (ic->ivl_state == NULL) {
		/* initialize ivl_start and ivl_end */
		ic->ivl_start = pkt->ts - (pkt->ts % h->flush_ivl);
		ic->ivl_end = ic->ivl_start + h->flush_ivl;
		
		/* call flush() to initialize ivl_state */
		ic->ivl_state = ic->flush(h, ic->ivl_start);
	    }
	    
	    if (*fltmap == 0)
		continue;	/* no interest in this packet */

	    res = ic->capture(h, pkt, ic->ivl_state);
	    
	    fltmap++;
	}
    }
}
#endif

/* EXPORT */

uint8_t *
mdl_store_rec(mdl_t * h, size_t sz, timestamp_t ts)
{
    mdl_iexport_t *ie;
    strec_t *r;
    
    ie = mdl_get_iexport(h);
    
    sz += sizeof(timestamp_t);
    ie->cs_cisz = sz + sizeof(size_t);
    
    r = (strec_t *) csmap(ie->cs_writer, ie->woff, (ssize_t *) &ie->cs_cisz);
    if (r == NULL)
	error("fail csmap for module %s", h->name);

    if ((ssize_t) ie->cs_cisz == -1) {
	warn("Can't write to disk for module %s\n", h->name);
	return NULL;
    }

    r->size = sz;
    r->ts = ts;
    
    return r->data; /* pointer to data */
}


void
mdl_store_commit(mdl_t * h)
{
    mdl_iexport_t *ie;
    
    ie = mdl_get_iexport(h);
    
    assert(ie->cs_cisz > 0 );
    ie->woff += ie->cs_cisz;
    cscommit(ie->cs_writer, ie->woff);
    ie->cs_cisz = 0;
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

