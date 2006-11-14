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
mdl_get_config_ser(const mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;

    switch (*type) {
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
    return NULL;
}


/* serialization/deserialization of mdl_t */
void
mdl_serialize(uint8_t ** sbuf, const mdl_t * h)
{
    serializable_t *config;
    
    config = mdl_get_config_ser(h);
    
    serialize_timestamp_t(sbuf, h->flush_ivl);
    serialize_string(sbuf, h->name);
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
	 config->sersize(src->config);

    return sz;
}

void
mdl_deserialize(uint8_t ** sbuf, mdl_t ** h_out, alc_t * alc)
{
    mdl_t *h;
    serializable_t *config;
    
    h = alc_new(alc, mdl_t);
    
    config = mdl_get_config_ser(h);
    
    deserialize_timestamp_t(sbuf, &h->flush_ivl);
    deserialize_string(sbuf, &h->name, alc);
    deserialize_string(sbuf, &h->filter, alc);
    deserialize_string(sbuf, &h->description, alc);
    config->deserialize(sbuf, &h->config, alc);
    
    *h_out = h;
}


mdl_icapture_t *
mdl_get_icapture(mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;
    if (type == NULL || *type != PRIV_ICAPTURE)
	error("Can't access ICapture for module `%s`\n", h->name);

    return (mdl_icapture_t *) h->priv;
}


mdl_isupervisor_t *
mdl_get_isupervisor(mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;
    if (type == NULL || *type != PRIV_ISUPERVISOR)
	error("Can't access ISupervisor for module `%s`\n", h->name);

    return (mdl_isupervisor_t *) h->priv;
}


mdl_iexport_t *
mdl_get_iexport(mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;
    if (type == NULL || *type != PRIV_IEXPORT)
	error("Can't access IExport for module `%s`\n", h->name);

    return (mdl_iexport_t *) h->priv;
}


mdl_iquery_t *
mdl_get_iquery(mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;
    if (type == NULL || *type != PRIV_IQUERY)
	error("Can't access IQuery for module `%s`\n", h->name);

    return (mdl_iquery_t *) h->priv;
}

int
mdl_load(mdl_t * h, mdl_priv_t priv)
{
    mdl_ibase_t *ib;
    char *filename;
    const char *libdir;
    
    switch (priv) {
    case PRIV_ISUPERVISOR:
	ib = (mdl_ibase_t *) como_new0(mdl_isupervisor_t);
	break;
    case PRIV_ICAPTURE:
	ib = (mdl_ibase_t *) como_new0(mdl_icapture_t);
	break;
    case PRIV_IEXPORT:
	ib = (mdl_ibase_t *) como_new0(mdl_iexport_t);
	break;
    case PRIV_IQUERY:
	ib = (mdl_ibase_t *) como_new0(mdl_iquery_t);
	break;
    }
    
    ib->type = priv;
    
    libdir = como_env_libdir();
    filename = shobj_build_path(libdir, h->mdlname);
    ib->shobj = shobj_open(filename);
    if (ib->shobj == NULL) {
	free(ib);
	return -1;
    }
    
    return 0;
}

#if 0
void *
mdl__alloc_config(mdl_t * h, size_t sz, serializable_t * ser)
{
    /* allocate the config state of size sz and keep track of it */
    
}
#endif

/* CAPTURE */


void *
mdl__alloc_rec(mdl_t * h, size_t sz)
{
    /* allocate the record of size sz and keep track of it */
    mdl_icapture_t *ic;
    
    ic = mdl_get_icapture(h);
    return alc_malloc(&ic->alc, sz);
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
    
#if 0    
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
#endif
    return 0; 
}

