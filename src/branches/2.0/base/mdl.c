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

typedef uint8_t * (*serialize_fn)   (uint8_t * sbuf, const void * data);
typedef uint8_t * (*deserialize_fn) (uint8_t * sbuf, void ** data_out, allocator_t * alc);
typedef size_t (*expose_len_fn)     (const void * src);

typedef struct serializable {
    serialize_fn	serialize;
    deserialize_fn	deserialize;
    expose_len_fn	expose_len;
} serializable_t;


typedef struct strec strec_t;

struct strec {
    size_t	size;
    timestamp_t	ts;
    uint8_t	data[0];
};

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


#define WARN_UNUSED_RESULT __attribute((warn_unused_result))

strec_t * strec_put_uint64(strec_t * r, uint64_t val) WARN_UNUSED_RESULT;
strec_t * strec_get_uint64(strec_t * r, uint64_t *val) WARN_UNUSED_RESULT;

#define timestamp_serialize(sbuf, val) \
*((timestamp_t *) sbuf) = (val), ((timestamp_t *) sbuf) + 1

#define timestamp_deserialize(sbuf, val) \
*(val) = *((timestamp_t *) sbuf), ((timestamp_t *) sbuf) + 1

uint8_t *
charptr_serialize(uint8_t * sbuf, const char * val)
{
    size_t sz;
    sz = strlen(val) + 1;
    
    sbuf = uint32_serialize(sbuf, sz);
    memcpy(sbuf, val, sz);
    return sbuf + sz;
}

uint8_t *
charptr_deserialize(uint8_t * sbuf, char ** val_out, allocator_t * alc)
{
    size_t sz;
    char *val;
    
    sbuf = uint32_deserialize(sbuf, &sz);
    val = alc_alloc(alc, sz);
    memcpy(val, sbuf, sz);
    return sbuf + sz;
}

size_t
charptr_expose_len(const char * val)
{
    return strlen(val) + 1;
}

typedef struct mdl mdl_t;


struct mdl {
    /* public fields */
    timestamp_t	flush_ivl;
    char *	name;
    char *	description;
    char *	filter;
    void *	config;
    /* private state */
    void *	priv;
};


/* serialization/deserialization of mdl_t */
uint8_t *
mdl_serialize(uint8_t * sbuf, const mdl_t * h)
{
    serializable_t *config;
    
    config = mdl_get_config_ser(h);
    
    sbuf = timestamp_serialize(sbuf, h->flush_ivl);
    sbuf = charptr_serialize(sbuf, h->name);
    sbuf = config->serialize(sbuf, h->config);
    
    return sbuf;
}

size_t
mdl_expose_len(const mdl_t * src)
{
    size_t sz;
    serializable_t *config;
    
    config = mdl_get_config_ser(h);

    sz = sizeof(src->flush_ivl) +
	 charptr_expose_len(src->name) +
	 charptr_expose_len(src->description) +
	 charptr_expose_len(src->filter) +
	 config->expose_len(src->config);

    return sz;
}

uint8_t *
mdl_deserialize(uint8_t * sbuf, mdl_t ** h_out, allocator_t * alc)
{
    mdl_t *h;
    serializable_t *config;
    
    h = alc_new(alc, mdl_t);
    
    config = mdl_get_config_ser(h);
    
    sbuf = timestamp_deserialize(sbuf, &h->flush_ivl);
    sbuf = charptr_deserialize(sbuf, &h->name, alc);
    sbuf = charptr_deserialize(sbuf, &h->filter, alc);
    sbuf = charptr_deserialize(sbuf, &h->description, alc);
    sbuf = config->deserialize(sbuf, &h->config, alc);
    
    *h_out = h;
    
    return sbuf;
}

#define mdl_get_config(h, type) \
((const type *) (h->config))

#define mdl_alloc_config(h, type) \
((type *) mdl__alloc_config(h, sizeof(type), &(type ## _serializable))

void *
mdl__alloc_config(mdl_t * h, size_t sz, serializable_t * ser)
{
    /* allocate the config state of size sz and keep track of it */
    
}

/* CAPTURE */
#define mdl_alloc_rec(h, type) \
((type *) mdl__alloc_rec(h, sizeof(type))


void *
mdl__alloc_rec(mdl_t * h, size_t sz)
{
    /* allocate the record of size sz and keep track of it */
    mdl_icapture_t *ic;
    
    ic = mdl_get_icapture(h);
    return alc_malloc(&ic->alc, sz);
}

typedef enum mdl_priv {
    PRIV_ISUPERVISOR,
    PRIV_ICAPTURE,
    PRIV_IEXPORT,
    PRIV_IQUERY
} mdl_priv_t;

typedef void * (*su_init_fn) (mdl_t * h);

typedef void * (*flush_fn)   (mdl_t * h, timestamp_t ts);
typedef int    (*capture_fn) (mdl_t * h, pkt_t * pkt, void * state);




struct mdl_icapture {
    mdl_priv_t	type;
    timestamp_t	ivl_start;
    timestamp_t	ivl_end;
    void *	ivl_state;
    collection_t *records;
    flush_fn	flush;
    capture_fn	capture;

    serializable_t * mdl_config;
    serializable_t * mdl_rec;
    
    alc_t	alc;
    alc_t	shalc;
};

typedef struct mdl_icapture mdl_icapture_t;


struct mdl_isupervisor {
    mdl_priv_t	type;
    su_init_fn	init;

    serializable_t * mdl_config;

};

typedef struct mdl_isupervisor mdl_isupervisor_t;

struct mdl_iexport {
    int		cs_writer;
    size_t	cs_cisz;
    off_t	woff;
};

typedef struct mdl_iexport mdl_iexport_t;

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


serializable_t *
mdl_get_config_ser(const mdl_t * h)
{
    mdl_priv_t * type;
    type = (mdl_priv_t *) h->priv;

    switch (type) {
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
	    
	    if (*which == 0)
		continue;	/* no interest in this packet */

	    res = ic->capture(h, pkt, ic->ivl_state);
	    
	    which++;
	}
    }
}

/* EXPORT */

strec_t *
mdl_store_rec(mdl_t * h, size_t sz, timestamp_t ts)
{
    strec_t *r;
    
    sz += sizeof(timestamp_t);
    h->cs_cisz = sz + sizeof(size_t);
    
    r = (strec_t *) csmap(h->cs_writer, h->woff, (ssize_t *) &h->cs_cisz);
    if (r == NULL)
	error("fail csmap for module %s", mdl->name);

    if ((ssize_t) h->cs_cisz == -1) {
	warn("Can't write to disk for module %s\n", h->name);
	return NULL;
    }

    r->size = sz;
    r->ts = ts;
    
    return (r + 1); /* pointer to data */
}


void
mdl_store_commit(mdl_t * h)
{
    assert(h->cs_cisz > 0 );
    h->woff += h->cs_cisz;
    cscommit(h->cs_writer, h->woff);
    h->cs_cisz = 0;
}

/* QUERY */

strec_t *
mdl_load_rec(mdl_t * h, size_t sz, timestamp_t * ts)
{

}


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
    
    is = mdl_get_isupervisor(h);
    
    mdl->config = is->init(h);
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

