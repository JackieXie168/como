#ifndef MDL_H_
#define MDL_H_

typedef struct mdl mdl_t;

/*
 * Module callbacks
 */


/**
 * su_init_fn() run from supervisor to initialize a module,
 * For the time being, just initialize the private memory for the module,
 * and take arguments from the config file.
 * Returns the config state.
 */
typedef void * (*su_init_fn) (mdl_t * h);


/**
 * flush_fn() run from capture at every flush interval to obtain a clean
 * flush state.
 */
typedef void * (*flush_fn)   (mdl_t * h, timestamp_t ts);

/**
 * captures_fn() run from capture to update *state with the info from *pkt.
 * state points to current flush state.
 * Normally returns COMO_OK to continue to process the packets, can return
 * COMO_FLUSH to force a flush.
 */
typedef int    (*capture_fn) (mdl_t * h, pkt_t * pkt, void * state);


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

#define mdl_get_config(h, type) \
((const type *) (h->config))

#define mdl_alloc_config(h, type) \
((type *) mdl__alloc_config(h, sizeof(type), &(type ## _serializable)))

#define mdl_alloc_tuple(h, type) \
((type *) mdl__alloc_tuple(h, sizeof(type)))


void * mdl__alloc_tuple(mdl_t * h, size_t sz);
char * mdl_alloc_string(mdl_t * h, size_t sz);


uint8_t * mdl_serialize   (uint8_t * sbuf, const mdl_t * h);
size_t    mdl_expose_len  (const mdl_t * src);
uint8_t * mdl_deserialize (uint8_t * sbuf, mdl_t ** h_out, alc_t * alc);


/* Module callbacks */

typedef int    (ca_init_fn)(mdl_t *self);
typedef void * (ca_update_fn)(mdl_t *self, pkt_t *pkt);
typedef void   (ca_flush_fn)(mdl_t *self);

typedef int (ca_tuple_serlen)(mdl_t *self, void *tuple);
typedef int (ca_tuple_serialize)(mdl_t *self, void *tuple, uint8_t *buffer);

struct _ca_module_callbacks {
    ca_init_fn   * init;    /* initialize capture state (optional) */
    ca_update_fn * update;  /* update capture state */
    ca_flush_fn  * flush;   /* flush current available data (optional) */
    ca_tuple_serlen  * serlen;       /* min bufsize to serialize a tuple */
    ca_tuple_serialize  * serialize; /* serialize a tuple */
};

struct _ex_module_callbacks {

};

struct _qu_module_callbacks {

};

#endif /*MDL_H_*/
