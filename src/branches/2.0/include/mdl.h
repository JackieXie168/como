#ifndef MDL_H_
#define MDL_H_

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
