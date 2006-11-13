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


#endif /*MDL_H_*/
