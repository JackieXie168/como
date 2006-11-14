#ifndef POOL_H_
#define POOL_H_

typedef struct pool_t pool_t;

pool_t * pool_create   ();
void     pool_clear    (pool_t * pool);
void     pool_destroy  (pool_t * pool);
void     pool_alc_init (pool_t * pool, alc_t * alc);

#endif /*POOL_H_*/
