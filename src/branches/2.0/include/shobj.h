#ifndef SHOBJ_H_
#define SHOBJ_H_

typedef struct shobj shobj_t;

char *    shobj_build_path(const char * directory, const char * name);
shobj_t * shobj_open(const char * filename);
void *    shobj_symbol(shobj_t * shobj, const char * symbol);
int       shobj_close(shobj_t * shobj);

#endif /*SHOBJ_H_*/
