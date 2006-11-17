#ifndef SHMEM_H_
#define SHMEM_H_

typedef struct shmem shmem_t;

shmem_t *    shmem_create   (size_t reqsize, const char * filename);
int          shmem_destroy  (shmem_t * m);
shmem_t *    shmem_attach   (const char * filename, void *base_addr);
int          shmem_detach   (shmem_t * m);
void *       shmem_baseaddr (const shmem_t * m);
size_t       shmem_size     (const shmem_t * m);
const char * shmem_filename (const shmem_t * m);

int shmem_remove (const char *filename);


#endif /*SHMEM_H_*/
