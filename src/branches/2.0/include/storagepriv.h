#ifndef STORAGEPRIV_H_
#define STORAGEPRIV_H_

#include "storage.h"

#define CS_MAXCLIENTS   	500            	/* max no. of clients/files */
#define CS_OPTIMALSIZE		(1024*1024)	/* size for mmap() */
#define CS_DEFAULT_TIMEOUT	TIME2TS(3600,0)	/* readers' timeout */
/*
 * file name format 
 */
#define FILE_NAMELEN    16 /* filenames are 16 decimal digits */
#define FILE_NAMEFMT    "%s/%016llx" /* format used to print */

#ifndef MAP_NOSYNC /* linux doesn't have MAP_NOSYNC */
#define MAP_NOSYNC 0
#endif

/*
 * Message exchanged between STORAGE and its clients.
 */
typedef struct csmsg {
    int		id; 
    int		arg;			/* seek method, open mode, errno */ 
    off_t	ofs;			/* requested offset */
    off_t	size;			/* requested/granted block size
					   (or filesize) */
    char	name[FILENAME_MAX];	/* file name (only for OPEN message) */
} csmsg_t;


/* storage IPCs */
enum {
   S_ERROR = 0x5100,
   S_NODATA,
   S_ACK,
   S_OPEN,
   S_CLOSE,
   S_REGION,
   S_SEEK,
   S_INFORM,
   S_SHUTDOWN
};

#endif /*STORAGEPRIV_H_*/
