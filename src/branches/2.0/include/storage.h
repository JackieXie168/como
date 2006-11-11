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
 */


#ifndef STORAGE_H_
#define STORAGE_H_

/*
 * Data structure definitions for Como Storage module.
 * The preferred prefix for all entries here is 'cs' for Como Storage.
 *
 */

/*
 * Modes for opening a bytestream.
 * We voluntarily use some weird values to catch errors.
 */
typedef enum csmode {
    CS_READER = 0xff12,	/* read mode */
    CS_READER_NOBLOCK = 0xdfde,	/* read mode (non blocking) */
    CS_WRITER = 0x0437	/* write mode */
} csmode_t;


typedef enum {
    CS_SEEK_NONE,		/* error */
    CS_SEEK_FILE_NEXT,		/* goto next file */
    CS_SEEK_FILE_PREV,		/* goto prev file */

#if 0	/* XXX unimplemented */
    CS_SEEK_SET,		/* seek from the first byte */
    CS_SEEK_CUR,		/* seek from the current byte */
    CS_SEEK_END,		/* seek from the last byte */
    CS_SEEK_FILE_SET,	/* seek from the first file */
    CS_SEEK_FILE_CUR,	/* seek from the current file */
    CS_SEEK_FILE_END,	/* seek from the last file */
    CS_SEEK_TIME_SET,	/* seek from the first timestamp */
    CS_SEEK_TIME_CUR,	/* seek from the current timestamp */
    CS_SEEK_TIME_END,	/* seek from the last timestamp */
#endif
} csmethod_t;


/* 
 * Function prototypes 
 */

int    csopen   (const char * name, csmode_t mode, off_t size,
		 ipc_peer_t * storage);
off_t  csgetofs (int fd);
void * csmap    (int fd, off_t ofs, ssize_t * sz);
void   cscommit (int fd, off_t ofs);
off_t  csseek   (int fd, csmethod_t wh);
void   csclose  (int fd, off_t ofs);

#endif	/* STORAGE_H_ */
