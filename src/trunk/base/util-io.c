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


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> 			/* va_start */
#include <string.h>
#include <errno.h>
#include <unistd.h>     
#include <dlfcn.h>
#include <sys/types.h>			/* inet_ntop */
#include <assert.h>

#include "como.h"


/* 
 * keeps reading until complete. 
 */
int
como_read(int fd, char *buf, size_t nbytes)
{
    int n = 0;
    
    while (n < (int) nbytes) {
        int ret = read(fd, buf + n, nbytes - n);
        if (ret == -1)
            return -1;
        if (ret == 0) /* EOF */
            break;
        
        n += ret;
    }
    
    return n; /* <= nbytes */
}

/*
 * keeps writing until complete.
 */
int
como_writen(int fd, const char *buf, size_t nbytes)
{
    size_t n = 0;

    while (n < nbytes) {
	int ret = write(fd, buf + n, nbytes - n);

	if (ret == -1)
	    return -1;

        n += ret;
    }
   
    return n; /* == nbytes */
}

