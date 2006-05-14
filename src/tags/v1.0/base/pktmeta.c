/*
 * Copyright (c) 2006, Intel Corporation
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

#include <string.h>
#include <assert.h>

#include "como.h"
#include "comopriv.h"
#include "hash.h"

static hash_t *s_registered_types = NULL;
static pktmeta_type_t s_type_counter = 0;

pktmeta_type_t
pktmeta_type_from_name(const char *name)
{
    pktmeta_type_t t;
    void *o;
    
    if (s_registered_types == NULL) {
	s_registered_types = hash_new(allocator_shared(),
				      HASHKEYS_STRING, NULL, NULL);
    }
    
    o = hash_lookup_string(s_registered_types, name);
    
    if (o == NULL) {
	/* create new type */
	s_type_counter++; /* after incr s_type_counter is the new type id */
	t = s_type_counter;
	hash_insert_string(s_registered_types, name, (void *) (uint32_t) t);
    } else {
    	t = (pktmeta_type_t) (uint32_t) o;
    }
    
    return t;
}

/*
 * -- pktmeta_set
 * 
 * Given a pkt in which the pktmetas pointer points to a valid area of memory
 * this function appends a new pktmeta to the packet.
 * Pktmetas are packed into memory with this layout:
 * +-------------------------+--------------+-------------------+
 * | pktmeta_type_t (16 bit) | len (16 bit) | value (len bytes) |
 * +-------------------------+--------------+-------------------+
 */
void
pktmeta_set(pkt_t *pkt, const char *name, void *value, uint16_t len)
{
    pktmeta_type_t pktmeta_type;
    char *newpktmeta;
    
    assert(pkt->pktmetas != NULL);
    
    pktmeta_type = pktmeta_type_from_name(name);
    
    newpktmeta = pkt->pktmetas + pkt->pktmetaslen;
    
    memcpy(newpktmeta, &pktmeta_type, sizeof(pktmeta_type_t));
    newpktmeta += sizeof(pktmeta_type_t);
    memcpy(newpktmeta, &len, sizeof(uint16_t));
    newpktmeta += sizeof(uint16_t);
    memcpy(newpktmeta, value, len);
    
    pkt->pktmetaslen += sizeof(pktmeta_type_t) + sizeof(uint16_t) + len;
}

void *
pktmeta_get(pkt_t *pkt, const char *name, uint16_t *len)
{
    pktmeta_type_t pktmeta_type;
    uint16_t *cur_len;
    char *pktmeta;
    char *endpktmeta;
    
    pktmeta_type = pktmeta_type_from_name(name);
    
    pktmeta = pkt->pktmetas;
    endpktmeta = pkt->pktmetas + pkt->pktmetaslen;
    
    while (pktmeta < endpktmeta) {
	pktmeta_type_t *cur_pktmeta_type;
	
	cur_pktmeta_type = (pktmeta_type_t *) pktmeta;
	pktmeta += sizeof(pktmeta_type_t);
	cur_len = (uint16_t *) pktmeta;
	if (pktmeta_type == *cur_pktmeta_type) {
	    if (len)
		*len = *cur_len;
	    return (void *) pktmeta + sizeof(uint16_t);
	}
	pktmeta += *cur_len;
    }
    if (len)
	*len = 0;
    return NULL;
}

