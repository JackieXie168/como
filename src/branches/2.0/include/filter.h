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


#ifndef _COMO_FILTER_H
#define _COMO_FILTER_H

/*
 * Packet filter.
 *
 * On input, a list of packets and a count. On output, it returns the
 * number of outputs in *n_outputs, and also allocates and fills a
 * matrix of n_output rows, n_packet columns, indicating,
 * for each output, who is going to receive which packets.
 * The pointer to the matrix is returned by the function.
 *
 * The function also needs the array of modules, to check if a module
 * has been disabled (and if so, filter out all packets).
 *
 * For the time being, the array is one of integers. Later it
 * will be packed to use bits.
 */
struct _ipaddr {
    uint8_t direction;
    uint32_t ip;
    uint32_t nm;
};
typedef struct _ipaddr ipaddr_t;

struct _asnfilt {
    uint8_t direction;
    uint16_t asn;
};
typedef struct _asnfilt asnfilt_t;

struct _portrange {
    uint8_t direction;
    uint16_t lowport;
    uint16_t highport;
};
typedef struct _portrange portrange_t;

struct _iface { 
    uint8_t direction; 
    uint16_t index;
};
typedef struct _iface iface_t;

union _nodedata {
    ipaddr_t ipaddr;
    portrange_t ports;
    uint16_t proto;
    iface_t iface;
    ipaddr_t exaddr;
    asnfilt_t asn;
};
typedef union _nodedata nodedata_t;

struct _treenode
{
    uint8_t type;
    uint8_t pred_type;
    char *string;
    nodedata_t *data;
    struct _treenode *left;
    struct _treenode *right;
};
typedef struct _treenode treenode_t;

#define FILTER_ALL      0x0000
#define FILTER_PROTO    0x0001
#define FILTER_SRCIP    0x0002
#define FILTER_DSTIP    0x0004
#define FILTER_SRCPORT  0x0008
#define FILTER_DSTPORT  0x0010
#define FILTER_IFACE	0x0020

#endif /* _COMO_FILTER_H */
