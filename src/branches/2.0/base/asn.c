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

#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#define LOG_DOMAIN "ASN"
#include "como.h"
#include "comopriv.h"

/*
 * This file provides Autonomous System identification for IP addresses
 *
 * It reads a file in MRT format to create a data structure (a binary
 * tree) that records which ASNs are announcing particular ranges.
 * IP addresses can then checked to determine if they are in a given ASN.
 *
 * MRT format is currently described in draft-ietf-grow-mrt-03.txt
 *
 */

uint32_t maskval[32] = {
    0xFFFFFFFF << 31,
    0xFFFFFFFF << 30,
    0xFFFFFFFF << 29,
    0xFFFFFFFF << 28,
    0xFFFFFFFF << 27,
    0xFFFFFFFF << 26,
    0xFFFFFFFF << 25,
    0xFFFFFFFF << 24,
    0xFFFFFFFF << 23,
    0xFFFFFFFF << 22,
    0xFFFFFFFF << 21,
    0xFFFFFFFF << 20,
    0xFFFFFFFF << 19,
    0xFFFFFFFF << 18,
    0xFFFFFFFF << 17,
    0xFFFFFFFF << 16,
    0xFFFFFFFF << 15,
    0xFFFFFFFF << 14,
    0xFFFFFFFF << 13,
    0xFFFFFFFF << 12,
    0xFFFFFFFF << 11,
    0xFFFFFFFF << 10,
    0xFFFFFFFF << 9,
    0xFFFFFFFF << 8,
    0xFFFFFFFF << 7,
    0xFFFFFFFF << 6,
    0xFFFFFFFF << 5,
    0xFFFFFFFF << 4,
    0xFFFFFFFF << 3,
    0xFFFFFFFF << 2,
    0xFFFFFFFF << 1,
    0xFFFFFFFF
};

/*
 * --------------------------------------------------------------------------
 * tree building
 * --------------------------------------------------------------------------
 *
 * for performance reasons we want a nice bushy tree to search, but
 * unfortunately the MRT file turns up pretty much in (ascending) order.
 * So we first perform an insertion sort to build a chained list
 * of prefixes, then, once completed, we turn that into an optimal tree.
 *
 * note that the tree is ordered left to right, with low prefix addresses
 * to the left and high prefix addresses to the right. Where the prefix
 * matches the most specific address (the highest subnet, the biggest
 * mask value) is the leftmost.
 */

typedef struct prefix prefix_t;

struct prefix {
    struct prefix *left;	/* left (lower)   part of tree */
    struct prefix *right;	/* right (higher) part of tree */
    uint32_t addr;		/* start of CIDR range         */
    uint32_t mask;		/* subnet mask                 */
    asn_t as0;			/* AS announcing this route    */
    asn_t as1;			/* another announcing AS (!)   */
};

prefix_t *base = NULL;

static void
free_prefix_tree(prefix_t * ptr)
{
    if (ptr->left)
	free_prefix_tree(ptr->left);
    if (ptr->right)
	free_prefix_tree(ptr->right);
    free(ptr);
}


static void
init_prefix_tree(void)
{
    if (base) {
	free_prefix_tree(base->left);
	free_prefix_tree(base->right);
    }

    base = NULL;
}

static void
add_new_prefix(const uint32_t prefix, const uint32_t mask,
	       const uint8_t subnet, const asn_t origin)
{
    prefix_t *ptr;

    /* walk chain (following "left/lower" links) to locate insertion point */

    for (ptr = base; ptr; ptr = ptr->left) {
	if (prefix == ptr->addr) {
	    if (mask == ptr->mask) {

		/* identical route to one we already have */

		if (origin == ptr->as0)
		    return;

		if (origin == ptr->as1)
		    return;

		/* a different AS -- that's how life is, add a second or moan */

		if (ptr->as1 == 0)
		    ptr->as1 = origin;
		else
		    warn("ignoring further announcement of %u.%u.%u.%u/%u "
			 "by AS %u!\n",
			 (prefix >> 24) & 0xFF,
			 (prefix >> 16) & 0xFF,
			 (prefix >> 8)  & 0xFF,
			  prefix        & 0xFF,
			  subnet,
			 origin);

		/* no need to make another node, so done */

		return;

	    } else if (mask < ptr->mask) {

		/* we have a less specific so insert here */

		break;
	    }
	} else if (prefix > ptr->addr) {

	    /* we have a higher start address so insert here */

	    break;
	}
    }

    /* insert new node to the "right/higher" side of where we are */

    prefix_t *node = malloc(sizeof(prefix_t));

    node->addr = prefix;
    node->mask = mask;
    node->as0  = origin;
    node->as1  = 0;

    node->left = ptr;

    if (ptr) {
	node->right = ptr->right;
	ptr->right = node;
    } else
	node->right = NULL;

    if (node->right)
	node->right->left = node;
    else
	base = node;
}

/* build_tree : recursive tree-building */

static prefix_t *
build_tree(prefix_t * const ptr, const int count)
{
    prefix_t *temp = ptr;

    switch (count) {
    case 0:
	error("zero length tree range!");

    case 1:			/* just a single item, so return it */
	temp->left = NULL;
	temp->right = NULL;
	break;

    case 2:			/* two items, so make rightmost one higher level */
	ptr->right = NULL;

	ptr->left->left = NULL;
	ptr->left->right = NULL;
	break;

    case 3:			/* three items, so can make nicely balanced tree */
	temp = ptr->left;

	ptr->left = NULL;
	ptr->right = NULL;

	temp->left->left = NULL;
	temp->left->right = NULL;

	break;

    default:
	{
	    /* otherwise split in half and deal with the two halves */

	    int i;
	    for (i = 0; i < count / 2; i++)
		temp = temp->left;

	    temp->left = build_tree(temp->left, (count - i) - 1);
	    temp->right = build_tree(ptr, i);

	    break;
	}
    }

    return temp;
}

/* make_prefix_tree: build tree from flat chain */

static void
make_prefix_tree(void)
{
    /* count items in tree */

    prefix_t *ptr;
    int count = 0;

    for (ptr = base; ptr; ptr = ptr->left)
	count++;

    /* recursive build of tree */

    base = build_tree(base, count);
}

/*
 * --------------------------------------------------------------------------
 * MRT utility routines
 * --------------------------------------------------------------------------
 */

static inline uint32_t
fetch32(const uint8_t * const buffer, const int offset)
{
    return (buffer[offset + 0] << 24)
	 | (buffer[offset + 1] << 16)
	 | (buffer[offset + 2] << 8) | buffer[offset + 3];
}

static inline uint16_t
fetch16(const uint8_t * const buffer, const int offset)
{
    return (buffer[offset + 0] << 8) | buffer[offset + 1];
}

static inline uint8_t
fetch8(const uint8_t * const buffer, const int offset)
{
    return buffer[offset];
}

/*
 * --------------------------------------------------------------------------
 * asn_readfile : read the MRT file describing current AS structure
 * --------------------------------------------------------------------------
 */

char *asn_file = NULL;		/* debounce file reading */

void
asn_readfile(const char *filename)
{
    char *fail = NULL;		/* possible failure message */
    int fd;			/* file descriptor */
#define	BUFFER_SIZE	1024
    uint8_t buffer[BUFFER_SIZE];	/* working buffer  */
#define ERRBUF_SIZE	64
    char errbuf[ERRBUF_SIZE];

    /*
     * debounce on the filename (if picky would extend this to an MD5
     * of the contents or similar, but this will do for now!
     */

    if (asn_file && filename && strcmp(asn_file, filename) == 0)
	return;

    free(asn_file);

    if (filename)
	asn_file = strdup(filename);
    else
	asn_file = NULL;

    /* initialise the prefix tree */

    init_prefix_tree();

    /* AS 65535 deemed to be the RFC1918 addresses:
     *          10.0.0.0/8
     *          172.16.0.0/12
     *          192.168.0.0/16
     */

    add_new_prefix((10 << 24) | (0 << 16), maskval[8 - 1], 8, 65535);
    add_new_prefix((172 << 24) | (16 << 16), maskval[12 - 1], 12, 65535);
    add_new_prefix((192 << 24) | (168 << 16), maskval[16 - 1], 16, 65535);

    /* now see what in the global routing table file... */

    if (filename) {
	if ((fd = open(filename, O_RDONLY)) < 0) {
	    warn("error while opening file %s: %s\n",
		 filename, strerror(errno));
	    return;
	}

	for (;;) {
	    uint16_t type;
	    uint16_t subtype;
	    uint16_t length;
	    uint32_t prefix;
	    uint8_t subnet;
	    uint8_t status;
	    asn_t peerAS;
	    asn_t origin;
	    uint16_t attribLen;
	    uint16_t i;

	    int count;		/* characters read */

	    if ((count = read(fd, buffer, 12)) != 12) {
		if (count)
		    fail = "header too short";
		break;
	    }

/*	    timestamp = fetch32(buffer, 0); 	ignored */
	    type = fetch16(buffer, 4);
	    subtype = fetch16(buffer, 6);
	    length = fetch32(buffer, 8);

	    if (type != 12) {
		fail = "unexpected type";
		break;
	    }

	    if (length > BUFFER_SIZE) {
		fail = "body too long";
		break;
	    }

	    if ((count = read(fd, buffer, length)) != length) {
		fail = "body too short";
		break;
	    }

	    switch (subtype) {
	    case 1:		/* IPV4 */
		break;
	    case 2:		/* IPV6 */
		continue;
	    default:
		fail = "unexpected subtype";
		break;
	    }

	    if (fail)
		break;

/*	    view   = fetch16(buffer, 0);		ignored */
/*	    seq    = fetch16(buffer, 2);		ignored */
	    prefix = fetch32(buffer, 4);
	    subnet = fetch8(buffer, 8);
	    status = fetch8(buffer, 9);

	    if (status != 1) {
		snprintf(errbuf, ERRBUF_SIZE,
			 "unexpected status value: %u", status);
		fail = errbuf;
		break;
	    }

/*	    orgtime   = fetch32(buffer, 10);	ignored */
/*	    peer      = fetch32(buffer, 14);	ignored */
	    peerAS    = fetch16(buffer, 18);
	    attribLen = fetch16(buffer, 20);

	    if (peerAS == 0)
		continue;

	    if (attribLen == 0) {
		fail = "unexpected lack of attributes";
		break;
	    }

	    origin = 0;

	    for (i = 0; i < attribLen;) {
		uint8_t *attrib;
		uint16_t lengthAttrib;

		uint8_t flags = fetch8(buffer, 22 + 0 + i);
		uint8_t acode = fetch8(buffer, 22 + 1 + i);

/*		int optionalAttrib   = (flags & 0x80);	ignored */
/*		int transitiveAttrib = (flags & 0x40);	ignored */
/*		int partialAttrib    = (flags & 0x20);	ignored */
		int extendedAttrib   = (flags & 0x10);

		if ((flags & 0x0F) != 0) {
		    fail = "bad flags on attribute";
		    break;
		}

		if (extendedAttrib) {
		    lengthAttrib = fetch16(buffer, 22 + 2 + i);
		    attrib = &buffer[22 + 4 + i];
		    i += 4 + lengthAttrib;
		} else {
		    lengthAttrib = fetch8(buffer, 22 + 2 + i);
		    attrib = &buffer[22 + 3 + i];
		    i += 3 + lengthAttrib;
		}

		if (acode == 2) {
		    uint16_t j;

		    if (origin) {
			fail = "multiple paths";
			break;
		    }

		    if (lengthAttrib == 0) {
			fail = "missing path";
			break;
		    }

		    /* as_path : triples of seg-type, seg-length, seg-value */

		    for (j = 0; j < lengthAttrib;) {
			uint8_t segLength;
			uint8_t segType = fetch8(attrib, j + 0);

			switch (segType) {
			case 1:	/* AS_SET */
			    break;
			case 2:	/* AS_SEQ */
			    break;
			default:
			    snprintf(errbuf, ERRBUF_SIZE,
				     "unexpected status value: %u",
				     status);
			    fail = errbuf;
			    break;
			}

			if (fail)
			    break;

			segLength = fetch8(attrib, j + 1);
			origin = fetch16(attrib, j + (2 * segLength));

			j += 2 + (2 * segLength);
		    }
		}
	    }

	    if (fail)
		break;

	    if (origin == 0) {
		fail = "no path seen";
		break;
	    }

	    if (subnet < 8 || subnet > 32) {
		warn("ignoring %u.%u.%u.%u/%u as clearly an error!\n",
		     (prefix >> 24) & 0xFF,
		     (prefix >> 16) & 0xFF,
		     (prefix >>  8) & 0xFF,
		      prefix        & 0xFF,
		      subnet);
	    } else {
		uint32_t mask = maskval[subnet - 1];

		if ((prefix & mask) != prefix)
		    warn("ignoring %u.%u.%u.%u/%u as non-aligned!\n",
			 (prefix >> 24) & 0xFF, (prefix >> 16) & 0xFF,
			 (prefix >> 8) & 0xFF, prefix & 0xFF, subnet);
		else
		    add_new_prefix(prefix, mask, subnet, origin);
	    }
	}

	if (fail)
	    warn("error in MST file: %s\n", fail);

	close(fd);
    }

    make_prefix_tree();
}

/*
 * --------------------------------------------------------------------------
 * asn_test: determine if an address is within the given AS
 * --------------------------------------------------------------------------
 */

int
asn_test(const uint32_t addr, const asn_t asn)
{
    prefix_t *ptr = base;

    while (ptr) {
	uint32_t a = addr & ptr->mask;

	if (a > ptr->addr)
	    ptr = ptr->right;
	else if (a < ptr->addr)
	    ptr = ptr->left;
	else {
	    /* matched the address, but may also match other nearby
	     * entries as well... so check for these cases */

	    if (ptr->right) {
		uint32_t r = addr & ptr->right->mask;
		if ((r == ptr->right->addr) && (r > a)) {
		    ptr = ptr->right;
		    continue;
		}
	    }

	    if (ptr->left) {
		uint32_t l = addr & ptr->left->mask;
		if ((l == ptr->left->addr) && (a >= l)) {
		    ptr = ptr->left;
		    continue;
		}
	    }

	    if (asn == ptr->as0 || asn == ptr->as1)
		return 1;
	    else
		return 0;
	}
    }

    return 0;
}

/* end of asn.c */
