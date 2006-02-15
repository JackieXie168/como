/*
 * Copyright (c) 2005 Intel Corporation 
 * Copyright (c) 2005 Steven Smith, University of Cambridge Computer Laboratory.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

/* Can't cope with any packets bigger than this.  This must be a
   factor of the page size. */
#define SK98_EXPECTED_PACKET_SIZE 2048

#define SK98_RING_SIZE 65534
struct sk98_map_area_header {
	/* Stuff mostly written by userspace */
	unsigned k2u_cons;
	unsigned u2k_prod;
	unsigned u2k_tokens[SK98_RING_SIZE];

	/* Stuff mostly written by kernel space */
	unsigned u2k_cons;
	unsigned k2u_prod;
	struct {
		unsigned token;
		unsigned tstamp;
		unsigned short len;
		unsigned short interface;
	} k2u_pipe[SK98_RING_SIZE];

	unsigned drop_counter;
};

struct sk98_ioctl_map {
	void *start_addr;
	unsigned long len;
	unsigned offset;
	unsigned version;
#define SK98_CURRENT_VERSION 4
};
#define SK98_IOCTL_MAP 1

