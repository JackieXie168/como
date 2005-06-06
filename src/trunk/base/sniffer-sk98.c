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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "como.h"
#include "sniffers.h"
#include "sk98_timers.h"

/* 
 * SNIFFER  ---    SysKonnect card SK98
 * 
 * Gigabit Ethernet card. 
 * It needs modified device driver from Computer Lab (Cambridge University). 
 * 
 */ 

/* 
 * Packet buffers. 
 * Note that each packet uses 2Kbytes of memory. 
 */
#define BUFFER_MB 32
struct packet_data_area {
    unsigned char payload[2048];
};


/* 
 * Rings with packet tokens. Modified by kernel and user 
 */
#define RING_SIZE 65535
struct map_area_header {
    /* Stuff mostly written by userspace */
    unsigned k2u_cons;
    unsigned u2k_prod;
    unsigned u2k_tokens[RING_SIZE];

    /* Stuff mostly written by kernel */
    unsigned u2k_cons;
    unsigned k2u_prod;
    struct {
	unsigned token;
	unsigned tstamp;
	unsigned short len;
	unsigned short interface;
    } k2u_pipe[RING_SIZE];
};

#define mb() asm volatile("lock; addl $0, (%%esp)" ::: "memory")


/* 
 * IOCTL structure used to pass info to the driver
 */
struct sk98_ioctl_map {
    void *start_addr;
    unsigned long len;
    unsigned offset;
};
#define SK98_IOCTL_MAP 1


/* 
 * Sniffer state variables for SK98 card (include packets, tokens
 * and time-synchronization information).  
 */
struct _snifferinfo { 
    struct map_area_header * m;	
    struct packet_data_area * packet_pool;	
    unsigned retimer_size;		
    clock_retimer_t ** clock_retimers;	
    int tokens[RING_SIZE];
    int no_tokens; 
};


/* 
 * -- discard_packets 
 * 
 * Clean up packet pool and tokens. Useful after time calibration.
 * 
 */
static void
discard_packets(struct map_area_header * m)
{
    /* Return packets to the OS without examining them */
    while (m->k2u_prod > m->k2u_cons) {
	m->u2k_tokens[m->u2k_prod % RING_SIZE] = 
		m->k2u_pipe[m->k2u_cons % RING_SIZE].token;
	mb();
	m->u2k_prod++;
	m->k2u_cons++;
    }
    mb();
}


/* 
 * -- calibrate
 * 
 * Calibrate the packet timestamps 
 *
 */
void 
calibrate(struct _snifferinfo * info)
{
    struct map_area_header * m = info->m; 
    clock_retimer_t ** cr = info->clock_retimers;	
    uint size = info->retimer_size; 
    uint num;
    uint calibrated; 

    logmsg(V_LOGSNIFFER, "Starting timer calibration\n");

    num = calibrated = 0;
    do {
	struct timeval now;
	uint s, t;

        while (m->k2u_cons >= m->k2u_prod)
            mb();
        t = m->k2u_prod;

        mb();
        gettimeofday(&now, NULL);
        for (s = m->k2u_cons; s < t; s++) {
            uint iface;
            int ind;

            ind = s % RING_SIZE;
            iface = m->k2u_pipe[ind].interface;
            if (iface == (unsigned short)-1)
                continue;

            if (iface >= size) {
                logmsg(V_LOGSNIFFER, 
		    "Extend retimer array: %d -> %d\n", size, iface + 1);
                cr = safe_realloc(cr, (iface + 1) * sizeof(cr[0]));
                memset(cr + size, 0, sizeof(cr[0]) * (iface + 1 - size));
                size = iface + 1;
            }

            if (cr[iface] == NULL) {
                logmsg(V_LOGSNIFFER, "Found interface %d\n", iface);
                cr[iface] = new_clock_retimer("", 0);
                num++;
            }
            calibrated += doTimer(cr[iface], m->k2u_pipe[ind].tstamp, 0, &now);
        }
        discard_packets(m);
    } while (calibrated != num);

    info->retimer_size = size; 
    info->clock_retimers = cr;
    logmsg(V_LOGSNIFFER, "Calibrated %d interfaces\n", calibrated);
}


/* 
 * -- sniffer_start
 * 
 * In order to start the Syskonnect sk98 we open the device and 
 * mmap a region in memory that the driver has allocated for us
 * (it will keep the tokens for the packets). 
 * Then, we inform the driver of the size of the packet buffer and
 * where it is. Finally, start timer calibration using the sk98-timers API. 
 * It returns 0 on success, -1 on failure.
 * 
 */
static int
sniffer_start(source_t * src) 
{
    struct _snifferinfo * info; 
    struct sk98_ioctl_map args;
    int fd;

    /* Start up the timestamps library 
     * 
     * XXX where do we get 78110207 from? (initial frequency?) 
     */
    initialise_timestamps(1, 78110207, NULL);

    /* open the device */
    fd = open(src->device, O_RDWR);
    if (fd < 0) {
        logmsg(LOGWARN, "sniffer-sk98: cannot open %s: %s\n", 
	    src->device, strerror(errno)); 
        return -1;
    } 

    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo)); 
    info = (struct _snifferinfo *) src->ptr; 

    /* 
     * mmap the region that contains the ring buffers 
     * with the tokens. 
     */ 
    info->m = mmap(NULL, sizeof(struct map_area_header), 
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (info->m == MAP_FAILED) {
        logmsg(LOGWARN, "sniffer-sk98: failed to mmap %s: %s\n", 
	    src->device, strerror(errno)); 
	free(src->ptr);
        return -1;
    } 

    /* inform the driver of where the packets should go */
    args.len = 1024 * 1024 * BUFFER_MB;
    args.offset = 0;
    info->packet_pool = safe_malloc(args.len);
    args.start_addr = info->packet_pool;
    if (ioctl(fd, SK98_IOCTL_MAP, &args) < 0) {
        logmsg(LOGWARN, "sniffer-sk98: failed creating packet pool: %s\n", 
	    strerror(errno)); 
	free(src->ptr);
        return -1;
    } 

    /* we have no packets */
    info->no_tokens = -1; 

    /* do timer calibration */
    calibrate(info); 

    src->fd = fd; 
    return 0;	/* success */
}


/*
 * -- return_token
 *
 * gives token back to kernel
 */
static void
return_token(struct map_area_header * m, unsigned token)
{
    unsigned ind;
    ind = m->u2k_prod % RING_SIZE;
    m->u2k_tokens[ind] = token;
    m->u2k_prod++;
}

/*
 * sniffer_next
 *
 * Fill a structure with a copy of the next packet and its metadata.
 * Return number of packets read.
 *
 */
static int
sniffer_next(source_t * src, pkt_t *out, int max_no)
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr; 
    pkt_t * pkt;
    int npkts;                 /* processed pkts */

    mb();

    /* return all tokens of previous round */
    for (; info->no_tokens >= 0; info->no_tokens--) {
	info->m->k2u_cons++;
	return_token(info->m, info->tokens[info->no_tokens]);
    } 

    info->no_tokens = 0; 

    for (npkts = 0, pkt = out; npkts < max_no; npkts++, pkt++) { 
	uint ind;
	uint token;
	ushort iface;
	struct timeval tv;
	int len; 
	char * base; 

        if (info->m->k2u_cons == info->m->k2u_prod) 
	    break; 	/* no more tokens */

	ind = info->m->k2u_cons % RING_SIZE;
	token = info->m->k2u_pipe[ind].token;

	iface = info->m->k2u_pipe[ind].interface;
	if (iface == (ushort)-1) {
	    /* Kernel decided not to use this token.  Return it. */
	    return_token(info->m, token);
	    info->m->k2u_cons++;
	    continue;
	}

	if (iface >= info->retimer_size || info->clock_retimers[iface] == NULL){
	    /* Clock calibration was incomplete.  Uh oh. */
	    logmsg(V_LOGSNIFFER, "calibration incomplete, returning token\n"); 
	    return_token(info->m, token);
	    info->m->k2u_cons++;
	    continue;
	}

	/* we have a good incoming packet; deal with it. */
	info->tokens[npkts] = token; 
	base = info->packet_pool[token].payload; 
	len = info->m->k2u_pipe[ind].len; 
	getTime(info->clock_retimers[iface], info->m->k2u_pipe[ind].tstamp, 
		&tv, NULL);

        /*
         * Now we have a packet: start filling a new pkt_t struct
         * (beware that it could be discarded later on)
         */
        pkt->ts = TIME2TS(tv.tv_sec, tv.tv_usec); 
        pkt->len = len; 
        pkt->caplen = len;
	pkt->payload = base; 

        /* 
         * update layer2 information and offsets of layer 3 and above. 
         * this sniffer only runs on ethernet frames. 
         */
        updateofs(pkt, COMOTYPE_ETH); 
    }

    info->no_tokens = npkts; 
    return npkts;		
}


static void
sniffer_stop (source_t * src) 
{
    struct _snifferinfo * info = (struct _snifferinfo *) src->ptr;

    munmap(info->m,  sizeof(struct map_area_header));
    free(info->packet_pool); 
    free(src->ptr);
}

sniffer_t sk98_sniffer = {
    "sk98", sniffer_start, sniffer_next, sniffer_stop, 0
};
