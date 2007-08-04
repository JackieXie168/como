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

#include <sys/stat.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* close */
#include <string.h>		/* memset */
#include <errno.h>
#include <dlfcn.h>		/* dlopen */
#include <sys/mman.h>   /* mmap.h */

#include <sys/ioctl.h>		/* ioctl for monitor mode */
#include <sys/socket.h>		/* socket for monitor mode */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <math.h>

#include <assert.h>

#include "como.h"
#include "sniffers.h"
#include "pcap.h"

#include "capbuf.c"

typedef int (*monitor_open_fn) (const char *, int, void **);
typedef void (*monitor_close_fn) (const char *, void *);

typedef struct {
    const char *name;			/* name of monitor capable device */
    monitor_open_fn open;		/* enter monitor mode */
    monitor_close_fn close;		/* exit monitor mode */
    to_como_radio_fn to_como_radio;	/* convert radio hdr into como radio */
    void *data;				/* private data */
} monitor_t;


#define MONITOR_NAME_DEFAULT	"none"

/* 
 * default values for libpcap 
 */
#define RADIO_DEFAULT_SNAPLEN 1500	/* packet capture */
#define RADIO_DEFAULT_TIMEOUT 0	/* timeout to serve packets */
#define RADIO_MIN_BUFSIZE	(1024 * 1024)
#define RADIO_MAX_BUFSIZE	(RADIO_MIN_BUFSIZE * 2)

/* 
 * functions that we need from libpcap.so 
 */
typedef int (*pcap_dispatch_fn)(pcap_t *, int, pcap_handler, u_char *); 
typedef pcap_t * (*pcap_open_live_fn)(const char *, int, int, int, char *);
typedef void (*pcap_close_fn)(pcap_t *); 
typedef int (*pcap_setnonblock_fn)(pcap_t *, int, char *); 
typedef int (*pcap_fileno_fn)(pcap_t *); 
typedef int (*pcap_datalink_fn)(pcap_t *); 

/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */

struct radio_me {
    sniffer_t		sniff;		/* common fields, must be the first */
    void *		handle;		/* handle to libpcap.so */
    pcap_dispatch_fn	sp_dispatch;	/* ptr to pcap_dispatch function */
    pcap_close_fn	sp_close;	/* ptr to pcap_close function */
    pcap_t *		pcap;		/* pcap handle */
    enum COMOTYPE	type;		/* como layer type */
    const char *	device;		/* capture device */
    int			channel;	/* monitored channel */
    int			snaplen; 	/* capture length */
    int			timeout;	/* capture timeout */
    char		errbuf[PCAP_ERRBUF_SIZE + 1]; /* error buffer */
    monitor_t *		mon;		/* monitor capable device */
    to_como_radio_fn	fallback_to_como_radio;
    int			dropped_pkts;
    capbuf_t		capbuf;
};


static int
ifconfig_set_flags(const char *dev, short flags)
{
    int s;
    struct ifreq r;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    strncpy(r.ifr_name, dev, IFNAMSIZ);
    r.ifr_flags = flags;

    if (ioctl(s, SIOCSIFFLAGS, &r) < 0) {
	logmsg(LOGWARN, "ioctl failed: %s\n", strerror(errno));
	close(s);
	return -1;
    }

    close(s);

    return 0;
}

static int
ifconfig_get_flags(const char *dev, short *flags)
{
    int s;
    struct ifreq r;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    strncpy(r.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIFFLAGS, &r) < 0) {
	logmsg(LOGWARN, "ioctl failed: %s\n", strerror(errno));
	close(s);
	return -1;
    }

    *flags = r.ifr_flags;

    close(s);

    return 0;
}

#define IW_MAX_PRIV_DEF 128

static int
iwconfig_set_priv(const char *dev, const char *cmd, int v1, int v2)
{
    int i;
    int s;
    struct iwreq r;
    struct iw_priv_args priv[IW_MAX_PRIV_DEF];
    int nargs;
    int subcmd = 0;
    int offset = 0;
    uint8_t buffer[4096];

    memset(priv, 0, sizeof(priv));

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    memset(&r, 0, sizeof(r));
    strncpy(r.ifr_name, dev, IFNAMSIZ);

    r.u.data.pointer = (caddr_t) priv;
    r.u.data.length = IW_MAX_PRIV_DEF;
    r.u.data.flags = 0;

    if (ioctl(s, SIOCGIWPRIV, &r) < 0) {
	logmsg(LOGWARN, "can't retrieve list of private ioctls: %s\n",
	       strerror(errno));
	close(s);
	return -1;
    }

    for (i = 0; i < r.u.data.length; i++)
	if (strcmp(priv[i].name, cmd) == 0)
	    break;

    if (i == r.u.data.length) {
	logmsg(LOGWARN, "can't fint private ioctl: %s\n", cmd);
	close(s);
	return -2;
    }

    if (priv[i].cmd < SIOCDEVPRIVATE) {
	int j;

	for (j = -1; j < r.u.data.length; j++)
	    if ((priv[j].name[0] == '\0') ||
		(priv[j].set_args == priv[i].set_args) ||
		(priv[j].get_args != priv[i].get_args))
		break;

	if (j == r.u.data.length) {
	    logmsg(LOGWARN, "can't fint private subioctl: %s\n", cmd);
	    close(s);
	    return -2;
	}

	subcmd = priv[i].cmd;
	offset = sizeof(uint32_t);
	i = j;
    }

    if ((priv[i].set_args & IW_PRIV_TYPE_MASK) == 0 ||
	(priv[i].set_args & IW_PRIV_SIZE_MASK) == 0) {
	logmsg(LOGWARN, "can't set values for private ioctl: %s\n", cmd);
	close(s);
	return -1;
    }

    if ((priv[i].set_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
	logmsg(LOGWARN, "private ioctl doesn't accept integers: %s\n", cmd);
	close(s);
	return -1;
    }

    nargs = (priv[i].set_args & IW_PRIV_SIZE_MASK);
    if (nargs > 2) {
	logmsg(LOGWARN, "private ioctl expects more than 2 args: %s\n", cmd);
	close(s);
	return -1;
    }

    memset(&r, 0, sizeof(struct iwreq));
    strncpy(r.ifr_name, dev, IFNAMSIZ);

    r.u.data.length = nargs;
    ((uint32_t *) buffer)[0] = (uint32_t) v1;
    if (nargs > 1) {
	((uint32_t *) buffer)[1] = (uint32_t) v2;
    }

    if ((priv[i].set_args & IW_PRIV_SIZE_FIXED) &&
	((sizeof(uint32_t) * nargs) + offset <= IFNAMSIZ)) {
	if (offset)
	    r.u.mode = subcmd;
	memcpy(r.u.name + offset, buffer, IFNAMSIZ - offset);
    } else {
	r.u.data.pointer = (caddr_t) buffer;
	r.u.data.flags = 0;
    }

    if (ioctl(s, priv[i].cmd, &r) < 0) {
	logmsg(LOGWARN, "ioctl failed %s: %s\n", cmd, strerror(errno));
	close(s);
	return -1;
    }

    close(s);
    return 0;
}

static int
iwconfig_get_mode(const char *dev, int *mode)
{
    struct iwreq q;
    int s;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    memset(&q, 0, sizeof(struct iwreq));
    strncpy(q.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIWMODE, &q) < 0) {
	logmsg(LOGWARN, "can't get mode: %s\n", strerror(errno));
	close(s);
	return -1;
    }

    (*mode) = q.u.mode;

    close(s);
    return 0;
}

static int
iwconfig_set_mode(const char *dev, int mode)
{
    struct iwreq r;
    int s;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    memset(&r, 0, sizeof(struct iwreq));
    strncpy(r.ifr_name, dev, IFNAMSIZ);
    r.u.mode = mode;

    if (ioctl(s, SIOCSIWMODE, &r) < 0) {
	logmsg(LOGWARN, "can't set mode: %s\n", strerror(errno));
	close(s);
	return -1;
    }

    close(s);
    return 0;
}

inline static float
freq_to_float(struct iwreq *inreq)
{
    return ((float) inreq->u.freq.m) * pow(10, inreq->u.freq.e);
}

static void
float_to_freq(double in_val, struct iw_freq *out_freq)
{
    if (in_val <= 165) {
	out_freq->m = (uint32_t) in_val;
	out_freq->e = 0;
	return;
    }

    out_freq->e = (short) (floor(log10(in_val)));
    if (out_freq->e > 8) {
	out_freq->m = ((long) (floor(in_val / pow(10, out_freq->e - 6)))) * 100;
	out_freq->e -= 8;
    } else {
	out_freq->m = (uint32_t) in_val;
	out_freq->e = 0;
    }
}

static int IEEE80211Freq[] = {
    2412, 2417, 2422, 2427, 2432,
    2437, 2442, 2447, 2452, 2457,
    2462, 2467, 2472, 2484,
    5180, 5200, 5210, 5220, 5240,
    5250, 5260, 5280, 5290, 5300,
    5320, 5745, 5760, 5765, 5785,
    5800, 5805, 5825,
    -1
};

int IEEE80211Ch[] = {
    1, 2, 3, 4, 5,
    6, 7, 8, 9, 10,
    11, 12, 13, 14,
    36, 40, 42, 44, 48,
    50, 52, 56, 58, 60,
    64, 149, 152, 153, 157,
    160, 161, 165
};

static int
float_to_int_channel(float in_chan)
{
    if (in_chan > 0 && in_chan <= 165)
	return (int) in_chan;

    int mod_chan = (int) rintf(in_chan / 1000000);
    int x = 0;

    while (IEEE80211Freq[x] != -1) {
	if (IEEE80211Freq[x] == mod_chan) {
	    return IEEE80211Ch[x];
	}
	x++;
    }

    return 0;
}

static int
iwconfig_get_channel(const char *dev, int *ch)
{
    struct iwreq q;
    int s;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }

    memset(&q, 0, sizeof(struct iwreq));
    strncpy(q.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIWFREQ, &q) < 0) {
	logmsg(LOGWARN, "can't get channel socket: %s\n", strerror(errno));
	close(s);
	return -1;
    }

    close(s);

    *ch = float_to_int_channel(freq_to_float(&q));

    return 0;
}

static int
iwconfig_set_channel(const char *dev, int in_ch)
{
    struct iwreq q;
    int s;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	logmsg(LOGWARN, "can't create socket: %s\n", strerror(errno));
	return -1;
    }
    memset(&q, 0, sizeof(struct iwreq));

    strncpy(q.ifr_name, dev, IFNAMSIZ);
    float_to_freq(in_ch, &q.u.freq);

    /* Set a channel */
    if (ioctl(s, SIOCSIWFREQ, &q) < 0) {
	usleep(5000);

	/* Try twice with a tiny delay, some cards (madwifi) need a second chance... */
	if (ioctl(s, SIOCSIWFREQ, &q) < 0) {
	    logmsg(LOGWARN, "can't set channel socket: %s\n", strerror(errno));
	    close(s);
	    return -1;
	}
    }

    close(s);
    return 0;
}

typedef struct {
    int ch;
    short flags;
} orinoco_data_t;

static int
orinoco_open(const char *dev, int ch, void **data_)
{
    orinoco_data_t *data;

    data = safe_malloc(sizeof(orinoco_data_t));
    *data_ = data;

    /* Save the current flags */
    if (ifconfig_get_flags(dev, &data->flags) < 0)
	return -1;

    if (ifconfig_set_flags
	(dev, data->flags | IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
	return -1;

    /* Save the current channel */
    if (iwconfig_get_channel(dev, &data->ch) < 0)
	return -1;

    usleep(5000);

    if (iwconfig_set_priv(dev, "monitor", 1, ch) < 0)
	return -1;

    return 0;
}

static void
orinoco_close(const char *dev, __attribute__((__unused__)) void *data_)
{
    orinoco_data_t *data = (orinoco_data_t *) data_;

    /* Restore flags */
    ifconfig_set_flags(dev, data->flags);

    /* Restore channel */
    iwconfig_set_channel(dev, data->ch);

    /* Exit monitor mode */
    iwconfig_set_priv(dev, "monitor", 0, 1);

    free(data);
}

typedef struct {
    int mode;
    int ch;
    short flags;
} wlext_data_t;

static int
wlext_open(const char *dev, int ch, void **data_)
{
    wlext_data_t *data;

    data = safe_malloc(sizeof(wlext_data_t));
    *data_ = data;

    /* Save the current flags */
    if (ifconfig_get_flags(dev, &data->flags) < 0)
	return -1;

    if (ifconfig_set_flags
	(dev, data->flags | IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
	return -1;

    /* Save the current channel */
    if (iwconfig_get_channel(dev, &data->ch) < 0)
	return -1;

    /* Save the current mode */
    if (iwconfig_get_mode(dev, &data->mode) < 0)
	return -1;

    /* Avoid to enter monitor mode if the device is already in */
    if (data->mode != IW_MODE_MONITOR) {
	/* Enter monitor mode */
	if (iwconfig_set_mode(dev, IW_MODE_MONITOR) < 0) {
	    logmsg(LOGWARN, "can't enter in monitor mode!\n");
	    return -1;
	}
    }

    /* Set the initial channel */
    if (iwconfig_set_channel(dev, ch) < 0) {
	return -2;
    }

    return 0;
}

static void
wlext_close(const char *dev, void *data_)
{
    wlext_data_t *data = (wlext_data_t *) data_;

    /* Restore flags */
    ifconfig_set_flags(dev, data->flags);

    /* Restore channel */
    iwconfig_set_channel(dev, data->ch);

    if (data->mode != IW_MODE_MONITOR) {
	/* Exit monitor mode */
	if (iwconfig_set_mode(dev, data->mode) < 0) {
	    logmsg(LOGWARN, "failed to exit from monitor mode!\n");
	}
    }

    free(data);
}

enum PRISM2_MONITOR {
    PRISM2_MONITOR_80211 = 0,
    PRISM2_MONITOR_PRISM = 1,
    PRISM2_MONITOR_CAPHDR = 2	/* AVS header */
};

#define PRISM2_PARAM_MONITOR_TYPE 26

static int
hostap_open(const char *dev, int ch, void **data_)
{
    if (iwconfig_set_priv(dev, "prism2_param",
			  PRISM2_PARAM_MONITOR_TYPE, PRISM2_MONITOR_CAPHDR) < 0)
	return -1;

    return wlext_open(dev, ch, data_);
}

static int
none_open(__attribute__((__unused__)) const char *dev,
          __attribute__((__unused__)) int ch,
          __attribute__((__unused__)) void **data_)
{
    *data_ = NULL;		/* Unused */

    return 0;
}

static void
none_close(__attribute__((__unused__)) const char *dev,
           __attribute__((__unused__)) void *data)
{
}

static monitor_t s_monitors[] = {
    {"none", none_open, none_close, NULL, NULL},
    {"orinoco", orinoco_open, orinoco_close, avs_or_prism2_header_to_como_radio,
        NULL},
    {"wlext", wlext_open, wlext_close, NULL, NULL},
    {"hostap", hostap_open, wlext_close, avs_header_to_como_radio, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};


/*
 * -- sniffer_init
 * 
 */
static sniffer_t *
sniffer_init(const char * device, const char * args)
{
    struct radio_me *me;
    char* libpcap_name = NULL;

    me = safe_calloc(1, sizeof(struct radio_me));
    
    me->sniff.max_pkts = 128;
    me->sniff.flags = SNIFF_SELECT | SNIFF_SHBUF;
    me->snaplen = RADIO_DEFAULT_SNAPLEN;
    me->timeout = RADIO_DEFAULT_TIMEOUT;
    me->device = device;
    me->mon = &s_monitors[0];

    if (args) { 
	/* process input arguments */
	char *p; 

	if ((p = strstr(args, "snaplen=")) != NULL) {
	    me->snaplen = atoi(p + 8);
	    if (me->snaplen < 1 || me->snaplen > 65536) {
		logmsg(LOGWARN,
		       "sniffer-libpcap: invalid snaplen %d, using %d\n",
		       me->snaplen, RADIO_DEFAULT_SNAPLEN);
		me->snaplen = RADIO_DEFAULT_SNAPLEN;
	    }
	}
	if ((p = strstr(args, "timeout=")) != NULL) {
	    me->timeout = atoi(p + 8);
	}
	if ((p = strstr(args, "channel=")) != NULL) {
	    /* frequency channel to monitor */
	    me->channel = atoi(p + 8);
	    if (me->channel < 1) {
		me->channel = 1;
	    } else if (me->channel > 14) {
		me->channel = 14;
	    }
	}
	if ((p = strstr(args, "monitor=")) != NULL) {
	    /* monitor device type */
	    monitor_t *mon;
	    for (mon = s_monitors; mon->name != NULL; mon++) {
		if (strncmp(mon->name, p + 8, strlen(mon->name)) == 0)
		    break;
	    }
	    if (mon->name) {
		me->mon = mon;
	    } else {
		logmsg(LOGWARN, "sniffer-radio: unrecognized monitor device");
	    }
	}
    }

    logmsg(V_LOGSNIFFER,
	   "sniffer-radio: snaplen %d, timeout %d, channel %d\n",
	   me->snaplen, me->timeout, me->channel);

    /* link the libpcap library */
    asprintf(&libpcap_name, "libpcap%s", SHARED_LIB_EXT);
    me->handle = dlopen(libpcap_name, RTLD_NOW);

    if (me->handle == NULL) { 
	logmsg(LOGWARN, "sniffer-libpcap: error opening %s: %s\n",
	       libpcap_name, dlerror());
	goto error;
    } 

    /* find all the symbols that we will need */
#define SYMBOL(name) dlsym(me->handle, name)

    me->sp_close = (pcap_close_fn) SYMBOL("pcap_close"); 
    me->sp_dispatch = (pcap_dispatch_fn) SYMBOL("pcap_dispatch");

    /* create the capture buffer */
    if (capbuf_init(&me->capbuf, args, NULL, RADIO_MIN_BUFSIZE,
		    RADIO_MAX_BUFSIZE) < 0)
	goto error;

    return (sniffer_t *) me;
error:
    if (me->handle) {
	dlclose(me->handle);
    }
    free(me);
    if (libpcap_name != NULL)
      free(libpcap_name);
    return NULL;
}


static void
sniffer_setup_metadesc(sniffer_t * s)
{
    struct radio_me *me = (struct radio_me *) s;
    metadesc_t *outmd;
    pkt_t *pkt;
    const headerinfo_t *lchi;
    char protos[32]; /* protos string of metadesc template */

    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(s, 0);
    
    lchi = headerinfo_lookup_with_type_and_layer(me->type, LCOMO);
    assert(lchi);
    
    snprintf(protos, 32, "%s:802.11:any:any", lchi->name);
    pkt = metadesc_tpl_add(outmd, protos);
    COMO(caplen) = me->snaplen;
}


/*
 * -- sniffer_start
 * 
 * open the pcap device using the options provided.
 * this sniffer needs to keep some information in the source_t 
 * data structure. It returns 0 on success and -1 on failure.
 * 
 */
static int
sniffer_start(sniffer_t * s)
{
    struct radio_me *me = (struct radio_me *) s;
    pcap_open_live_fn sp_open_live;
    pcap_setnonblock_fn sp_setnonblock;
    pcap_datalink_fn sp_datalink;
    pcap_fileno_fn sp_fileno;

    /* find all the symbols that we will need */
    sp_open_live = (pcap_open_live_fn) SYMBOL("pcap_open_live");  
    sp_setnonblock = (pcap_setnonblock_fn) SYMBOL("pcap_setnonblock"); 
    sp_datalink = (pcap_datalink_fn) SYMBOL("pcap_datalink"); 
    sp_fileno = (pcap_fileno_fn) SYMBOL("pcap_fileno"); 

    /* put the device in monitor mode */
    if (me->mon->open(me->device, me->channel, &me->mon->data) < 0) {
	return -1;
    }

    /* initialize the pcap handle */
    me->pcap = sp_open_live(me->device, me->snaplen, 0,
			    me->timeout, me->errbuf);
    
    /* check for initialization errors */
    if (me->pcap == NULL) {
	logmsg(LOGWARN, "sniffer-libpcap: error: %s\n", me->errbuf);
	return -1;
    }
    if (me->errbuf[0] != '\0') {
	logmsg(LOGWARN, "sniffer-libpcap: %s\n", me->errbuf);
    }
    
    /*
     * It is very important to set pcap in non-blocking mode, otherwise
     * sniffer_next() will try to fill the entire buffer before returning.
     */
    if (sp_setnonblock(me->pcap, 1, me->errbuf) < 0) {
        logmsg(LOGWARN, "%s\n", me->errbuf);
        return -1;
    }
    
    /* check datalink type.  support 802.11 DLT_ values */
    switch (sp_datalink(me->pcap)) {
    case DLT_PRISM_HEADER:
	me->type = COMOTYPE_RADIO;
	me->fallback_to_como_radio = avs_or_prism2_header_to_como_radio;
	break;
    case DLT_IEEE802_11_RADIO:
        me->type = COMOTYPE_RADIO;
        me->fallback_to_como_radio = radiotap_header_to_como_radio;
        break;
    case DLT_IEEE802_11_RADIO_AVS:
	me->type = COMOTYPE_RADIO;
	me->fallback_to_como_radio = avs_header_to_como_radio;
	break;
    case DLT_IEEE802_11:
	me->type = COMOTYPE_LINK;
	me->fallback_to_como_radio = NULL;
	break;
    default:
	logmsg(LOGWARN, "sniffer-radio: unrecognized datalink format\n");
	me->sp_close(me->pcap);
	return -1;
    }

    me->sniff.fd = sp_fileno(me->pcap);

    return 0; 		/* success */
}


/* 
 * -- processpkt
 * 
 * this is the callback needed by pcap_dispatch. we use it to 
 * copy the data from the pcap packet into a pkt_t data structure. 
 * 
 */
static void
processpkt(u_char * data, const struct pcap_pkthdr *h, const u_char * buf)
{
    size_t sz;
    const size_t mgmt_sz = sizeof(struct _ieee80211_mgmt_hdr) +
			   sizeof(struct _como_wlan_mgmt);
    pkt_t *pkt;
    struct radio_me *me = (struct radio_me *) data;
    char *dest;
    int len;
    struct _ieee80211_base *hdr;

    sz = sizeof(pkt_t);
    if (me->type == COMOTYPE_RADIO) {
	sz += sizeof(struct _como_radio);
    }
    sz += MAX((size_t) h->caplen, mgmt_sz);
    
    /* reserve the space in the buffer for the packet */
    pkt = (pkt_t *) capbuf_reserve_space(&me->capbuf, sz);
    assert((void *) pkt >= me->capbuf.base &&
	   (void *) pkt < me->capbuf.end);

    /* the payload points to the end of the pkt_t structure */
    COMO(payload) = (char *) (pkt + 1);
    assert((void *) COMO(payload) >= me->capbuf.base &&
	   (void *) COMO(payload) < me->capbuf.end);
    
    COMO(ts) = TIME2TS(h->ts.tv_sec, h->ts.tv_usec);
    COMO(len) = h->len;
    COMO(type) = me->type;
    COMO(caplen) = 0;
    
    len = h->caplen;

    if (me->type == COMOTYPE_RADIO) {
	struct _como_radio *radio;
	int info_len;
	
	radio = (struct _como_radio *) COMO(payload);
	/* process the radio info header */
	if (me->mon->to_como_radio) {
	    info_len = me->mon->to_como_radio((const char *) buf, radio);
	} else {
	    info_len = me->fallback_to_como_radio((const char *) buf, radio);
	}
	assert(info_len > 0);
	/* so far caplen is sizeof(struct _como_radio) */
	COMO(caplen) = sizeof(struct _como_radio);
	/* point to the beginning of 802.11 frame */
	buf += info_len;
	len -= info_len;
    }

    hdr = (struct _ieee80211_base *) buf;
    dest = COMO(payload) + COMO(caplen);
    if (hdr->fc_type == IEEE80211TYPE_MGMT) {
	int mgmt_len;
	/* process the mgmt frame */
	mgmt_len = ieee80211_process_mgmt_frame((const char *) buf, len, dest);
	if (mgmt_len > 0) {
	    COMO(caplen) += mgmt_len;
	} else {
	    me->dropped_pkts++;
	    return;
	}
    } else {
	/* copy the frame */
	/* FIXME: caplen can be greater than than me->snaplen if the packet has
	 * radio information as they are rewritten in the _como_radio struct.
	 */
	memcpy(dest, buf, len);
	COMO(caplen) += len;
    }
	
    /*
     * update layer2 information and offsets of layer 3 and above.
     * this sniffer only runs on ethernet frames.
     */
    updateofs(pkt, L2, LINKTYPE_80211);

    ppbuf_capture(me->sniff.ppbuf, pkt);
}


/*
 * -- sniffer_next 
 *
 * Reads all the available packets and fills an array of variable sized
 * pkt_t accordingly. Returns the number of packets in the buffer or -1 
 * in case of error 
 *
 * The raw data format depends on the input device.
 * Using libpcap, each packet is preceded by the following header:
 *   struct timeval ts;    time stamp
 *   int32 caplen;         length of the actually available data
 *   int32 len;            length of the entire packet (off wire)
 * 
 */
static int
sniffer_next(sniffer_t * s, int max_pkts,
             __attribute__((__unused__)) timestamp_t max_ivl,
	     pkt_t * first_ref_pkt, int * dropped_pkts)
{
    struct radio_me *me = (struct radio_me *) s;
    int count, x;
    
    capbuf_begin(&me->capbuf, first_ref_pkt);
    
    for (count = 0, x = 1; x > 0 && count < max_pkts; count += x) {
	x = me->sp_dispatch(me->pcap, max_pkts, processpkt,
			   (u_char *) me);
    }
    
    *dropped_pkts = me->dropped_pkts;
    me->dropped_pkts = 0;
    
    return (x >= 0) ? 0 : -1;
}


static float
sniffer_usage(sniffer_t * s, pkt_t * first, pkt_t * last)
{
    struct radio_me *me = (struct radio_me *) s;
    size_t sz;
    void * y;
    
    y = ((void *) last) + sizeof(pkt_t) + last->caplen;
    sz = capbuf_region_size(&me->capbuf, first, y);
    return (float) sz / (float) me->capbuf.size;
}


/*
 * -- sniffer_stop 
 * 
 * close the pcap descriptor and destroy the entry in the
 * list of pcap devices. 
 */
static void
sniffer_stop(sniffer_t * s) 
{
    struct radio_me *me = (struct radio_me *) s;
    
    me->sp_close(me->pcap);
    me->mon->close(me->device, me->mon->data);

}


static void
sniffer_finish(sniffer_t * s)
{
    struct radio_me *me = (struct radio_me *) s;
    
    capbuf_finish(&me->capbuf);
    free(me);
}


SNIFFER(radio) = {
    name: "radio",
    init: sniffer_init,
    finish: sniffer_finish,
    setup_metadesc: sniffer_setup_metadesc,
    start: sniffer_start,
    next: sniffer_next,
    stop: sniffer_stop,
    usage: sniffer_usage
};
