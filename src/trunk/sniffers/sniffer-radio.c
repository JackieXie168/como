/*
 * Copyright (c) 2006, Intel Corporation
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

#include <sys/stat.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* close */
#include <string.h>		/* memset */
#include <errno.h>
#include <dlfcn.h>		/* dlopen */

#include <sys/ioctl.h>		/* ioctl for monitor mode */
#include <sys/socket.h>		/* socket for monitor mode */

#include <linux/wireless.h>

#include <math.h>

#include <assert.h>

#include "como.h"
#include "sniffers.h"
#include "pcap.h"

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
#define LIBPCAP_DEFAULT_SNAPLEN 1500	/* packet capture */
#define LIBPCAP_DEFAULT_TIMEOUT 0	/* timeout to serve packets */

/* 
 * functions that we need from libpcap.so 
 */
typedef int (*pcap_dispatch_fn) (pcap_t *, int, pcap_handler, u_char *);
typedef pcap_t *(*pcap_open_fn) (const char *, int, int, int, char *);
typedef void (*pcap_close_fn) (pcap_t *);
typedef int (*pcap_noblock_fn) (pcap_t *, int, char *);
typedef int (*pcap_fileno_fn) (pcap_t *);
typedef int (*pcap_datalink_fn) (pcap_t *);

/*
 * This data structure will be stored in the source_t structure and 
 * used for successive callbacks.
 */
#define BUFSIZE		(1024 * 1024)
struct _snifferinfo {
    void *handle;		/* handle to libpcap.so */
    uint32_t type;
    pcap_dispatch_fn dispatch;	/* ptr to pcap_dispatch function */
    pcap_t *pcap;		/* pcap handle */
    uint snaplen;		/* capture length */
    char pktbuf[BUFSIZE];	/* packet buffer */
    char errbuf[PCAP_ERRBUF_SIZE + 1];	/* error buffer for libpcap */
    monitor_t *mon;		/* monitor capable device */
    to_como_radio_fn fallback_to_como_radio;
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
orinoco_close(const char *dev, __unused void *data_)
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
none_open(__unused const char *dev, __unused int ch, __unused void **data_)
{
    *data_ = NULL;		/* Unused */

    return 0;
}

static void
none_close(__unused const char *dev, __unused void *data)
{
}

static monitor_t monitors[] = {
    {"none", none_open, none_close, NULL, NULL},
    {"orinoco", orinoco_open, orinoco_close, avs_or_prism2_header_to_como_radio, NULL},
    {"wlext", wlext_open, wlext_close, NULL, NULL},
    {"hostap", hostap_open, wlext_close, avs_header_to_como_radio, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static char s_protos[32];

/*
 * -- sniffer_start
 * 
 * open the pcap device using the options provided.
 * this sniffer needs to keep some information in the source_t 
 * data structure. It returns 0 on success and -1 on failure.
 * 
 */
static int
sniffer_start(source_t * src)
{
    struct _snifferinfo *info = NULL;
    uint snaplen = LIBPCAP_DEFAULT_SNAPLEN;
    uint timeout = LIBPCAP_DEFAULT_TIMEOUT;
    uint channel = 1;
    pcap_open_fn sp_open;
    pcap_fileno_fn sp_fileno;
    pcap_noblock_fn sp_noblock;
    pcap_datalink_fn sp_link;
    pcap_close_fn sp_close;
    char *mon_name = MONITOR_NAME_DEFAULT;
    monitor_t *mon;
    metadesc_t *outmd;
    pkt_t *pkt;
    const headerinfo_t *lchi;

    if (src->args) {
	/* process input arguments */
	char *p;
	char *val;

	if ((p = strstr(src->args, "snaplen")) != NULL) {
	    /* number of bytes to read from packet */
	    val = index(p, '=') + 1;
	    snaplen = atoi(val);
	}
	if ((p = strstr(src->args, "timeout")) != NULL) {
	    /* timeout to regulate reception of packets */
	    val = index(p, '=') + 1;
	    timeout = atoi(val);
	}
	if ((p = strstr(src->args, "channel")) != NULL) {
	    /* frequency channel to monitor */
	    val = index(p, '=') + 1;
	    channel = atoi(val);
	    if (channel < 1)
		channel = 1;
	    else if (channel > 14)
		channel = 14;
	}
	if ((p = strstr(src->args, "monitor")) != NULL) {
	    /* monitor device type */
	    val = index(p, '=') + 1;
	    if (val) {
		char *val2;
		val2 = index(val, ' ');
		if (val2)
		    *val2 = '\0';
		mon_name = val;
	    }
	}
    }

    logmsg(V_LOGSNIFFER,
	   "sniffer-radio: snaplen %d, timeout %d, channel %d\n",
	   snaplen, timeout, channel);

    /* 
     * set the interface in monitor mode
     */
    for (mon = monitors; mon->name != NULL; mon++)
	if (strcmp(mon->name, mon_name) == 0)
	    break;

    if (!mon->name) {
	logmsg(LOGWARN, "sniffer-radio: monitor device not supported: %s\n",
	       mon_name);
	return -1;
    }

    if (mon->open(src->device, channel, &mon->data) < 0)
	return -1;

    /* 
     * allocate the _snifferinfo and link it to the 
     * source_t data structure
     */
    src->ptr = safe_calloc(1, sizeof(struct _snifferinfo));
    info = (struct _snifferinfo *) src->ptr;
    info->pcap = NULL;

    info->mon = mon;

    /* link the libpcap library */
    info->handle = dlopen("libpcap.so", RTLD_NOW);
    if (info->handle == NULL) {
	logmsg(LOGWARN, "sniffer-radio: error while opening libpcap.so: %s\n",
	       strerror(errno));
	goto error;
    }

    /* find all the symbols that we will need */
    sp_open = (pcap_open_fn) dlsym(info->handle, "pcap_open_live");
    sp_noblock = (pcap_noblock_fn) dlsym(info->handle, "pcap_setnonblock");
    sp_link = (pcap_datalink_fn) dlsym(info->handle, "pcap_datalink");
    sp_fileno = (pcap_fileno_fn) dlsym(info->handle, "pcap_fileno");
    sp_close = (pcap_close_fn) dlsym(info->handle, "pcap_close");
    info->dispatch = (pcap_dispatch_fn) dlsym(info->handle, "pcap_dispatch");

    /* initialize the pcap handle */
    info->pcap = sp_open(src->device, snaplen, 0, timeout, info->errbuf);
    info->snaplen = snaplen;

    /* check for initialization errors */
    if (info->pcap == NULL) {
	logmsg(LOGWARN, "sniffer-radio: libpcap open failed: %s\n",
	       info->errbuf);
	goto error;
    }
    if (info->errbuf[0] != '\0')
	logmsg(LOGWARN, "sniffer-radio: libcap reports error: %s\n",
	       info->errbuf);

    /*
     * It is very important to set pcap in non-blocking mode, otherwise
     * sniffer_next() will try to fill the entire buffer before returning.
     */
    if (sp_noblock(info->pcap, 1, info->errbuf) < 0) {
	logmsg(LOGWARN, "sniffer-radio: can't set non blocking mode: %s\n",
	       info->errbuf);
	goto error;
    }

    /* check datalink type.  support 802.11 DLT_ values */
    switch (sp_link(info->pcap)) {
    case DLT_PRISM_HEADER:
	info->type = COMOTYPE_RADIO;
	info->fallback_to_como_radio = prism2_header_to_como_radio;
	break;
/*    case DLT_IEEE802_11_RADIO:
    info->type = COMOTYPE_RADIO;
    info->fallback_to_como_radio = NULL; // TODO: bsd
    break;*/
    case DLT_IEEE802_11_RADIO_AVS:
	info->type = COMOTYPE_RADIO;
	info->fallback_to_como_radio = avs_header_to_como_radio;
	break;
    case DLT_IEEE802_11:
	info->type = COMOTYPE_LINK;
	info->fallback_to_como_radio = NULL;
	break;
    default:
	logmsg(LOGWARN, "sniffer-radio: unrecognized datalink format\n");
	goto error;
    }

    src->fd = sp_fileno(info->pcap);
    src->flags = SNIFF_TOUCHED | SNIFF_SELECT;
    src->polling = 0;
    
    /* setup output descriptor */
    outmd = metadesc_define_sniffer_out(src, 0);
    
    lchi = headerinfo_lookup_with_type_and_layer(info->type, LCOMO);
    assert(lchi);
    
    snprintf(s_protos, 32, "%s:802.11:any:any", lchi->name);
    pkt = metadesc_tpl_add(outmd, s_protos);
    COMO(caplen) = snaplen;
    
    return 0;			/* success */
  error:
    if (info && info->pcap) {
	sp_close(info->pcap);
	info->pcap = NULL;
    }
    mon->close(src->device, mon->data);
    free(src->ptr);
    return -1;
}

typedef struct {
    pkt_t *pkt;
    struct _snifferinfo *info;
    int res_drop;
} processpkt_data_t;

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
    processpkt_data_t *pdata = (processpkt_data_t *) data;
    pkt_t *pkt = pdata->pkt;
    char *dest;
    int info_len = 0;
    int len;

    dest = COMO(payload);
    COMO(caplen) = 0;

    if (pdata->info->type == COMOTYPE_RADIO) {
	struct _como_radio *radio;
	radio = (struct _como_radio *) dest;
	if (pdata->info->mon->to_como_radio)
	    info_len = pdata->info->mon->to_como_radio((const char *) buf,
						       radio);
	else
	    info_len = pdata->info->fallback_to_como_radio((const char *) buf,
							   radio);

	buf += info_len;	/* buf points to 802.11 fixed header */
	dest += sizeof(struct _como_radio);

	COMO(caplen) = sizeof(struct _como_radio);
    }

    len = ieee80211_capture_frame((const char *) buf, h->caplen - info_len,
				  dest);
    if (len == 0) {
	pdata->res_drop = 1;
	return;
    }

    COMO(ts) = TIME2TS(h->ts.tv_sec, h->ts.tv_usec);
    COMO(caplen) += len;

    updateofs(pkt, L2, LINKTYPE_80211);
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
sniffer_next(source_t * src, pkt_t * out, int max_no)
{
    struct _snifferinfo *info = (struct _snifferinfo *) src->ptr;
    pkt_t *pkt = out;
    int npkts = 0;		/* processed packets */
    int nbytes = 0;
    processpkt_data_t pdata;

    pdata.info = info;

    while (npkts < max_no) {
	int count;
	assert(nbytes < BUFSIZE);
	/* point the packet payload to next packet */
	COMO(payload) = info->pktbuf + nbytes;
	/* specify como type */
	COMO(type) = info->type;

	pdata.pkt = pkt;
	pdata.res_drop = 0;

	/*
	 * we use pcap_dispatch() because pcap_next() is assumend unaffected
	 * by the pcap_setnonblock() call. (but it doesn't seem that this is 
	 * actually the case but we still believe the man page. 
	 * 
	 * we retrieve one packet at a time for simplicity. 
	 * XXX check the cost of processing one packet at a time... 
	 * 
	 */

	count = info->dispatch(info->pcap, 1, processpkt, (u_char *) & pdata);
	if (count == 0)
	    break;

	if (pdata.res_drop == 0) {
	    nbytes += COMO(caplen);
	    npkts++;
	    pkt++;
	} else {
	    src->drops++;
	}
    }

    return npkts;
}


/*
 * -- sniffer_stop 
 * 
 * close the pcap descriptor and destroy the entry in the
 * list of pcap devices. 
 */
static void
sniffer_stop(source_t * src)
{
    struct _snifferinfo *info = (struct _snifferinfo *) src->ptr;
    pcap_close_fn sp_close;

    close(src->fd);
    sp_close = (pcap_close_fn) dlsym(info->handle, "pcap_close");
    sp_close(info->pcap);
    info->mon->close(src->device, info->mon->data);
    free(src->ptr);
}

struct _sniffer radio_sniffer = {
    "radio", sniffer_start, sniffer_next, sniffer_stop
};
