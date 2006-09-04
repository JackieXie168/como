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


#include <stdarg.h> 			/* va_start */
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "como.h"
#include "comopriv.h"
#include "hash.h"

/* global state */
extern struct _como map;

static metadesc_t *
metadesc_new_va(allocator_t *alc, int pktmeta_count, va_list ap)
{
    metadesc_t *md;
    int i = 0;
    
    md = alc_calloc(alc, 1, sizeof(metadesc_t));

    md->_next = NULL;
    md->_alc = alc;
    md->_tpl_count = 0;
    md->_first_tpl = NULL;
    md->flags = 0;
    md->ts_resolution = 0;
    md->pktmeta_count = pktmeta_count;
    
    if (pktmeta_count > 0) {
    	md->pktmeta_types = alc_calloc(alc, pktmeta_count,
				       sizeof(pktmeta_type_t));
    	
	while (i < pktmeta_count) {
	    pktmeta_type_t pktmeta_type;
	    pktmeta_type = pktmeta_type_from_name(va_arg(ap, char *));
	    md->pktmeta_types[i] = pktmeta_type;
	    i++;
	}
    }
    
    return md;
}

/*
 * Creates a new metadesc_t object with pktmeta_count options.
 * Options are the same as pktmeta options used for packets, but in this context
 * only their types are used.
 * The object is dinamically allocated and should be freed with the
 * metadesc_list_free() function.
 */
metadesc_t *
metadesc_new(int pktmeta_count, ...)
{
    va_list ap;
    metadesc_t *md;
    
    va_start(ap, pktmeta_count);
    md = metadesc_new_va(allocator_safe(), pktmeta_count, ap);
    va_end(ap);
    
    return md;
}

/*
 * Behaves like metadesc_new as a metadesc_t object is created but this
 * function also manages the list of meta descriptors. Given the head of the
 * list it returns the new head of the list that points to the newly created
 * metadesc_t object.
 */
metadesc_t *
metadesc_list_new(metadesc_t *head, int pktmeta_count, ...)
{
    va_list ap;
    metadesc_t *md;
    
    va_start(ap, pktmeta_count);
    md = metadesc_new_va(allocator_safe(), pktmeta_count, ap);
    va_end(ap);
    
    md->_next = head;
    
    return md;
}

metadesc_t *
metadesc_define_in(module_t *self, int pktmeta_count, ...)
{
    va_list ap;
    metadesc_t *md;
    
    va_start(ap, pktmeta_count);
    md = metadesc_new_va(&self->alc, pktmeta_count, ap);
    va_end(ap);
    
    md->_next = self->indesc;
    self->indesc = md;
    
    return md;
}

metadesc_t *
metadesc_define_out(module_t *self, int pktmeta_count, ...)
{
    va_list ap;
    metadesc_t *md;
    
    va_start(ap, pktmeta_count);
    md = metadesc_new_va(&self->alc, pktmeta_count, ap);
    va_end(ap);
    
    md->_next = self->outdesc;
    self->outdesc = md;
    
    return md;
}

metadesc_t *
metadesc_define_sniffer_out(sniffer_t * s, int pktmeta_count, ...)
{
    va_list ap;
    metadesc_t *md;
    source_t *src;
    
    va_start(ap, pktmeta_count);
    md = metadesc_new_va(allocator_safe(), pktmeta_count, ap);
    va_end(ap);
    
    /* find the source corresponding to s */
    for (src = map.sources; src != NULL; src = src->next) {
	if (src->sniff == s)
		break;
    }
    assert(src != NULL);
    md->_next = src->outdesc;
    src->outdesc = md;
    
    return md;
}

/*
 * Destroys a metadesc_t object releasing all used resources.
 */
void
metadesc_list_free(metadesc_t *head)
{
    metadesc_t *d;
    metatpl_t *t;
    allocator_t *alc;
    
    while (head) {
    	alc = head->_alc;
	while (head->_first_tpl) {
	    t = head->_first_tpl;
	    head->_first_tpl = t->_next;
	    alc_free(alc, t->protos);
	    alc_free(alc, t);
	}
	d = head;
	head = d->_next;
	alc_free(alc, d->pktmeta_types);
	alc_free(alc, d);
    }
}

struct parsed_protos_t {
    uint16_t type;
    uint16_t l2type;
    uint16_t l3type;
    uint16_t l4type;
    uint16_t l2len;
    uint16_t l3len;
    uint16_t l4len;
    uint16_t padding;
    uint32_t len;
};

static void
parse_protos(const char *protos, struct parsed_protos_t *pp)
{
    const headerinfo_t *hi;
    layer_t l;
    const char d[] = ":";
    char *protos_copy = safe_strdup(protos);
    char *t, *s;
    t = s = protos_copy;

    pp->type = COMOTYPE_ANY;
    pp->l2type = LINKTYPE_ANY;
    pp->l3type = L3TYPE_ANY;
    pp->l4type = L4TYPE_ANY;
    pp->l2len = 0;
    pp->l3len = 0;
    pp->l4len = 0;

    pp->len = 0;
    
    l = LCOMO;

    while ((t = strsep(&s, d)) != NULL) {
	int has_bitmask = 0;
	
	if (*t == '\0')
	    continue;
	
	if (l > LCOMO) {
	    if (*t == '~') {
		t++;
		has_bitmask = 1;
	    }
	}
	
	hi = headerinfo_lookup_with_name_and_layer(t, l);
	assert(hi);
	/* FIXME: abort here? */
	
	switch (l) {
	case LCOMO:
	    pp->type = hi->type;
	    l = L2;
	    break;
	case L2:
	    pp->l2type = hi->type;
	    if (has_bitmask)
		pp->l2len = hi->hdr_len;
	    l = L3;
	    break;
	case L3:
	    pp->l3type = hi->type;
	    if (has_bitmask)
		pp->l3len = hi->hdr_len;
	    l = L4;
	    break;
	/*case L4:*/
	default:
	    pp->l4type = hi->type;
	    if (has_bitmask)
		pp->l4len = hi->hdr_len;
	    s = NULL; /* end parsing */
	    break;
	}
	if (has_bitmask) {
	    pp->len += hi->hdr_len;
	}
    }
    
    free(protos_copy);
}

/*
 * Adds a new packet template to the metadesc_t object pointed by md.
 * The structure of the new template is specified with the argument protos that
 * has the following syntax:
 * type + ':' + ['~'] + l2type + ':' + ['~'] + l3type + ':' + ['~'] + l4type
 * Where type is one of defined COMOTYPE, l2type one of LINKTYPE, and so on.
 * These types must be specified with their compact name:
 * e.g. COMOTYPE_ANY -> 'any', COMOTYPE_LINK -> 'link'
 * The approximate character '~' if present implies that the template defines
 * a template for that layer. This happens when the layer is not completely
 * available or required.
 * If '~' is not present then the full layer is expected to be available or
 * required.
 */
pkt_t *
metadesc_tpl_add(metadesc_t *md, const char *protos)
{
    metatpl_t *tpl;
    pkt_t *pkt;
    struct parsed_protos_t pp;
    
    parse_protos(protos, &pp);
    
    tpl = alc_calloc(md->_alc, 1, sizeof(metatpl_t) + pp.len);
    tpl->protos = alc_malloc(md->_alc, strlen(protos) + 1);
    strcpy(tpl->protos, protos);
    
    pkt = &tpl->tpl;
    
    /* sets important fields of new packet */
    COMO(type) = pp.type;
    COMO(l2type) = pp.l2type;
    COMO(l2ofs) = 0;
    COMO(l3type) = pp.l3type;
    COMO(l3ofs) = pp.l2len;
    COMO(l4type) = pp.l4type;
    COMO(l4ofs) = COMO(l3ofs) + pp.l3len;
    COMO(l7ofs) = COMO(l4ofs) + pp.l4len;
    COMO(caplen) = pp.len;
    assert(COMO(l7ofs) == COMO(caplen));
    /* the payload is located after pkt_t structure */
    COMO(payload) = (char *) ((char *) pkt + sizeof(pkt_t));
    
    /* update tpl list in md */
    md->_tpl_count++;
    tpl->_next = md->_first_tpl;
    md->_first_tpl = tpl;
    
    return pkt;
}

/*
 * This macro checks the compatibility of layer types.
 * The check is successful in the following cases:
 * - in type == NONE
 * - in type == out type
 * - out type == any
 * - in type == any && out type != none
 */
#define CHECK_TYPE(which, any, none)			\
    if (pin->which != none &&				\
       pin->which != pout->which &&			\
       pout->which != any &&				\
       (pin->which != any ||				\
       pout->which == none)) {				\
	tout = tout->_next;				\
	continue;					\
    }

/*
 * This macro compares the layer bitmasks if they exist.
 * The check is successful when, if the bitmasks exist, they are compatible
 * (compatibility is checked through binary matching).
 * The check is still successful when the bitmasks don't exist or a
 * bitmask exists only in the in template.
 * The check fails when a bitmask is provided only by out template.
 */
#define CHECK_LAYER(lno, none)				\
    if (hasL ## lno ## P(pin) && hasL ## lno ## P(pout)) { \
	char *inmask, *outmask;				\
	int k = 0, mask_ok = 1;				\
	assert(sizeofL ## lno ## P(pin) == sizeofL ## lno ## P(pout)); \
	inmask = COMOP(pin, payload) + COMOP(pin, l ## lno ## ofs); \
	outmask = COMOP(pout, payload) + COMOP(pout, l ## lno ## ofs); \
	while (k < sizeofL ## lno ## P(pin)) {		\
	    if (inmask[k] & ~outmask[k]) {		\
		mask_ok = 0;				\
		break;					\
	    }						\
	    k++;					\
	}						\
	if (!mask_ok) {					\
	    tout = tout->_next;				\
	    continue;					\
	}						\
    } else if (pin->l ## lno ## type != none &&		\
	       hasL ## lno ## P(pout)) {		\
    	tout = tout->_next;				\
    	continue;					\
    }

int
metadesc_try_match_pair(metadesc_t *out, metadesc_t *in)
{
    metatpl_t *tin, *tout;
    pkt_t *pin, *pout;
    int affinity = 0;

    /* meta level matching */
    
    /* check timestamp resolution */
    if (in->ts_resolution < out->ts_resolution)
	return METADESC_INCOMPATIBLE_TS_RESOLUTION;
    
    /* check flags */
    if (in->flags & ~out->flags)
	return METADESC_INCOMPATIBLE_FLAGS;
    
    /* check options */
    if (in->pktmeta_count > 0) {
	uint32_t i, j;
	int pktmeta_types_ok = 0;
	
	i = 0;
	while (i < in->pktmeta_count && !pktmeta_types_ok) {
	    j = 0;
	    while (j < out->pktmeta_count) {
		if (in->pktmeta_types[i] == out->pktmeta_types[j]) {
		    pktmeta_types_ok = 1;
		    break;
		}
		j++;
	    }
	    i++;
	}
	
	if (!pktmeta_types_ok)
	    return METADESC_INCOMPATIBLE_PKTMETAS;
	
	affinity += in->pktmeta_count;
    }
    
    /* check templates */
    tin = in->_first_tpl;
    
    while (tin) {
	int tpl_ok = 0;
	
	pin = &tin->tpl;
	assert(pin->pktmetaslen == 0);
	
	tout = out->_first_tpl;
	
	while (tout) {
	    pout = &tout->tpl;
	    assert(pout->pktmetaslen == 0);
	    
	    /* CHECKME: caplen = 0 means don't care, ok? */
	    if (pin->caplen != 0 && pout->caplen != 0 &&
		pin->caplen > pout->caplen) {
	    	tout = tout->_next;
	    	continue;
	    }
	    
	    CHECK_TYPE(type, COMOTYPE_ANY, COMOTYPE_NONE);
	    /* NOTE: no bitmask checking for type */
	    
	    CHECK_TYPE(l2type, LINKTYPE_ANY, LINKTYPE_NONE);
	    CHECK_LAYER(2, LINKTYPE_NONE);
	    
	    CHECK_TYPE(l3type, L3TYPE_ANY, L3TYPE_NONE);
	    CHECK_LAYER(3, L3TYPE_NONE);
	    
	    CHECK_TYPE(l4type, L4TYPE_ANY, L4TYPE_NONE);
	    CHECK_LAYER(4, L4TYPE_NONE);
	    
	    tpl_ok++;
	    tout = tout->_next;
	}
	
	if (!tpl_ok)
	    return METADESC_INCOMPATIBLE_TPLS;
	
	affinity += tpl_ok;

	tin = tin->_next;
    }
    
    if (affinity) {
	/* raise up affinity */
	if (out->flags & META_PKTS_ARE_FLOWS)
	    affinity += 2;
	
	if (out->flags & META_HAS_FULL_PKTS)
	    affinity += 1;
    }
    
    return affinity;
}

int
metadesc_try_match(metadesc_t * out, metadesc_t * in,
		   __OUT metadesc_match_t ** matches,
		   __OUT metadesc_incompatibility_t ** incomps_,
		   __OUT int *incomps_count_)
{
    metadesc_t *init, *outit;
    metadesc_match_t *res = NULL;
    metadesc_incompatibility_t *incomps = NULL;
    int affinity, matches_count = 0, incomps_count = 0;
    
    for (init = in; init != NULL; init = init->_next) {
	for (outit = out; outit != NULL; outit = outit->_next) {
	    affinity = metadesc_try_match_pair(outit, init);
	    if (affinity > 0) {
		res = safe_realloc(res, (matches_count + 1) *
				   sizeof(metadesc_match_t));
		
		res[matches_count].in = init;
		res[matches_count].out = outit;
		res[matches_count].affinity = affinity;
		matches_count++;
	    } else {
		incomps = safe_realloc(incomps, (incomps_count + 1) *
				       sizeof(metadesc_incompatibility_t));
		incomps[incomps_count].in = init;
		incomps[incomps_count].out = outit;
		incomps[incomps_count].reason = affinity;
		incomps_count++;
	    }
	}
    }
    
    *matches = res;
    *incomps_ = incomps;
    *incomps_count_ = incomps_count;
    
    return matches_count;
}

int
metadesc_best_match(metadesc_t * out, metadesc_t * in,
		    __OUT metadesc_match_t * best,
		    __OUT metadesc_incompatibility_t ** incomps,
		    __OUT int *incomps_count)
{
    metadesc_match_t *matches;
    int matches_count;
    
    matches_count = metadesc_try_match(out, in, &matches, incomps,
				       incomps_count);
    
    if (matches_count) {
	int i, max_affinity = 0;
	metadesc_match_t *found = NULL;
	for (i = 0; i < matches_count; i++) {
	    if (matches[i].affinity > max_affinity) {
		max_affinity = matches[i].affinity;
		found = &matches[i];
	    }
	}
	assert(found != NULL);
	*best = *found; /* copy out */
    }
    
    free(matches);
    
    return matches_count > 0;
}

const char *
metadesc_incompatibility_reason(metadesc_incompatibility_t * incomp)
{
    static const char *reasons[] = {
    	"Incompatible templates.",
    	"Incompatible packet meta options.",
    	"Incompatible flags.",
    	"Incompatible timestamp resolution."
    };
    if (incomp->reason < 0 && incomp->reason > -5) {
    	return reasons[incomp->reason + 4];
    }
    return NULL;
}


char *
metadesc_determine_filter(metadesc_t * md)
{
    int *layers[5];
    int l;
    uint32_t tpc;
    metatpl_t *tplit;
    pkt_t *pkt;
    char *filter = NULL, *tmp;
    int filter_initialized = 0;
    
    layers[0] = NULL;
    layers[LCOMO] = NULL;
    layers[L2] = NULL;
    
    for (l = L3; l <= L4; l++)
	layers[l] = safe_calloc(md->_tpl_count, sizeof(int));
    
    /*
     * Iterate over the template list and keep the information of used
     * l*types. If the type NONE or ANY is used then write -1 in the first
     * element of layers array.
     */
    for (tplit = md->_first_tpl, tpc = 0; tplit != NULL;
	 tplit = tplit->_next, tpc++) {
	
	assert(tpc < md->_tpl_count);
	
	pkt = &tplit->tpl;
	
	if (COMO(l3type) == L3TYPE_NONE || COMO(l3type) == L3TYPE_ANY) {
	    layers[L3][0] = -1;
	} else {
	    layers[L3][tpc] = COMO(l3type);
	}
	if (COMO(l4type) == L4TYPE_NONE || COMO(l4type) == L4TYPE_ANY) {
	    layers[L4][0] = -1;
	} else {
	    layers[L4][tpc] = COMO(l4type);
	}
    }
    /* NOTE: here we start from L4 so that if have a filter for L4
     * then we skip L3 */
    for (l = L4; l >= L3; l--) {
    	hash_t *seen;
	if (layers[l][0] == -1) continue;
	
	seen = hash_new(allocator_safe(), HASHKEYS_POINTER, NULL, NULL);
	
	if (filter_initialized == 0) {
	    asprintf(&filter, "(");
	    filter_initialized = 1;
	} else {
	    asprintf(&tmp, "%s and (", filter);
	    free(filter);
	    filter = tmp;
	}
	
	for (tpc = 0; tpc < md->_tpl_count; tpc++) {
	    const headerinfo_t *hi;
	    
	    hi = headerinfo_lookup_with_type_and_layer(layers[l][tpc], l);
	    
	    assert(hi);
	    
	    if (hash_insert(seen, (void *) hi, (void *) 1)) {
		/* This is the first insertion in hash */
		if (tpc == 0) {
		    asprintf(&tmp, "%s %s ", filter, hi->name);
		} else {
		    asprintf(&tmp, "%s or %s ", filter, hi->name);
		}
		free(filter);
		filter = tmp;
	    }
	}
	
	asprintf(&tmp, "%s)", filter);
	free(filter);
	filter = tmp;
	
	hash_destroy(seen);
	
	break;
    }
    
    for (l = L3; l <= L4; l++)
	free(layers[l]);

    return filter;
}

#if 0
/*
 * This was my first attempt to write the metadesc_determine_filter.
 * It turns out that this function does the correct work, however it's too
 * generic and provides a filter string also for layer COMO and layer 2
 * which are not needed because after the matching of metadescs the core is
 * already able to determine the compatability between sniffers and source
 * modules with consumer modules.
 */
char *
metadesc_determine_filter(metadesc_t *md)
{
    int *layers[5];
    int l;
    uint32_t tpc;
    metatpl_t *tplit;
    pkt_t *pkt;
    char *filter, *tmp;
    int filter_initialized = 0;
    
    layers[0] = NULL;
    
    for (l = LCOMO; l <= L4; l++)
	layers[l] = safe_calloc(md->_tpl_count, sizeof(int));
    
    /*
     * Iterate over the template list and keep the information of used
     * l*types. If the type NONE or ANY is used then write -1 in the first
     * element of layers array.
     */
    for (tplit = md->_first_tpl, tpc = 0; tplit != NULL;
	 tplit = tplit->_next, tpc++) {
	
	assert(tpc < md->_tpl_count);
	
	pkt = &tplit->tpl;
	
	if (COMO(type) == COMOTYPE_NONE || COMO(type) == COMOTYPE_ANY) {
	    layers[LCOMO][0] = -1;
	} else {
	    layers[LCOMO][tpc] = COMO(type);
	}
	if (COMO(l2type) == LINKTYPE_NONE || COMO(l2type) == LINKTYPE_ANY) {
	    layers[L2][0] = -1;
	} else {
	    layers[L2][tpc] = COMO(l2type);
	}
	if (COMO(l3type) == L3TYPE_NONE || COMO(l3type) == L3TYPE_ANY) {
	    layers[L3][0] = -1;
	} else {
	    layers[L3][tpc] = COMO(l3type);
	}
	if (COMO(l4type) == L4TYPE_NONE || COMO(l4type) == L4TYPE_ANY) {
	    layers[L4][0] = -1;
	} else {
	    layers[L4][tpc] = COMO(l4type);
	}
    }
    
    for (l = LCOMO; l <= L4; l++) {
    	hash_t *seen;
	if (layers[l][0] == -1) continue;
	
	seen = hash_new(NULL, HASHKEYS_POINTER, NULL, NULL);
	
	if (filter_initialized == 0) {
	    asprintf(&filter, "myfilter: (");
	    filter_initialized = 1;
	} else {
	    asprintf(&tmp, "%s and (", filter);
	    free(filter);
	    filter = tmp;
	}
	
	for (tpc = 0; tpc < md->_tpl_count; tpc++) {
	    const headerinfo_t *hi;
	    
	    hi = headerinfo_lookup_with_type_and_layer(layers[l][tpc], l);
	    
	    assert(hi);
	    
	    if (hash_insert(seen, (void *) hi, (void *) 1)) {
		/* This is the first insertion in hash */
		if (tpc == 0) {
		    asprintf(&tmp, "%s %s ", filter, hi->name);
		} else {
		    asprintf(&tmp, "%s or %s ", filter, hi->name);
		}
		free(filter);
		filter = tmp;
	    }
	}
	
	asprintf(&tmp, "%s)", filter);
	free(filter);
	filter = tmp;
	
	hash_destroy(seen);
    }
    
    for (l = LCOMO; l <= L4; l++)
	free(layers[l]);

    return filter;
}
#endif

#if 0
void
test_metadesc()
{
    metadesc_t *indesc1, *outdesc1;
    metadesc_match_t b;
    metadesc_incompatibility_t *incomps;
    int incomps_count;
    int mc;
    pkt_t *pkt;
    char *filter;
    
    indesc1 = metadesc_list_new(NULL, 0);
    
    pkt = metadesc_tpl_add(indesc1, "any:any:ip:tcp");
    assert(COMO(type) == COMOTYPE_ANY);
    assert(COMO(l2type) == LINKTYPE_ANY);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == IPPROTO_TCP);
    assert(COMO(caplen) == 0);
    
    pkt = metadesc_tpl_add(indesc1, "any:any:ip:~udp");
    assert(COMO(type) == COMOTYPE_ANY);
    assert(COMO(l2type) == LINKTYPE_ANY);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == IPPROTO_UDP);
    assert(COMO(caplen) == sizeof(struct _como_udphdr));
    assert(COMO(l4ofs) == 0);
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    indesc1 = metadesc_list_new(indesc1, 0);
    
    pkt = metadesc_tpl_add(indesc1, "sflow:eth:ip:any");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_ETH);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == L4TYPE_ANY);
    assert(COMO(caplen) == 0);
    
    pkt = metadesc_tpl_add(indesc1, "sflow:none:~ip:~tcp");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_NONE);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == IPPROTO_TCP);
    assert(COMO(caplen) == sizeof(struct _como_iphdr) +
			   sizeof(struct _como_tcphdr));
    N32(IP(src_ip)) = 0xffffff00;
    N32(IP(dst_ip)) = 0xffffff00;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    TCP(cwr) = 1;
    TCP(ece) = 1;
    TCP(urg) = 1;
    TCP(ack) = 1;
    TCP(psh) = 1;
    TCP(rst) = 1;
    TCP(syn) = 1;
    TCP(fin) = 1;
    
    outdesc1 = metadesc_list_new(NULL, 0);
    
    pkt = metadesc_tpl_add(outdesc1, "sflow:none:~ip:~tcp");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_NONE);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == IPPROTO_TCP);
    assert(COMO(caplen) == sizeof(struct _como_iphdr) +
			   sizeof(struct _como_tcphdr));
    IP(tos) = 0xff;
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffff00;
    N32(IP(dst_ip)) = 0xffffff00;
    N16(TCP(src_port)) = 0xffff;
    N16(TCP(dst_port)) = 0xffff;
    TCP(cwr) = 1;
    TCP(ece) = 1;
    TCP(urg) = 1;
    TCP(ack) = 1;
    TCP(psh) = 1;
    TCP(rst) = 1;
    TCP(syn) = 1;
    TCP(fin) = 1;
    
    pkt = metadesc_tpl_add(outdesc1, "sflow:none:~ip:~udp");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_NONE);
    assert(COMO(l3type) == ETHERTYPE_IP);
    assert(COMO(l4type) == IPPROTO_UDP);
    assert(COMO(caplen) == sizeof(struct _como_iphdr) +
			   sizeof(struct _como_udphdr));
    IP(tos) = 0xff;
    N16(IP(len)) = 0xffff;
    IP(proto) = 0xff;
    N32(IP(src_ip)) = 0xffffff00;
    N32(IP(dst_ip)) = 0xffffff00;
    N16(UDP(src_port)) = 0xffff;
    N16(UDP(dst_port)) = 0xffff;
    
    outdesc1 = metadesc_list_new(outdesc1, 0);
    
    pkt = metadesc_tpl_add(outdesc1, "sflow:eth:none:none");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_ETH);
    assert(COMO(l3type) == L3TYPE_NONE);
    assert(COMO(l4type) == L4TYPE_NONE);
    assert(COMO(caplen) == 0);
    
    outdesc1 = metadesc_list_new(outdesc1, 0);
    
    pkt = metadesc_tpl_add(outdesc1, "sflow:any:any:any");
    assert(COMO(type) == COMOTYPE_SFLOW);
    assert(COMO(l2type) == LINKTYPE_ANY);
    assert(COMO(l3type) == L3TYPE_ANY);
    assert(COMO(l4type) == L4TYPE_ANY);
    assert(COMO(caplen) == 0);
    
    mc = metadesc_best_match(outdesc1, indesc1, &b, &incomps, &incomps_count);
    printf("matches %d\n", mc);
    
    filter = metadesc_determine_filter(indesc1);
    printf("%s\n", filter);
    free(filter);
    
    filter = metadesc_determine_filter(indesc1->_next);
    printf("%s\n", filter);
    free(filter);

    exit(0);
}
#endif
