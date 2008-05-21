/*
 * Copyright (c) 2007, Universitat Politecnica de Catalunya
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

#include <unistd.h> /* getopt */
#include <stdlib.h> /* atoll */

#include "como.h"
#include "comopriv.h"

#define USAGE \
    "usage: %s [-c config-file] [-c config-string] " \
    "[-D db-path] [-L libdir] [-p query-port] " \
    "[-m mem-size] [-v logflags] [-i inline-module] [-S] [-t path_to_storage] "\
    "[-s sniffer[,device[,\"args\"]]] [module[:arg1=value1,arg2=value2..] " \
    "[-q queryarg1=value1,arg2=value2..] "\
    "[filter]]\n"

void
define_sniffer(char *name, char *device, char *args, como_config_t *cfg)
{
    sniffer_def_t sniff;

    sniff.name = name;
    sniff.device = device;
    sniff.args = args;

    array_add(cfg->sniffer_defs, &sniff);
}

/*
 * -- initialize_module_def
 *
 * Initialize a module definition with the default
 * values.
 */
void
initialize_module_def(mdl_def_t *mdl, alc_t *alc)
{
    bzero(mdl, sizeof(mdl_def_t));
    mdl->args = hash_new(alc, HASHKEYS_STRING, NULL, NULL);
    mdl->streamsize = 128 * 1024 * 1024;
    mdl->filter = como_strdup("all");
#ifdef LOADSHED
    mdl->minimum_srate = 0;
#endif
}

static void
destroy_sniffer_def(sniffer_def_t *d, alc_t *alc)
{
    alc_free(alc, d->name);
    alc_free(alc, d->device);
    if (d->args)
        alc_free(alc, d->args);
}

void
initialize_virtual_node_def(virtual_node_def_t *vnode, UNUSED alc_t *alc)
{
    bzero(vnode, sizeof(virtual_node_def_t));
}

void
define_virtual_node(virtual_node_def_t *vnode, UNUSED como_config_t *cfg,
                    alc_t *alc)
{
    int ok = 1;

    #define complain(x) warn("virtual node `%s': " x "\n", vnode->name, x)

    /* check that mandatory fields are there */
    if (vnode->location == NULL) {
        complain("location not defined");
        ok = 0;
    }
    if (vnode->type == NULL) {
        complain("type not defined");
        ok = 0;
    }
    if (vnode->filter == NULL) {
        complain("filter not defined");
        ok = 0;
    }
    if (vnode->query_port == 0) {
        complain("query port not defined");
        ok = 0;
    }
    if (vnode->source == NULL) {
        complain("source not defined");
        ok = 0;
    }

    #undef complain
    
    /* if not ok, output error notice and return */
    if (ok == 0) {
        warn("(ignoring virtual node definition)\n");
        destroy_virtual_node_def(vnode, alc);
        return;
    }

    /* everything ok, add virtual node definition */
    array_add(cfg->vnode_defs, vnode);
}

void
destroy_virtual_node_def(virtual_node_def_t *vnode, alc_t *alc)
{
    alc_free(alc, vnode->name);
    alc_free(alc, vnode->location);
    alc_free(alc, vnode->type);
    alc_free(alc, vnode->filter);
    alc_free(alc, vnode->source);
}

static void
free_hash_entries(hash_t *h, alc_t *alc)
{
    hash_iter_t it;

    hash_iter_init(h, &it); /* destroy the args */
    while(hash_iter_next(&it)) {
        alc_free(alc, (void *)hash_iter_get_string_key(&it));
        alc_free(alc, (void *)hash_iter_get_value(&it));
        hash_iter_remove_entry(&it);
    }
}

static void
destroy_module_def(mdl_def_t *d, alc_t *alc)
{
    free_hash_entries(d->args, alc);
    hash_destroy(d->args);
    
    alc_free(alc, d->name);
    alc_free(alc, d->mdlname);
    alc_free(alc, d->output);
    alc_free(alc, d->filter);
    alc_free(alc, d->descr);
    #ifdef LOADSHED
    alc_free(alc, d->shed_method);
    #endif
}

/*
 * -- define_module
 *
 * Check a module definition, fix whatever needed, add it to the cfg.
 */
void
define_module(mdl_def_t *mdl, como_config_t *cfg)
{
    if (mdl->output == NULL)
        mdl->output = como_strdup(mdl->name);
    if (mdl->mdlname == NULL)
        mdl->mdlname = como_strdup(mdl->name);
    if (mdl->descr == NULL)
        mdl->descr = como_strdup("");
#ifdef LOADSHED
    if (mdl->shed_method == NULL)
        mdl->shed_method = como_strdup("");
#endif

    array_add(cfg->mdl_defs, mdl);
}

/*
 * -- convert
 *
 * print a value into a character string. If conv is not zero,
 * the value is interpreted as an amount of bytes and converted to
 * GB|MB|KB as necessary.
 */
static void
convert(int64_t value, char *buffer, int conv)
{
    if (! conv || value < 1024)
        sprintf(buffer, "%lld%s", value, conv ? "B" : "");
    else if (value >= 1024 * 1024 * 1024)
        sprintf(buffer, "%lldGB", value / (1024 * 1024 * 1024));
    else if (value >= 1024 * 1024)
        sprintf(buffer, "%lldMB", value / (1024 * 1024));
    else
        sprintf(buffer, "%lldKB", value / 1024);
}

/*
 * -- sanitize_value
 *
 * Check that a value is within a range. If it is, just return the value.
 * Otherwise, show an error notice and either die or warn depending on
 * the isfatal flag. If issued a warning, depending on the autoadjust
 * flag either return the closest between min and max, or return zero.
 */
static int64_t
sanitize_value(char *what, int64_t value, int64_t min, int64_t max,
        int conv, int isfatal, int autoadjust)
{
    if (value < min || value > max) {
        char bmin[64], bmax[64], bvalue[64];

        convert(min, bmin, conv);
        convert(max, bmax, conv);
        convert(value, bvalue, conv);

        if (isfatal)
            error("%s invalid, value %s must be in range %s-%s.\n",
                    what, bvalue, bmin, bmax);

        warn("%s invalid, value %s must be in range %s-%s.\n",
                what, bvalue, bmin, bmax);

        if (value < min && autoadjust) {
            warn("increasing to %s\n", bmin);
            return min;
        }
        else if (value > max && autoadjust) {
            warn("decreasing to %s\n", bmax);
            return max;
        }
        else
            return 0;
    }
    return value;
}

#define B2MB(x) ((x) * 1024 * 1024)

#define NOTFATAL 0
#define FATAL 1

#define DONTCONVERT 0
#define CONVERT 1

#define DONTAUTOADJUST 0
#define AUTOADJUST 1

/*
 * -- set_filesize
 */
void
set_filesize(int64_t size, como_config_t *cfg)
{
    cfg->filesize = sanitize_value("filesize", size, B2MB(128), B2MB(1024),
            CONVERT, NOTFATAL, AUTOADJUST);
}

#define sanitize_query_port(fatal, adjust)  \
    sanitize_value("query port", port, 1, 65535, DONTCONVERT, fatal, adjust)

/*
 * -- set_queryport
 */
void
set_queryport(int64_t port, como_config_t *cfg)
{
    cfg->query_port = sanitize_query_port(FATAL, DONTAUTOADJUST);
}

/*
 * -- set_vnode_queryport
 */
void
set_vnode_queryport(int64_t port, virtual_node_def_t *vnode)
{
    vnode->query_port = sanitize_query_port(NOTFATAL, DONTAUTOADJUST);
}

/*
 * -- set_memsize
 */
void
set_memsize(int64_t size, como_config_t *cfg)
{
    cfg->shmem_size = sanitize_value("memsize", size, B2MB(16), B2MB(1024),
            CONVERT, FATAL, AUTOADJUST);
}

enum {
    CFG_ITEM_STRING,
    CFG_ITEM_FILE
};

typedef struct cfg_item cfg_item_t;
struct cfg_item {
    int type;
    char *info;
};

/*
 * -- configure
 *
 * Parse the command line and config files.
 */
como_config_t *
configure(int argc, char **argv, alc_t *alc, como_config_t *cfg)
{
    static const char *opts = "hi:St:q:c:C:D:L:p:m:vx:s:e";
    int i, c, cfg_item_count = 0;
    #define MAX_CFGITEMS 1024
    cfg_item_t cfg_items[MAX_CFGITEMS];

    bzero(cfg, sizeof(como_config_t));
    cfg->mdl_defs = array_new(sizeof(mdl_def_t));
    cfg->sniffer_defs = array_new(sizeof(sniffer_def_t));
    cfg->vnode_defs = array_new(sizeof(virtual_node_def_t));

    cfg->como_executable_full_path = como_strdup(argv[0]);

    /*
     * set some defaults
     */
    cfg->query_port = 44444;
    set_memsize(B2MB(64), cfg);
    cfg->db_path = como_strdup(DEFAULT_DBDIR);
    cfg->filesize = 128 * 1024 * 1024;
    cfg->libdir = como_strdup(DEFAULT_LIBDIR);
    cfg->query_args = hash_new(alc, HASHKEYS_STRING, NULL, NULL);
    cfg->query_alias = hash_new(alc, HASHKEYS_STRING, NULL, NULL);

    optind = 1; /* force getopt to start from 1st arg */

    while ((c = getopt(argc, argv, opts)) != -1) {
        switch(c) {
        case 'h':
            printf(USAGE, argv[0]);
            exit(0);

	case 'e':
	    cfg->exit_when_done = 1;
	    break;

        case 'c': /* parse a config file */
            if (cfg_item_count >= MAX_CFGITEMS)
                error("too many config files / strings\n");
            cfg_items[cfg_item_count].type = CFG_ITEM_FILE;
            cfg_items[cfg_item_count].info = optarg;
            cfg_item_count++;
	    break;

        case 'C': /* string to be parsed as if it were in a cfgfile */
            if (cfg_item_count >= MAX_CFGITEMS)
                error("too many config files / strings\n");
            cfg_items[cfg_item_count].type = CFG_ITEM_STRING;
            cfg_items[cfg_item_count].info = optarg;
            cfg_item_count++;
            break; 

	case 'D':	/* db-path */
	    cfg->db_path = como_strdup(optarg);
	    break;

	case 'L':	/* libdir */
	    cfg->libdir = como_strdup(optarg);
	    break;

	case 'p':
            set_queryport(atoll(optarg), cfg);
	    break;

        case 's':    /* sniffer */
        {
            char *name, *device, *args;

            name = como_strdup(strtok(optarg, ","));
            device = como_strdup(strtok(NULL, ","));
            args = como_strdup(strtok(NULL, ""));

            if (name && device)
                define_sniffer(name, device, args, cfg);
            else
                error("Unable to parse sniffer definition `%s'\n", optarg);

            break;
        }

        case 'm':   /* capture/export memory usage */
	    set_memsize(atoi(optarg), cfg);
	    break;

        case 'v':   /* verbose */
        #if 0
	    if (m->logflags == -1)
		m->logflags = 0;
            m->logflags = set_flags(m->logflags, optarg);
        #endif
            cfg->silent_mode = 0;
            break;

        case 'i': /* run inline: also silent & exit when done */
            cfg->inline_mode = 1;
            cfg->inline_module = como_strdup(optarg);
            cfg->silent_mode = 1;
            cfg->exit_when_done = 1;
            break;

        case 'S': /* silent mode */
            cfg->silent_mode = 1;
            break;

        case 'q': { /* query args for inline mode */
            char *str, *strbak;
            strbak = str = como_strdup(optarg);

            while (str != NULL) {
                char *k, *v;
                char *s1 = strchr(str, '=');
                char *s2 = strchr(str, ',');

                if (s1 == NULL || (s2 && s2 < s1))
                    error("Unable to parse query arguments `%s'\n", str);

                k = str;
                *s1 = '\0';
                v = s1 + 1;

                if (s2 == NULL)
                    str = NULL;
                else {
                    *s2 = '\0';
                    str = s2 + 1;
                }

                hash_insert_string(cfg->query_args, como_strdup(k),
                    como_strdup(v));
            }

            free(strbak);
            break;
        }

        case 't':   /* path to storage */
            cfg->storage_path = como_strdup(optarg);
            break;

        case '?':   /* unknown */
            error("unrecognized cmdline option (%s)\n\n" USAGE "\n",
                    argv[optind], argv[0]);

        case ':':   /* missing argument */
            error("missing argument for option (%s)\n", argv[optind]);
            break;

        default:    /* should never get here... */
            error(USAGE, argv[0]);
        }
    }

    /*
     * no cfg given, neither cfg files or strings.
     * try using the default cfg file.
     */
    if (cfg_item_count == 0) {
        cfg_items[cfg_item_count].type = CFG_ITEM_FILE;
        cfg_items[cfg_item_count].info = DEFAULT_CFGFILE;
        cfg_item_count++;
    }

    for (i = 0; i < cfg_item_count; i++) { /* parse config items here */
        switch (cfg_items[i].type) {
            case CFG_ITEM_FILE:
                parse_config_file(cfg_items[i].info, alc, cfg);
                break;
            case CFG_ITEM_STRING:
                parse_config_string(cfg_items[i].info, alc, cfg);
                break;
        }
    }

    while (optind < argc) { /* module definitions follow */
        char *args = NULL, *buf, *s;
        mdl_def_t mdl;

        bzero(&mdl, sizeof(mdl));

        buf = como_strdup(argv[optind]);

        s = strchr(buf, ':');
        if (s != NULL) {
            *s = '\0';
            args = s + 1;
        }

        initialize_module_def(&mdl, alc);
        mdl.name = como_strdup(buf);

        while (args != NULL) { /* parse the arguments */
            char *s1, *s2;

            s1 = strchr(args, '=');
            s2 = strchr(args, ',');

            /* no '=', or ',' before '=' */
            if (s1 == NULL || (s2 != NULL && s2 < s1))
                error("parse error in cmdline args for module `%s'. Expected "
                    "key1=value1,key2=value2..\n", mdl.name);
            
            *s1 = '\0'; /* null-terminate key. value resides at s1 + 1 */
            if (s2 != NULL)
                *s2 = '\0'; /* null-terminate value */

            hash_insert_string(mdl.args, como_strdup(args),
                                como_strdup(s1 + 1));
	
	    if (s2)	
	    	args = s2 + 1;
	    else
	        args = NULL;
        }

        define_module(&mdl, cfg);
        free(buf);
        optind++;
    }

    /*
     * TODO
     * - module names should be unique.
     * - no alias should collide with a real module name.
     */

    /*
     * final configuration tweak: if we are running in inline mode,
     * discard all module definitions but the interesting one.
     */
    if (cfg->inline_mode) {
        array_t *new_mdl_defs = array_new(sizeof(mdl_def_t));
        char *name, *realname, *tmp;
    
        name = strdup(cfg->inline_module);
        tmp = strchr(name, '?');
        if (tmp != NULL)
            *tmp = '\0';

        realname = config_resolve_alias(cfg, name);

        for (i = 0; i < cfg->mdl_defs->len; i++) {
            mdl_def_t *d = &array_at(cfg->mdl_defs, mdl_def_t, i);

            if (strcmp(d->name, realname) == 0) {
                array_add(new_mdl_defs, d);
                break;
            }
        }

        if (i == cfg->mdl_defs->len)
            error("inline module `%s' not found in config\n",
                    cfg->inline_module);

        cfg->mdl_defs = new_mdl_defs;
        free(name);
    }

    /* TODO extensive checking to remove all small mem leaks */

    return cfg;
}

/*
 * -- config_resolve_alias
 *
 * Get the real name of a module according to a configuration,
 * following aliases if any.
 */
char *
config_resolve_alias(como_config_t *cfg, char *name)
{
    char *aliased = hash_lookup_string(cfg->query_alias, name);

    if (aliased != NULL)
        return aliased;

    return name;
}

/*
 * -- config_get_module_def_by_name
 *
 * Search the module definitions in a config_t by name.
 */
mdl_def_t *
config_get_module_def_by_name(como_config_t *cfg, char *name)
{
    char *real_name;
    int i;

    real_name = config_resolve_alias(cfg, name);

    /*
     * search the on-demand module in the module definitions
     */
    for (i = 0; i < cfg->mdl_defs->len; i++) {
        mdl_def_t *def = &array_at(cfg->mdl_defs, mdl_def_t, i);

        if (! strcmp(def->name, real_name))
            return def;
    }

    return NULL;
}

/*
 * -- destroy_config
 *
 * Free a configuration.
 */
void
destroy_config(como_config_t *cfg, alc_t *alc)
{
    int i;

    for (i = 0; i < cfg->sniffer_defs->len; i++) { /* free sniff defs */
        sniffer_def_t *def = &array_at(cfg->sniffer_defs, sniffer_def_t, i);
        destroy_sniffer_def(def, alc);
    }

    for (i = 0; i < cfg->mdl_defs->len; i++) { /* free mdl defs */
        mdl_def_t *def = &array_at(cfg->mdl_defs, mdl_def_t, i);
        destroy_module_def(def, alc);
    }

    for (i = 0; i < cfg->vnode_defs->len; i++) { /* free vnode defs */
        virtual_node_def_t *def = &array_at(cfg->vnode_defs,
                virtual_node_def_t, i);
        destroy_virtual_node_def(def, alc);
    }

    array_free(cfg->sniffer_defs, 1); /* free the arrays themselves */
    array_free(cfg->mdl_defs, 1);
    array_free(cfg->vnode_defs, 1);

    free(cfg->como_executable_full_path); /* free strings */
    free(cfg->storage_path);
    free(cfg->mono_path);
    free(cfg->db_path);
    free(cfg->libdir);
    free(cfg->asn_file);
    free(cfg->name);
    free(cfg->location);
    free(cfg->type);
    free(cfg->comment);

    free(cfg->inline_module);

    free_hash_entries(cfg->query_args, alc);
    hash_destroy(cfg->query_args);
    free_hash_entries(cfg->query_alias, alc);
    hash_destroy(cfg->query_alias);
}

