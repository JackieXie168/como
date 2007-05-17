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
 * $Id: config.c 1138 2007-05-03 14:15:53Z jsanjuas $
 */

#include <unistd.h> /* getopt */
#include <stdlib.h> /* atoll */

#include "como.h"
#include "comopriv.h"

#define USAGE \
    "usage: %s [-c config-file] [-D db-path] [-L libdir] [-p query-port] " \
    "[-m mem-size] [-v logflags] " \
    "[-s sniffer[:device[:\"args\"]]] [module[:\"module args\"] " \
    "[filter]]\n"

void
define_sniffer(char *name, char *device, UNUSED char *args, como_config_t *cfg)
{
    sniffer_def_t sniff;

    sniff.name = name;
    sniff.device = device;
    sniff.args = NULL;

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
    bzero(mdl, sizeof(mdl));
    mdl->args = hash_new(alc, HASHKEYS_STRING, NULL, NULL);
    mdl->streamsize = 128 * 1024 * 1024;
    mdl->filter = como_strdup("all");
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

    array_add(cfg->mdl_defs, mdl);
}

static void
convert(int64_t value, char *buffer, int conv)
{
    if (! conv || value < 1024)
        sprintf(buffer, "%lld", value);
    else if (value >= 1024 * 1024 * 1024)
        sprintf(buffer, "%lldGB", value / (1024 * 1024 * 1024));
    else if (value >= 1024 * 1024)
        sprintf(buffer, "%lldMB", value / (1024 * 1024));
    else
        sprintf(buffer, "%lldKB", value / 1024);
}

static int64_t
sanitize_value(char *what, int64_t value, int64_t min, int64_t max,
        int conv, int isfatal)
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

        if (value < min) {
            warn("increasing to %s\n", bmin);
            return min;
        }
        else {
            warn("decreasing to %s\n", bmax);
            return min;
        }
    }
    return value;
}

#define B2MB(x) ((x) * 1024 * 1024)

#define NOTFATAL 0
#define FATAL 1

#define DONTCONVERT 0
#define CONVERT 1

/*
 * -- set_filesize
 */
void
set_filesize(int64_t size, como_config_t *cfg)
{
    cfg->filesize = sanitize_value("filesize", size, B2MB(128), B2MB(1024),
            CONVERT, NOTFATAL);
}

/*
 * -- set_queryport
 */
void
set_queryport(int64_t port, como_config_t *cfg)
{
    cfg->query_port = sanitize_value("query port", port, 1, 65535, DONTCONVERT,
            FATAL);
}

/*
 * -- set_memsize
 */
void
set_memsize(int64_t size, como_config_t *cfg)
{
    cfg->shmem_size = sanitize_value("memsize", size, B2MB(16), B2MB(1024),
            CONVERT, FATAL);
}

/*
 * -- configure
 *
 * Parse the command line and config files.
 */
como_config_t *
configure(int argc, char **argv, alc_t *alc, como_config_t *cfg)
{
    static const char *opts = "hc:D:L:p:m:v:x:s:e";
    int i, c, cfg_file_count = 0;
    #define MAX_CFGFILES 1024
    char *cfg_files[MAX_CFGFILES];

    bzero(cfg, sizeof(como_config_t));
    cfg->mdl_defs = array_new(sizeof(mdl_def_t));
    cfg->sniffer_defs = array_new(sizeof(sniffer_def_t));

    /*
     * set some defaults
     */
    /* XXX conflict with como_env stuff in libcomo/como.c */
    cfg->query_port = 44444;
    set_memsize(B2MB(64), cfg);
    cfg->db_path = "/tmp/como-data";
    cfg->filesize = 128 * 1024 * 1024;
    cfg->libdir = DEFAULT_LIBDIR;

    while ((c = getopt(argc, argv, opts)) != -1) {
        switch(c) {
        case 'h':
            msg(USAGE, argv[0]);
            exit(0);

	case 'e':
	    cfg->exit_when_done = 1;
	    break;

        case 'c': /* parse a config file */
            if (cfg_file_count >= MAX_CFGFILES)
                error("too many config files\n");
            cfg_files[cfg_file_count++] = optarg;
	    break;

	case 'D':	/* db-path */
	    cfg->db_path = optarg;
	    break;

	case 'L':	/* libdir */
	    cfg->libdir = optarg;
	    break;

	case 'p':
            set_queryport(atoll(optarg), cfg);
	    break;

        case 's':    /* sniffer */
        {
            char *name, *device, *args;

            name = como_strdup(strtok(optarg, ":"));
            device = como_strdup(strtok(NULL, ":"));
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

#if 0
        case 'v':   /* verbose */
	    if (m->logflags == -1)
		m->logflags = 0;
            m->logflags = set_flags(m->logflags, optarg);
            break;
#endif

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

    for (i = 0; i < cfg_file_count; i++) /* parse config files here */
        parse_config_file(cfg_files[i], alc, cfg);

    if (cfg_file_count == 0) /* no cfg files given, try using the default */
        parse_config_file(DEFAULT_CFGFILE, alc, cfg);

    while (optind < argc) { /* module definitions follow */
        warn("TODO: specify modules in cmdline (%s)\n", argv[optind]);
        optind++;
    }

    return cfg;
}

