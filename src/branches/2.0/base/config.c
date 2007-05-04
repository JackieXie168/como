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
 * -- define_module
 *
 * Check a module definition, fix whatever needed, add it to the cfg.
 */
void
define_module(mdl_def_t *mdl, como_config_t *cfg)
{
    /* TODO: do the checks here */
    array_add(cfg->mdl_defs, mdl);
}

/*
 * -- set_filesize
 */
void
set_filesize(int64_t size, como_config_t *cfg)
{
    if (size < 0 || size >= 1 * 1024 * 1024 * 1024) {
        warn("filesize %d invalid, must be in range 0-1GB\n", cfg);
        warn("defaulting to 128MB\n");
        size = 128 * 1024 * 1024;
    }

    cfg->filesize = size;
}

/*
 * -- set_queryport
 */
void
set_queryport(int64_t port, como_config_t *cfg)
{
    if (port < 0 || port >= 65536) {
        warn("query port %d invalid, must be in range 0-65535\n", port);
        warn("defaulting to 44444\n");
        port = 44444;
    }

    cfg->query_port = port;
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
    int c, cfg_file_count = 0;
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
    cfg->shmem_size = 64 * 1024 * 1024;
    cfg->db_path = "/tmp/como-data";
    cfg->filesize = 128 * 1024 * 1024;
    cfg->libdir = "";
    alc = alc;

    
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
            parse_config_file(optarg, alc, cfg);
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
	    cfg->shmem_size = atoi(optarg);
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

    while (optind < argc) { /* module definitions follow */
        warn("TODO: specify modules in cmdline (%s)\n", argv[optind]);

        optind++;
    }

    return cfg;
}

