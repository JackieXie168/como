/*
 * Copyright (c) 2007, Universitat Politecnica de Catalunya
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
 * $Id: filter-syntax.y 1096 2006-11-27 16:42:10Z rnc1 $
 */

/*
 * Config parsing for CoMo
 */
 
%{
#define YYDEBUG 1
#define YYFPRINTF fwarn

#include <strings.h> /* bzero */

#define LOG_DOMAIN "CONFIG"
#include "como.h"
#include "comopriv.h"

#define fwarn(a, b...) warn(b)

#define YYERROR_VERBOSE

struct _listnode
{
    char *string;
    struct _listnode *next;
    struct _listnode *prev;
};
typedef struct _listnode listnode_t;

int yclex(void);
void ycerror(char *fmt, ...);

/* global variables */
alc_t *alc;
static mdl_def_t mdl;
static como_config_t cfg; /* result */

void
define_sniffer(char *name, char *device, UNUSED char *args)
{
    sniffer_def_t sniff;

    sniff.name = name;
    sniff.device = device;
    sniff.args = NULL;

    array_add(cfg.sniffer_defs, &sniff);
}

void
report_parse_error(void)
{
    extern int ycline;

    warn("parse error at line %d. Ignoring until end of line.\n",
            ycline - 1 /* (we already got a newline) */);
}

%}

%union {
    char *string;
    int64_t number;
}

/* Data types and tokens used by the parser */

%token TOK_DBPATH TOK_LIBDIR TOK_MEMSIZE TOK_QUERY_PORT TOK_NAME TOK_LOCATION
%token TOK_TYPE TOK_COMMENT TOK_SNIFFER TOK_FILESIZE TOK_MODULE TOK_DESCRIPTION
%token TOK_SOURCE TOK_OUTPUT TOK_FILTER TOK_HASHSIZE TOK_STREAMSIZE TOK_ARGS
%token TOK_ARGSFILE TOK_RUNNING TOK_END TOK_NEWLINE
%token <string> TOK_STRING
%token <number> TOK_NUMBER

%start config

%%

config: config item | item;
item:
      TOK_NEWLINE
    | keyword TOK_NEWLINE
    | sniffer_def
    | module_def
    | error TOK_NEWLINE { report_parse_error(); }
;

keyword: /* a global keyword */
      TOK_DBPATH TOK_STRING { cfg.db_path = $2; }
    | TOK_LIBDIR TOK_STRING { cfg.libdir = $2; }
    | TOK_MEMSIZE TOK_NUMBER { cfg.shmem_size = $2; }

    | TOK_NAME TOK_STRING { cfg.name = $2; }
    | TOK_LOCATION TOK_STRING { cfg.location = $2; }
    | TOK_TYPE TOK_STRING { cfg.type = $2; }
    | TOK_COMMENT TOK_STRING { cfg.comment = $2; }

    | TOK_FILESIZE TOK_NUMBER {
        if ($2 < 0 || $2 >= 1 * 1024 * 1024 * 1024) {
            warn("filesize %d invalid, must be in range 0-1GB\n", $2);
        }
        cfg.filesize = $2;
    }

    | TOK_QUERY_PORT TOK_NUMBER {
        if ($2 < 0 || $2 >= 65536) {
            error("query port %d invalid, must be in range 0-65535\n", $2);
        }
        cfg.query_port = $2;
    }
;

sniffer_def: /* the definition of a sniffer */
    TOK_SNIFFER TOK_STRING TOK_STRING TOK_NEWLINE {
        /* sniffer + type + iface/filename */
        define_sniffer($2, $3, NULL);
    }
    | TOK_SNIFFER TOK_STRING TOK_STRING TOK_STRING TOK_NEWLINE {
        /* same plus options */
        define_sniffer($2, $3, $4);
    }
;

module_def:
    TOK_MODULE {
        /* initialize the defn */
        bzero(&mdl, sizeof(mdl));
        mdl.args = hash_new(alc, HASHKEYS_STRING, NULL, NULL);
    }
    TOK_STRING TOK_NEWLINE
    optional_module_keywords
    TOK_END TOK_NEWLINE {
        /* save the module defn */
        mdl.name = $3;
        array_add(cfg.mdl_defs, &mdl);
    }
;

optional_module_keywords: | module_keywords;
module_keywords: module_keywords module_keyword | module_keyword;

module_keyword:
      TOK_NEWLINE
    | TOK_ARGS args_list TOK_NEWLINE
    | TOK_SOURCE TOK_STRING TOK_NEWLINE      { mdl.mdlname = $2; }
    | TOK_OUTPUT TOK_STRING TOK_NEWLINE      { mdl.output = $2; }
    | TOK_DESCRIPTION TOK_STRING TOK_NEWLINE { mdl.descr = $2; }
    | TOK_FILTER TOK_STRING TOK_NEWLINE      { mdl.filter = $2; }
    | TOK_HASHSIZE TOK_NUMBER TOK_NEWLINE    { mdl.hashsize = $2; }
    | TOK_STREAMSIZE TOK_NUMBER TOK_NEWLINE  { mdl.streamsize = $2; }
    /*| TOK_ARGSFILE TOK_STRING (TODO) */
    /*| TOK_RUNNING TOK_STRING (TODO) */
    | error TOK_NEWLINE { report_parse_error(); }
;

args_list: args_list TOK_STRING | TOK_STRING;

%%

#include "config-lexic.c"

void ycerror(char *fmt, ...)
{ 
    extern int ycline;
    va_list ap;
    char error[255];
    
    va_start(ap, fmt);
    vsnprintf(error, sizeof(error), fmt, ap);
    warn("Config parser error: %s, at line %d\n", error, ycline);
    va_end(ap);
}

como_config_t *
parse_config_file(char *f, alc_t *my_alc)
{
    alc = my_alc;

    bzero(&cfg, sizeof(cfg));

    cfg.mdl_defs = array_new(sizeof(mdl_def_t));
    cfg.sniffer_defs = array_new(sizeof(sniffer_def_t));

    ycin = fopen(f, "r");
    if (ycin == NULL) {
        error("cannot open `%s' for reading\n", f);
    }

    ycparse();
    return &cfg;
}
