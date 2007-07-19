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

int yclex(void);
void ycerror(char *fmt, ...);

void config_lexic_init();

/* global variables */
alc_t *alc;
static mdl_def_t mdl;
static como_config_t *cfg; /* result */

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
%token TOK_ARGSFILE TOK_RUNNING TOK_END TOK_NEWLINE TOK_EQUALS TOK_COMMA
%token TOK_STORAGEPATH TOK_ASNFILE
%token TOK_SHEDMETHOD
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
      TOK_DBPATH TOK_STRING { cfg->db_path = $2; }
    | TOK_LIBDIR TOK_STRING { cfg->libdir = $2; }
    | TOK_STORAGEPATH TOK_STRING { cfg->storage_path = $2; }
    | TOK_MEMSIZE TOK_NUMBER { set_memsize($2, cfg); }
    | TOK_ASNFILE TOK_STRING { cfg->asn_file = $2; }

    | TOK_NAME TOK_STRING { cfg->name = $2; }
    | TOK_LOCATION TOK_STRING { cfg->location = $2; }
    | TOK_TYPE TOK_STRING { cfg->type = $2; }
    | TOK_COMMENT TOK_STRING { cfg->comment = $2; }

    | TOK_FILESIZE TOK_NUMBER { set_filesize($2, cfg); }

    | TOK_QUERY_PORT TOK_NUMBER { set_queryport($2, cfg); }
;

sniffer_def: /* the definition of a sniffer */
    TOK_SNIFFER TOK_STRING TOK_STRING TOK_NEWLINE {
        /* sniffer + type + iface/filename */
        define_sniffer($2, $3, NULL, cfg);
    }
    | TOK_SNIFFER TOK_STRING TOK_STRING TOK_STRING TOK_NEWLINE {
        /* same plus options */
        define_sniffer($2, $3, $4, cfg);
    }
;

module_def:
    TOK_MODULE {
        /* initialize the defn */
        initialize_module_def(&mdl, alc);
    }
    TOK_STRING TOK_NEWLINE
    optional_module_keywords
    TOK_END TOK_NEWLINE {
        /* save the module defn */
        mdl.name = $3;
        define_module(&mdl, cfg);
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
    | TOK_SHEDMETHOD TOK_STRING TOK_NEWLINE    {
                                                #ifdef LOADSHED
                                                mdl.shed_method = $2;
                                                #endif
                                               }
    /*| TOK_ARGSFILE TOK_STRING (TODO) */
    /*| TOK_RUNNING TOK_STRING (TODO) */
    | error TOK_NEWLINE { report_parse_error(); }
;

args_list: args_list TOK_COMMA arg | arg;
arg: TOK_STRING TOK_EQUALS TOK_STRING { hash_insert_string(mdl.args, $1, $3); }

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
parse_config_file(char *f, alc_t *my_alc, como_config_t *my_cfg)
{
    config_lexic_init();

    cfg = my_cfg;
    alc = my_alc;

    ycin = fopen(f, "r");
    if (ycin == NULL) {
        error("cannot open `%s' for reading\n", f);
    }

    ycparse();
    return cfg;
}
