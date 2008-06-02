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
 * $Id$
 */

/*
 * Query parsing for CoMo
 */
 
%{
#include <strings.h> /* bzero */

#define LOG_DOMAIN "QUERY"
#include "como.h"
#include "comopriv.h"

/* #define YYDEBUG 1 */

#ifdef YYDEBUG
#define YYFPRINTF parser_debug

#define parser_debug(a, b...) do_parser_debug(b)

static void
do_parser_debug(char *fmt, ...)
{ 
    va_list ap;
    char msg[2048];
    
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    warn("query parser dbg: %s\n", msg);
}
#define YYERROR_VERBOSE
#endif

int yqlex(void);
void yqerror(char *fmt, ...);

/* global variables */

char *input_string;
query_ast_t ast;

%}

%union {
    char *string;
}

/* Data types and tokens used by the parser */

%token TOK_GET TOK_SLASH TOK_AMP TOK_QMARK TOK_EQUALS TOK_SPACE TOK_HTTPVER
%token <string> TOK_STRING

%type <string> fullpath
%type <string> relpath
%type <string> value

%start query

%%

query:
    TOK_GET blanks fullpath arglist blanks TOK_HTTPVER {
            ast.resource = $3;
        }
    ;

blanks: blanks TOK_SPACE | TOK_SPACE;

fullpath:
    slashes relpath {
            $$ = safe_asprintf("/%s", $2);
            free($2);
        }
    | slashes {
            $$ = safe_asprintf("/");
        }
    ;

relpath:
    relpath slashes TOK_STRING {
            $$ = safe_asprintf("%s/%s", $1, $3);
            free($1);
            free($3);
        }
    | TOK_STRING {
            $$ = $1;
        }
    ;

slashes: slashes TOK_SLASH | TOK_SLASH

/* if we have a question mark, we want arguments */
arglist: TOK_QMARK inside_arglist |;

/* after a question mark we want at least one key=value pair,
 * optionally followed by many &key=value sequences.
 */
inside_arglist: keyvalue | keyvalue TOK_AMP inside_arglist;

/* XXX that would be the easiest: 
     keyvalue: TOK_STRING TOK_EQUALS TOK_STRING;
   but we want to support CoMoLive!, which may feed args
   which are in the form ?key=value=that=may=include=TOK_EUALS&key2=...
 */

keyvalue:
    TOK_STRING TOK_EQUALS value {
            ast.keyvals[ast.nkeyvals].key = $1;
            ast.keyvals[ast.nkeyvals].val = $3;
            ast.nkeyvals++;
        }
    | TOK_STRING TOK_EQUALS { /* value is not there */
            ast.keyvals[ast.nkeyvals].key = $1;
            ast.keyvals[ast.nkeyvals].val = safe_strdup("");
            ast.nkeyvals++;
        }
    | TOK_STRING {
            ast.keyvals[ast.nkeyvals].key = $1;
            ast.keyvals[ast.nkeyvals].val = safe_strdup("");
            ast.nkeyvals++;
        }
    | { /* tolerate missing key=val */ }
    ;

value:
    TOK_STRING {
            $$ = $1;
        }
    | value TOK_EQUALS TOK_STRING {
            $$ = safe_asprintf("%s=%s", $1, $3);
            free($1);
            free($3);
        }
    ;

%%

#include "query-lexic.c"

void yqerror(char *fmt, ...)
{ 
    //extern int ycline;
    va_list ap;
    char error[255];
    
    va_start(ap, fmt);
    vsnprintf(error, sizeof(error), fmt, ap);
    warn("Query parser error: %s\n", error);
    va_end(ap);
}

query_ast_t *
parse_query_str(char *query_string)
{
    char *str;
    int i, ret;

    #ifdef YYDEBUG
    #if YYDEBUG == 1
    yydebug = 1;
    #endif
    #endif

    bzero(&ast, sizeof(ast));

    /* terminate string at end of 1st line */
    str = strchr(query_string, '\n');
    if (str)
        *str = '\0';
    str = strchr(query_string, '\r');
    if (str)
        *str = '\0';

    input_string = query_string;

    debug("PARSING len = %d '%s'\n", strlen(query_string), query_string);
    yq_scan_string(query_string);
    ret = yqparse();
    debug("Query parsed. resource = %s\n", ast.resource);
    for (i = 0; i < ast.nkeyvals; i++)
        debug("\targ #%d: '%s' => '%s'\n", i, ast.keyvals[i].key,
            ast.keyvals[i].val);

    if (ret)
        return NULL;
    return &ast;
}
