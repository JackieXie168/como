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
 * Config parsing for CoMo - lexical analyzer
 */
%{

/* C Declarations */
#include <stdlib.h> /* atoll */

/* #define DEBUG_A_LOT */

#ifdef DEBUG_A_LOT
#define dbg_return(x) do { debug(#x "\n"); return x; } while(0)
#else
#define dbg_return(x) return x
#endif

#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr;
int ycline;

void config_lexic_init(void)
{
    ycline = 1;
    include_stack_ptr = 0;
}

%}

DIGIT           [0-9]
NUMBER          {DIGIT}+

%option noyywrap
%option nounput

%s comment 
%s import

%%

"/*"                    BEGIN(comment);
<comment>[^*\n]*        /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*   /* eat up '*'s not followed by '/'s */
<comment>\n             ycline++; /* and newlines */
<comment>"*"+"/"        BEGIN(INITIAL);

import              BEGIN(import);
<import>\"[^"]*\"   {
                        char *str;

                        if (include_stack_ptr >= MAX_INCLUDE_DEPTH)
                            error("reading cfg: imports nested too deeply\n");

                        str = safe_strdup(yytext + 1); /* remove "s */
                        str[strlen(str) - 1] = '\0';

                        include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
                        yyin = fopen(str, "r" );
                        if (yyin == NULL)
                            error("reading cfg: cannot open imported " \
                                    "file `%s' for reading\n", str);

                        yy_switch_to_buffer(yy_create_buffer(yyin,YY_BUF_SIZE));

                        BEGIN(INITIAL);
                    }
<import>[ \t]*      /* skip spaces */

db-path         { dbg_return(TOK_DBPATH); }
librarydir      { dbg_return(TOK_LIBDIR); }
memsize         { dbg_return(TOK_MEMSIZE); }
query-port      { dbg_return(TOK_QUERY_PORT); }

name            { dbg_return(TOK_NAME); }
location        { dbg_return(TOK_LOCATION); }
type            { dbg_return(TOK_TYPE); }
comment         { dbg_return(TOK_COMMENT); }
sniffer         { dbg_return(TOK_SNIFFER); }
filesize        { dbg_return(TOK_FILESIZE); }
module          { dbg_return(TOK_MODULE); }
description     { dbg_return(TOK_DESCRIPTION); }
source          { dbg_return(TOK_SOURCE); }
output          { dbg_return(TOK_OUTPUT); }
filter          { dbg_return(TOK_FILTER); }
hashsize        { dbg_return(TOK_HASHSIZE); }
streamsize      { dbg_return(TOK_STREAMSIZE); }
args            { dbg_return(TOK_ARGS); }
on-demand       { dbg_return(TOK_ONDEMAND); }
end             { dbg_return(TOK_END); }
=               { dbg_return(TOK_EQUALS); }
,               { dbg_return(TOK_COMMA); }
asnfile         { dbg_return(TOK_ASNFILE); }
alias           { dbg_return(TOK_ALIAS); }
virtual-node    { dbg_return(TOK_VIRTUAL_NODE); }
source-module   { dbg_return(TOK_SOURCE_MODULE); }

shed-method     { dbg_return(TOK_SHEDMETHOD); }
min_srate       { dbg_return(TOK_MINSRATE); }

"<-"            { dbg_return(TOK_LEFTARROW); }

{DIGIT}*"."{DIGIT}+ {
                        yclval.fpnumber = atof(yytext);
                        dbg_return(TOK_FPNUMBER);
                    }

{DIGIT}+"."{DIGIT}* {
                        yclval.fpnumber = atof(yytext);
                        dbg_return(TOK_FPNUMBER);
                    }
{NUMBER}GB      {
                    yclval.number = atoll(yytext) * 1024 * 1024 * 1024;
                    dbg_return(TOK_NUMBER);
                }
{NUMBER}MB      {
                    yclval.number = atoll(yytext) * 1024 * 1024;
                    dbg_return(TOK_NUMBER);
                }
{NUMBER}KB      {
                    yclval.number = atoll(yytext) * 1024;
                    dbg_return(TOK_NUMBER);
                }
{NUMBER}B       {
                    yclval.number = atoll(yytext);
                    dbg_return(TOK_NUMBER);
                }

{NUMBER}        {
                    yclval.number = atoll(yytext);
                    dbg_return(TOK_NUMBER);
                }

\"[^"]*\"       {   /* string literal */
                    yclval.string = safe_strdup(yytext + 1);
                    yclval.string[strlen(yclval.string) - 1] = '\0';
                    dbg_return(TOK_STRING);
                }
" "

#.*             /* comment til end of line */
\t
\n              {   ycline++; dbg_return(TOK_NEWLINE); }

[a-zA-Z0-9-]+   {
                    warn("line %d: ignoring unknown keyword: `%s'\n", ycline,
                            yctext);
                }
.               {
                    warn("line %d: junk `%s' found\n", ycline, yctext);
                }

<<EOF>>         {
                    include_stack_ptr--;
                    if (include_stack_ptr < 0)
                        yyterminate();
                    else {
                        yy_delete_buffer(YY_CURRENT_BUFFER);
                        yy_switch_to_buffer(include_stack[include_stack_ptr]);
                    }
                }

%%
