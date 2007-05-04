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
 * Config parsing for CoMo - lexic file
 */
%{

/* C Declarations */
#include <stdlib.h> /* atoll */
#if 0
"/*"         BEGIN(comment);
<comment>[^*\n]*        /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*   /* eat up '*'s not followed by '/'s */
<comment>\n             /* and newlines */
<comment>"*"+"/"        BEGIN(INITIAL);
#endif

int ycline = 1;

%}

/* Tokens for the filter parser:
 * The tokens that can appear in a CoMo filter are not completely defined yet.
 * This section should be modified as they change
 */

DIGIT           [0-9]
NUMBER          {DIGIT}+

%option noyywrap
%option nounput

%s comment 

/* Actions to be executed when a token is found:
 * 
 * Here we need to specify, for each possible token, what is the information
 * that we want to pass to the syntactic parser.
 *
 * Variables that are available in this section:
 *
 * - yytext is the string read from the input
 * - yyleng contains yytext length
 * - yflval is the value that will be passed to the syntactic parser.
 *   new data types can be added to it in base/filter-syntax.y (%union section)
 */

%%

"/*"                    BEGIN(comment);
<comment>[^*\n]*        /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*   /* eat up '*'s not followed by '/'s */
<comment>\n             ycline++; /* and newlines */
<comment>"*"+"/"        BEGIN(INITIAL);

db-path         { return TOK_DBPATH; }
librarydir      { return TOK_LIBDIR; }
memsize         { return TOK_MEMSIZE; }
query-port      { return TOK_QUERY_PORT; }

name            { return TOK_NAME; }
location        { return TOK_LOCATION; }
type            { return TOK_TYPE; }
comment         { return TOK_COMMENT; }
sniffer         { return TOK_SNIFFER; }
filesize        { return TOK_FILESIZE; }
module          { return TOK_MODULE; }
description     { return TOK_DESCRIPTION; }
source          { return TOK_SOURCE; }
output          { return TOK_OUTPUT; }
filter          { return TOK_FILTER; }
hashsize        { return TOK_HASHSIZE; }
streamsize      { return TOK_STREAMSIZE; }
args            { return TOK_ARGS; }
args-file       { return TOK_ARGSFILE; }
running         { return TOK_RUNNING; }
end             { return TOK_END; }
=               { return TOK_EQUALS; }
,               { return TOK_COMMA; }

{NUMBER}GB      {
                    yclval.number = atoll(yytext) * 1024 * 1024 * 1024;
                    return TOK_NUMBER;
                }
{NUMBER}MB      {
                    yclval.number = atoll(yytext) * 1024 * 1024;
                    return TOK_NUMBER;
                }
{NUMBER}KB      {
                    yclval.number = atoll(yytext) * 1024;
                    return TOK_NUMBER;
                }
{NUMBER}B       {
                    yclval.number = atoll(yytext);
                    return TOK_NUMBER;
                }

{NUMBER}        {
                    yclval.number = atoll(yytext);
                    return TOK_NUMBER;
                }

\"[^"]*\"       {   /* string literal */
                    yclval.string = como_strdup(yytext + 1);
                    yclval.string[strlen(yclval.string) - 1] = '\0';
                    return TOK_STRING;
                }
" "

#.*             /* comment til end of line */
\t
\n              {   ycline++; return TOK_NEWLINE; }

[a-zA-Z0-9-]+   {
                    warn("line %d: ignoring unknown keyword: `%s'\n", ycline,
                            yctext);
                }
.               {
                    warn("line %d: junk `%s' found\n", ycline, yctext);
                }

%%
