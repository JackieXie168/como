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
 * Query parsing for CoMo - lexic file
 */
%{

/* C Declarations */

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

GET             { return TOK_GET; }
"HTTP/1.0"      { return TOK_HTTPVER; }
"HTTP/1.1"      { return TOK_HTTPVER; }

"/"             { return TOK_SLASH; }
&               { return TOK_AMP; }
"?"             { return TOK_QMARK; }
=               { return TOK_EQUALS; }
" "             { return TOK_SPACE; }

[a-zA-Z0-9:%]+    { yqlval.string = como_strdup(yytext); return TOK_STRING; }

%%
