%{
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

/* 
 * Lexer for C focused on what we need to understand. The only weird
 * restriction we impose is that 'char *', which we interpret as
 * type string, must be specified in a single line with a single
 * space between them.
 */
#include <stdio.h>
#include "grammar.h"

//extern void *yylval;

int line, cpp_line, col;
char *currline;
char *current_file;

#define adv() col += strlen(yytext)

#define save_string() yylval = (YYSTYPE) strdup(yytext)
#define save_number() yylval = (YYSTYPE) strtol(yytext, NULL, 0)
%}

D			[0-9]
L			[a-zA-Z_]
H			[a-fA-F0-9]
E			[Ee][+-]?{D}+
FS			(f|F|l|L)
IS			(u|U|l|L)*

%%

"como_tuple"    { adv(); return(TOK_TUPLE); }
"como_record"   { adv(); return(TOK_RECORD); }
"como_config"   { adv(); return(TOK_CONFIG); }

"char *"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"char"		{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"double"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"float"		{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"int"		{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"long"		{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"short"		{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"uint64_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"int64_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"uint32_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"int32_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"uint16_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"int16_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"uint8_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"n32_t" 	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"n16_t" 	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"int8_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }
"timestamp_t"	{ adv(); save_string(); return(TOK_KNOWN_TYPE); }

"signed"	{ adv(); return(TOK_SIGNED); }
"struct"	{ adv(); return(TOK_STRUCT); }
"typedef"	{ adv(); return(TOK_TYPEDEF); }
"unsigned"	{ adv(); return(TOK_UNSIGNED); }
"void"		{ adv(); return(TOK_VOID); }

0[xX]{H}+{IS}?	{ adv(); save_number(); return(TOK_NUM_CONSTANT); }
0{D}+{IS}?	{ adv(); save_number(); return(TOK_NUM_CONSTANT); }
{D}+{IS}?	{ adv(); save_number(); return(TOK_NUM_CONSTANT); }

L?'(\\.|[^\\'])+'      { adv(); return(TOK_CONSTANT); }
{D}+{E}{FS}?           { adv(); return(TOK_CONSTANT); }
{D}*"."{D}+({E})?{FS}? { adv(); return(TOK_CONSTANT); }
{D}+"."{D}*({E})?{FS}? { adv(); return(TOK_CONSTANT); }
L?\"(\\.|[^\\"])*\"    { adv(); return(TOK_CONSTANT); }

{L}({L}|{D})*	{ adv(); save_string(); return(TOK_IDENTIFIER); }
";"		{ adv(); return(';'); }
("{"|"<%")	{ adv(); return('{'); }
("}"|"%>")	{ adv(); return('}'); }

("["|"<:")	{ adv(); return('['); }
("]"|":>")	{ adv(); return(']'); }
"*"		{ adv(); return('*'); }

^#" "{D}+.*\"[^\"\n]+\".* { /* cpp output-specific line */
                    line = atoi(yytext + 2) - 1;
                    yytext = strchr(yytext, '"') + 1; /* after initial '"' */
                    *(strchr(yytext + 1, '"')) = 0;   /* until next '"' */
                    if (current_file)
                        free(current_file);
                    current_file = strdup(yytext);      /* copy the string */
                }
[ \t\v\f]       { adv(); }
\n              { line++; cpp_line++; col = 0; }
.		{ adv(); }


%%

int
yywrap()
{
    return(1);
}


