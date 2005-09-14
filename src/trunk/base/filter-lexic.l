/*
 * Copyright (c) 2005 Universitat Politecnica de Catalunya
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$ 
 */

/*
 * Author: Diego Amores Lopez (damores@ac.upc.edu)
 * 
 * Description:
 * ------------
 *  
 * Filter parsing for CoMo - lexic file
 *
 * Here we define the tokens that can appear in a CoMo filter.
 * GNU Flex turns this file into a C program that can get one token at a time
 * from the input and send them to the Bison-generated parser.
 */

%{

/* C Declarations */

%}

/* The tokens that can appear in a CoMo filter are not completely defined yet.
   This section should be modified as they change */

ALFANUMERIC     [a-zA-Z0-9]
CONDITION       ALL|isIP
MACROKW         COMO|PROTO|proto|DIR|IFACE|CLASS_A|CLASS_B|CLASS_C|CLASS_D|MULTICAST|EXPERIMENTAL|BADCLASS|NET
MACRO           {MACROKW}\(({ALFANUMERIC}+\,)*{ALFANUMERIC}+\)

%option noyywrap
%option nounput

%%

{CONDITION}     { yflval.text = (char *)malloc(yyleng + 1);
                  strncpy(yflval.text, yytext, strlen(yytext) + 1);
                  return(CONDITION); }
{MACRO}         { yflval.text = (char *)malloc(yyleng + 1);
                  strncpy(yflval.text, yytext, strlen(yytext) + 1);
                  return(MACRO); }
and             { return(AND); }
or              { return(OR); }
not             { return(NOT); }
\(              { return(OPENBR); }
\)              { return(CLOSEBR); }

[ \t\n]+

%%
