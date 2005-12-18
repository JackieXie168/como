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
 * Snort module for CoMo - lexic file
 *
 * Here we define the tokens that can appear in a Snort rule.
 * GNU Flex turns this file into a C program that can get one token at a time
 * from the input and send them to the Bison-generated parser.
 */
 
%{

/* C Declarations */

%}

DIGIT           [0-9]
ACTION          alert|log|pass|activate|dynamic
OPT_METADATA    msg|reference|sid|rev|classtype|priority
OPT_PAYLOAD     content|nocase|depth|offset|distance|within|isdataat|pcre|byte_test|byte_jump
OPT_NPAYLOAD    fragoffset|ttl|tos|id|ipopts|flow|fragbits|dsize|flags|seq|ack|window|itype|icode|icmp_id|icmp_seq|rpc|ip_proto|sameip
OPT_OTHER       activates|activated-by|count
OPT_NOSUPPORT   rawbytes|uricontent|ftpbounce|regex|content-list|flowbits|logto|session|resp|react|tag|threshold
KEYWORD         {OPT_METADATA}|{OPT_PAYLOAD}|{OPT_NPAYLOAD}|{OPT_OTHER}
BADKEYWORD      {OPT_NOSUPPORT}
COLON           ":"
IPTOK           ({DIGIT}{1,3}"."){3}{DIGIT}{1,3}
NETMASK         "/"({DIGIT}){1,2}
COMMA           ","
PORT            {DIGIT}+
ANY             "any"
DIRECTION       "->"|"<>"
NEGATION        "!"
OPENSQBR        "["
CLOSESQBR       "]"
VAR             var
VARNAME         [A-Z][A-Z_]*
VARREF          "$"{VARNAME}
PROTO           ip|tcp|udp|icmp
SEMICOLON       ";"
OPENBR          "("
CLOSEBR         ")"
CONTENT         {COLON}[^; ]+{SEMICOLON}
QUOTE           "\""
QUOTEDCONTENT   {COLON}{QUOTE}[^\"]+{QUOTE}{SEMICOLON}
COMMENT         "#"(.)*

%option noyywrap
%option nounput
/* This should work with Flex version >= 2.5.11 */
option noyyalloc noyyfree noyyrealloc

%%

{IPTOK}         { 
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(IPTOK); 
                }
{NETMASK}       { 
                yslval.text = (char *)prv_alloc(strlen(yytext));
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext+1, strlen(yytext));
                return(NETMASK); 
                }
{PORT}          { 
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(PORT); 
                }
{DIRECTION}     { 
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(DIRECTION); 
                }
{VARNAME}       {
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1;
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(VARNAME);
                }
{VARREF}        {
                yslval.text = (char *)prv_alloc(strlen(yytext));
                if (yslval.text == NULL) return -1;
                strncpy(yslval.text, yytext+1, strlen(yytext));
                return(VARREF);
                }
{ACTION}        { 
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(ACTION); 
                }
{PROTO}         {
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1;
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(PROTO);                
                }
{QUOTEDCONTENT} {
                yslval.text = (char *)prv_alloc(strlen(yytext)-3);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext+2, strlen(yytext)-4);
                strcat(yslval.text, "\0");
                return(CONTENT);
                }
{CONTENT}       {
                yslval.text = (char *)prv_alloc(strlen(yytext)-1);
                if (yslval.text == NULL) return -1;
                strncpy(yslval.text, yytext+1, strlen(yytext)-2);
                strcat(yslval.text, "\0");
                return(CONTENT);
                }
{KEYWORD}       {
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(KEYWORD);
                }
{BADKEYWORD}    {
                yslval.text = (char *)prv_alloc(strlen(yytext)+1);
                if (yslval.text == NULL) return -1; 
                strncpy(yslval.text, yytext, strlen(yytext)+1);
                return(BADKEYWORD);
                }
{COLON}         { 
                return(COLON); 
                }
{ANY}           {
                return(ANY);
                }
{NEGATION}      {
                return(NEGATION);
                }
{OPENSQBR}      {
                return(OPENSQBR);
                }
{CLOSESQBR}     {
                return(CLOSESQBR);
                }
{COMMA}         {
                return(COMMA);
                }
{VAR}           {
                return(VAR);
                }
{OPENBR}        {
                return(OPENBR);
                }
{CLOSEBR}       {
                return(CLOSEBR);
                }
{SEMICOLON}     {
                return(SEMICOLON);
                }
{COMMENT}       {
                return(COMMENT);
                }
[ \t\n]+

%%

/* Redefine memory allocation functions
 * This should work with Flex version >= 2.5.11 
 */

void *yyalloc (size_t bytes) {
    return prv_alloc(bytes);
}

void yyfree (void *ptr) {
    return prv_free(ptr);
}

void *yyrealloc (void *ptr, size_t bytes) {
    return prv_realloc(ptr, bytes);
}
