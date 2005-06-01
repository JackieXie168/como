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
 */

%{

/* C Declarations */

%}

DIGIT           [0-9]
ACTION          alert|log|pass|activate|dynamic
OPT_METADATA    msg|reference|sid|rev|classtype|priority
OPT_PAYLOAD     content|nocase|rawbytes|depth|offset|distance|within|uricontent|isdataat|pcre|byte_test|byte_jump|regex|content-list
OPT_NPAYLOAD    fragoffset|ttl|tos|id|ipopts|fragbits|dsize|flags|flow|flowbits|seq|ack|window|itype|icode|icmp_id|icmp_seq|rpc|ip_proto|sameip
OPT_POSTDETECT  logto|session|sesp|react|tag
KEYWORD         {OPT_METADATA}|{OPT_PAYLOAD}|{OPT_NPAYLOAD}|{OPT_POSTDETECT}
COLON           ":"
SEMICOLON       ";"
QUOTE           "\""
CONTENT         {COLON}[a-zA-Z0-9"|""+"]+{SEMICOLON}
QUOTEDCONTENT   {COLON}{QUOTE}[a-zA-Z0-9"|""+" ]+{QUOTE}{SEMICOLON}
IPTOK           ({DIGIT}{1,3}"."){3}{DIGIT}{1,3}
NETMASK         "/"({DIGIT}){1,2}
COMMA           ","
DIRECTION       "->"|"<>"
PROTO           ip|tcp|udp|icmp
PORT            {DIGIT}+
ANY             "any"
NEGATION        "!"
OPENSQBR        "["
CLOSESQBR       "]"
OPENBR          "("
CLOSEBR         ")"

%option noyywrap
%option nounput

%%

{ACTION}        { 
                yylval.text = strndup(yytext, strlen(yytext)); 
                return(ACTION); 
                }
{PROTO}         { 
                yylval.text = strndup(yytext, strlen(yytext));
                return(PROTO); 
                } 
{IPTOK}         { 
                yylval.text = strndup(yytext, strlen(yytext));
                return(IPTOK); 
                }
{NETMASK}       { 
                yylval.text = strndup(yytext+1, strlen(yytext));
                return(NETMASK); 
                }
{PORT}          { 
                yylval.text = strndup(yytext, strlen(yytext));
                return(PORT); 
                }
{COLON}         { 
                return(COLON); 
                }
{DIRECTION}     { 
                yylval.text = strndup(yytext, strlen(yytext));
                return(DIRECTION); 
                }
{ANY}           {
                yylval.text = strndup(yytext, strlen(yytext));
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
{OPENBR}        {
                return(OPENBR);
                }
{CLOSEBR}       {
                return(CLOSEBR);
                }
{CONTENT}       {
                yylval.text = strndup(yytext+1, strlen(yytext+1) - 1);
                return(CONTENT);
                }
{QUOTEDCONTENT} {
                yylval.text = strndup(yytext+2, strlen(yytext+2) - 2);
                return(QUOTEDCONTENT);
                }
{KEYWORD}       {
                yylval.text = strndup(yytext, strlen(yytext));
                return(KEYWORD);
                }
{SEMICOLON}     {
                return(SEMICOLON);
                }                
[ \t\n]+
%%

/* C Functions */
