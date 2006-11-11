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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "structmagic.h"

#define MAX_STRUCTS 1024
int num_structs;
struct_t *structs[MAX_STRUCTS + 1];
struct_t *current_struct;

static void yyerror(char *s);
int yylex(void);

/* vars owned by the lexer */
extern char yytext[], *current_file;
extern int line, col, cpp_line, cpp_col;
extern FILE *yyin;

static void
generate_error(char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "*** structmagic error ***\n");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\nParser aborted at file '%s', line %d, column %d "
        "[cpp ouput line %d].\n", current_file, line, col, cpp_line);
    exit(1);
}


/*
 * create a new struct_t, save it into the structs array
 * and set current_struct to point to the new struct_t.
 */
static void
new_struct(char *name)
{
    if (num_structs == MAX_STRUCTS)
        generate_error("too many structs in source file (maximum is %d)",
                        MAX_STRUCTS);

    current_struct = calloc(1, sizeof(struct_t));
    current_struct->name = name;
    structs[num_structs++] = current_struct;
}

/*
 * save a field definition into current_struct.
 */
static void
save_field(char *type, char *name, int arrlen, int arrlen2)
{
    field_t *field;

    if (current_struct->n_fields == MAX_ITEMS)
        generate_error("struct '%s' has too many fields", current_struct->name);

    if (! strcmp(type, "char") && arrlen == 0)
        generate_error("struct '%s': 'char' fields only supported as arrays. "
                "You may use int8_t or uint8_t instead.",
                current_struct->name);

    field = &current_struct->fields[current_struct->n_fields];
    field->type = type;
    field->name = name;
    field->arrlen = arrlen;
    field->arrlen2 = arrlen2;
    field->dim = !!arrlen + !!arrlen2; /* beautiful */

    current_struct->n_fields++;
}

%}

%token TOK_CHAR TOK_DOUBLE TOK_FLOAT TOK_INT TOK_LONG TOK_SHORT TOK_SIGNED
%token TOK_STRUCT TOK_TYPEDEF TOK_UNSIGNED TOK_VOID TOK_IDENTIFIER
%token TOK_TUPLE TOK_RECORD TOK_CONFIG TOK_KNOWN_TYPE
%token TOK_NUM_CONSTANT TOK_CONSTANT TOK_TYPE

%start code

%%

code: code something | something;
something: relevant_struct_definition | othertokens;

/*
 * A relevant struct definition is a como-specific keyword
 * (either como_serializable or como_storable) followed by
 * a struct definition with fields of como-supported types.
 */
relevant_struct_definition:
        como_keywords TOK_STRUCT struct_name '{' declaration_list '}' ';'
        {
            current_struct->flags = $1;
        }
        ;

como_keywords
        : como_keywords como_keyword { $$ = $1 | $2; }
        | como_keyword               { $$ = $1; }
        ;

como_keyword:
        | TOK_TUPLE  { $$ = FLAG_TUPLE; }
        | TOK_RECORD { $$ = FLAG_RECORD; }
        | TOK_CONFIG { $$ = FLAG_CONFIG; }
        ;

struct_name: TOK_IDENTIFIER { new_struct((char *) $1); };

declaration_list: declaration_list declaration | declaration;

declaration
        : TOK_KNOWN_TYPE TOK_IDENTIFIER ';'
        {
            save_field((char *) $1, (char *) $2, 0, 0);
        }
        | TOK_KNOWN_TYPE TOK_IDENTIFIER '[' TOK_NUM_CONSTANT ']' ';'
        {
            int n = (int) $4;
            if (n <= 0)
                generate_error("unsupported array length <= 0");
            save_field((char *) $1, (char *) $2, (int) $4, 0);
        }
        | TOK_KNOWN_TYPE TOK_IDENTIFIER
            '[' TOK_NUM_CONSTANT ']' '[' TOK_NUM_CONSTANT ']' ';'
        {
            int n = (int) $4;
            if (n <= 0)
                generate_error("unsupported array length <= 0");
            n = (int) $7;
            if (n <= 0)
                generate_error("unsupported array length <= 0");
            save_field((char *) $1, (char *) $2, (int) $4, (int) $7);
        }
        | TOK_KNOWN_TYPE TOK_IDENTIFIER
            '[' TOK_NUM_CONSTANT ']' '[' TOK_NUM_CONSTANT ']' '['
        {
            generate_error("only uni and bidimensional arrays are supported.");
        }
        | TOK_IDENTIFIER
        {
            generate_error("Parsing struct '%s': type '%s' not supported. "
                    "Please switch to a supported type.",
                    current_struct->name, $1);
        }
        ;

othertokens /* anything but a como_keyword */
        : TOK_CHAR | TOK_DOUBLE | TOK_FLOAT | TOK_INT | TOK_LONG
        | TOK_SHORT | TOK_SIGNED | TOK_STRUCT | TOK_TYPEDEF | TOK_UNSIGNED
        | TOK_VOID | TOK_CONSTANT | TOK_NUM_CONSTANT | TOK_TYPE
        | ';' | '{' | '}' | '[' | ']' | '*'
        | TOK_KNOWN_TYPE { free((void *)$1); }
        | TOK_IDENTIFIER { free((void *)$1); }
        ;

%%

static void
yyerror(char *s)
{
    /* TODO open file and print line where error was found */
    printf("parse error at file \"%s\", line %d, column %d\n", current_file,
            line, col);
    printf("(cpp output file: line %d)\n", cpp_line);
    printf("[s = %s]\n", s);
    exit(1);
}

int yyparse(void);

void
parse(char *input)
{
    yyin = fopen(input, "r");      
    if (yyin == NULL)
        err(1, "cannot open input file '%s'", input);

    num_structs = 0;
    bzero(&structs, sizeof(structs));
    cpp_line = line = 1;
    current_file = NULL;
    col = 0;
    yyparse();
}
