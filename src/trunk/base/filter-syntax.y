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

%{

/* C Declarations */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "filter.h"
#include "como.h"

/* Node types */
#define Tand  0
#define Tor   1
#define Tnot  2
#define Tpred 3

typedef struct treenode
{
    int             nodetype;
    char            *text;
    struct treenode  *left;
    struct treenode  *right;
} treenode_t;

typedef struct listnode
{
    char            *text;
    struct listnode *next;
} listnode_t;

int yflex(void);
void yferror(char const *);

/*
 * makes a malloc'ed copy of src into *dst, freeing the previous one if any
 * taken from base/config.c
 */
static void
safe_dup(char **dst, char *src)
{
    if (*dst)
	free(*dst);
    *dst = strdup(src);
    if (*dst == NULL)
        panic("out of memory");
}

/* Variable where the final string will be stored after parsing the filter */
char **parsedstring;

/* Create a new expression tree node */
treenode_t *TreeMake(int node, treenode_t *left, treenode_t *right, char *t)
{
  treenode_t *s = (treenode_t *)malloc(sizeof(*s));
  s->nodetype = node;
  s->text = t;
  s->right = right;
  s->left = left;
  return(s);
}

/* Print an expression tree with indentation */
void TreePrintIndent(treenode_t *tree, int indent)
{
  int i;

  if (!tree) return;
  printf("\n");
  printf("     ");
  for (i = 1; i <= indent; i++) printf("   ");
  switch (tree->nodetype)
    {
	case Tand:  printf("and"); break;
	case Tor:   printf("or");  break;
	case Tnot:  printf("not"); break;
    }
  printf("%s", tree->text);
  TreePrintIndent(tree->left, indent + 1);
  TreePrintIndent(tree->right, indent + 1);
}

/* Print an expression tree */
void TreePrint(treenode_t *tree)
{
  if (tree)
    {
      printf("\n\n\nLogical Expression Tree: \n\n");
      TreePrintIndent(tree, 0);
      printf("\n\n\n\n");
    }
  else
    printf("\n\n\nLogical Expression Tree is empty!\n\n");
}

#define T (*tree)

void negate(treenode_t **);

void propagate(treenode_t *);

/* Propagate a negation inwards through an AND node */
void negate_and(treenode_t **tree) {
    if (!T) return;
    if (T->nodetype == Tand) {
        T->nodetype = Tor;
        negate_and(&(T->left));
        negate_and(&(T->right));
    }
    else
        negate(tree);
}

/* Propagate a negation inwards through an OR node */
void negate_or(treenode_t **tree) {
    if (!T) return;
    if (T->nodetype == Tor) {
        T->nodetype = Tand;
        negate_or(&(T->left));
        negate_or(&(T->right));
    }
    else
        negate(tree);
}

/* Propagate negations inwards until only the leaves of the tree
   can be negated */

void negate(treenode_t **tree) {
    if (!T) return;
    /* Make the negation */
    switch (T->nodetype) {
        case Tpred:
            T = TreeMake(Tnot, T, NULL, "");
            break;
        case Tnot:
            if (T->left->nodetype == Tpred)
                T = TreeMake(Tnot, T, NULL, "");
            else propagate(T->left);
            break;
        case Tand:
            T->nodetype = Tor;
            negate_and(&(T->left));
            negate_and(&(T->right));
            break;
        case Tor:
            T->nodetype = Tand;
            negate_or(&(T->left));
            negate_or(&(T->right));
            break;
    }
}

void propagate(treenode_t *tree) {
    if (!tree) return;
    switch (tree->nodetype) {
        case Tnot:
            if (tree->left->nodetype != Tpred)
                negate(&(tree->left));
            break;
        case Tand:
            propagate(tree->left);
            propagate(tree->right);
            break;
        case Tor:
            propagate(tree->left);
            propagate(tree->right);
            break;
    }            
}

/* Clean innecessary and residual negations from a tree */
void clean_neg(treenode_t **tree) {
    treenode_t *aux;
    
    if (!T) return;
    if (T->nodetype == Tnot) {
        /* Double negation */
        if (T->left->nodetype == Tnot) {
            aux = T;
            T = TreeMake(T->left->left->nodetype, T->left->left->left, 
                         T->left->left->right, T->left->left->text);
            free(aux->left->left);
            free(aux->left);
            free(aux);
        }
        /* Negated AND/OR */
        else if (T->left->nodetype == Tand || T->left->nodetype == Tor) {
            aux = T;
            T = TreeMake(T->left->nodetype, T->left->left, T->left->right,
                         T->left->text);
            free(aux->left);
            free(aux);
        }
    }
    clean_neg(&(T->left));
    clean_neg(&(T->right));
}

/* Get the text of a tree leaf */
char *get_text(treenode_t *n) {
    char *s;
    if (n->nodetype == Tpred)
        s = n->text;
    else if (n->nodetype == Tnot)
        s = n->left->text;
    else safe_dup(&s, "");
    return s;
}

int found;

/* Propagate disjunctions inwards */

void cnf(treenode_t **);

void disjunct(treenode_t **tree) {
    treenode_t *disj1, *disj2;
    
    if (!T) return;
    if (T->left->nodetype == Tand) {
        found = 1;
        disj1 = TreeMake(Tor, T->right, T->left->left, "");
        disj2 = TreeMake(Tor, T->right, T->left->right, "");
        free(T->left);
        free(T);
        T = TreeMake(Tand, disj1, disj2, "");
        cnf(&(T->left));
        cnf(&(T->right));
    }
    else if (T->right->nodetype == Tand) {
        found = 1;
        disj1 = TreeMake(Tor, T->left, T->right->left, "");
        disj2 = TreeMake(Tor, T->left, T->right->right, "");
        free(T->right);
        free(T);
        T = TreeMake(Tand, disj1, disj2, "");
        cnf(&(T->left));
        cnf(&(T->right));
    }
    else {
        cnf(&(T->left));
        cnf(&(T->right));
    }
}

void cnf(treenode_t **tree) {
    if (!T) return;
    switch (T->nodetype) {
        case Tnot:
            cnf(&(T->left));
            cnf(&(T->right));
            break;
        case Tand:
            cnf(&(T->left));
            cnf(&(T->right));
            break;
        case Tor:
            disjunct(tree);
            break;
    }
}

/* Transform a tree into a Conjunctive Normal Form expression */
void transform(treenode_t **tree) {
    if (!T) return;
    /* 1. Propagate negations inward */
    propagate(T);
    /* 2. Clean the innecessary negations that are left in the tree */
    clean_neg(tree);
    /* 3. Take care of conjunctions and disjunctions */
    do {
        found = 0;
        cnf(tree);
    } while (found);
}

/* Insert a node in a list, keeping alphabetical order */
listnode_t *insert_node(listnode_t *list, char *text) {
    listnode_t *prev, *cur;
    listnode_t *newnode;
    
    if (!list) {
        list = (listnode_t *)safe_malloc(sizeof(listnode_t));
        list->text = text;
        list->next = NULL;
        return list;
    }
    prev = NULL;
    cur = list;
    while (cur && strcmp(cur->text, text) <= 0) {
        prev = cur;
        cur = cur->next;
    }
    newnode = (listnode_t *)safe_malloc(sizeof(listnode_t));
    newnode->text = text;
    newnode->next = cur;
    if (prev) {
        prev->next = newnode;
        return list;
    }
    else return newnode;
}

/* Create a string that represents a filter in CNF form */

char *make_string(treenode_t *);

listnode_t *add_node(listnode_t *list, int ntype, treenode_t *tree) {
    char *s, *sleft, *sright;
    
    if (!tree) return NULL;
    if (tree->nodetype == Tpred)
        return insert_node(list, get_text(tree));
    if (tree->nodetype == Tnot) {
        s = (char *)safe_malloc(strlen(get_text(tree)) + 5);
        sprintf(s, "not(%s)", get_text(tree));
        return insert_node(list, s);
    }
    if (tree->nodetype == ntype) {
        list = add_node(list, ntype, tree->left);
        list = add_node(list, ntype, tree->right);
        return list;
    }
    sleft = make_string(tree->left);
    sright = make_string(tree->right);
    if (tree->nodetype == Tand) {
        s = (char *)safe_malloc(strlen(sleft) + strlen(sright) + 7);
        if (strcmp(sleft, sright) <= 0)
            sprintf(s, "(%s and %s)", sleft, sright);
        else sprintf(s, "(%s and %s)", sright, sleft);
    }
    else if (tree->nodetype == Tor) {
        s = (char *)safe_malloc(strlen(sleft) + strlen(sright) + 6);
        if (strcmp(sleft, sright) <= 0)
            sprintf(s, "(%s or %s)", sleft, sright);
        else sprintf(s, "(%s or %s)", sright, sleft);
    }
    return insert_node(list, s);
}

char *make_string(treenode_t *tree) {
    char *s = NULL;
    listnode_t *list = NULL;
    
    /* We traverse the tree in postorder */
    
    if (!tree) return NULL;
    if (tree->nodetype == Tpred) {
        safe_dup(&s, tree->text);
    }
    if (tree->nodetype == Tnot) {
        s = (char *)safe_malloc(strlen(tree->left->text) + 5);
        sprintf(s, "not(%s)", tree->left->text);
    }
    if (tree->nodetype == Tand) {
        list = add_node(list, Tand, tree->left);
        list = add_node(list, Tand, tree->right);
        safe_dup(&s, "(");
        for (; list->next; list = list->next) {
            s = (char *)safe_realloc(s, strlen(s) + strlen(list->text) + 6);
            strcat(s, list->text); 
            strcat(s, " and ");
        }
        s = (char *)safe_realloc(s, strlen(s) + strlen(list->text) + 2);
        strcat(s, list->text);
        strcat(s, ")");
    }
    if (tree->nodetype == Tor) {
        list = add_node(list, Tor, tree->left);
        list = add_node(list, Tor, tree->right);
        safe_dup(&s, "(");
        for (; list->next; list = list->next) {
            s = (char *)safe_realloc(s, strlen(s) + strlen(list->text) + 5);
            strcat(s, list->text);            
            strcat(s, " or ");
        }
        s = (char *)safe_realloc(s, strlen(s) + strlen(list->text) + 2);
        strcat(s, list->text);
        strcat(s, ")");
    }
    return s;
}

%}

%union {
    char *text;
    treenode_t *tree;
}

/* Data types and tokens used by the parser */

%token <text> CONDITION MACRO
%token NOT AND OR OPENBR CLOSEBR
%left NOT AND OR
%type <tree> filter expr
%start filter

%%

/* Grammar rules and actions */

filter: expr
        { $$ = $1;
          transform(&$$);
          *parsedstring = make_string($$); }
          
expr: expr AND expr { $$ = TreeMake(Tand, $1, $3, ""); } |
      OPENBR expr AND expr CLOSEBR { $$ = TreeMake(Tand, $2, $4, ""); } |
      expr OR expr { $$ = TreeMake(Tor, $1, $3, ""); } |
      OPENBR expr OR expr CLOSEBR { $$ = TreeMake(Tor, $2, $4, ""); } |
      NOT expr { $$ = TreeMake(Tnot, $2, NULL, ""); } | 
      NOT OPENBR expr CLOSEBR { $$ = TreeMake(Tnot, $3, NULL, ""); } | 
      CONDITION { $$ = TreeMake(Tpred, NULL, NULL, $1); } |
      MACRO { $$ = TreeMake(Tpred, NULL, NULL, $1); }

%%

#include "filter-lexic.c"

void yferror(char const *error)
{ 
    printf("FILTER: Error parsing filter: %s\n", error);
}

int 
parse_filter(char *filter, char **string)
{
    parsedstring = string;
    yf_scan_string(filter);
    return yfparse();
}
