/* A Bison parser, made by GNU Bison 1.875c.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0

/* If NAME_PREFIX is specified substitute the variables and functions
   names.  */
#define yyparse yfparse
#define yylex   yflex
#define yyerror yferror
#define yylval  yflval
#define yychar  yfchar
#define yydebug yfdebug
#define yynerrs yfnerrs


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     NOT = 258,
     AND = 259,
     OR = 260,
     OPENBR = 261,
     CLOSEBR = 262,
     COLON = 263,
     ALL = 264,
     DIRECTION = 265,
     PORT = 266,
     LEVEL3 = 267,
     LEVEL4 = 268,
     NETMASK = 269,
     IPADDR = 270
   };
#endif
#define NOT 258
#define AND 259
#define OR 260
#define OPENBR 261
#define CLOSEBR 262
#define COLON 263
#define ALL 264
#define DIRECTION 265
#define PORT 266
#define LEVEL3 267
#define LEVEL4 268
#define NETMASK 269
#define IPADDR 270




/* Copy the first part of user declarations.  */
#line 80 "filter-syntax.y"


/* C Declarations */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h> 	/* va_start */

#include "como.h"

#define YYERROR_VERBOSE

/* Node types */
#define Tand   0
#define Tor    1
#define Tnot   2
#define Tpred  3

struct _ipaddr {
    uint8_t direction;
    uint32_t ip;
    uint32_t nm;
};
typedef struct _ipaddr ipaddr_t;

struct _portrange {
    uint8_t proto;
    uint8_t direction;
    uint16_t lowport;
    uint16_t highport;
};
typedef struct _portrange portrange_t;

typedef struct treenode
{
    uint8_t type;
    char *string;
    struct treenode *left;
    struct treenode *right;
} treenode_t;

typedef struct listnode
{
    char *string;
    struct listnode *next;
    struct listnode *prev;
} listnode_t;

int yflex(void);
void yferror(char *fmt, ...);

/* Variable where the result string will be stored after parsing the filter */
char **parsed_filter;

/*
 * -- parse_ip
 *
 * Dots and numbers notation -> Binary representation of an IP address
 *
 */
static int
parse_ip(char *ipstring, uint32_t *ip)
{
    struct in_addr inp;
    
    if (!inet_aton(ipstring, &inp)) {
        yferror("Invalid IP address: %s", ipstring);
        return -1;
    }
    *ip = inp.s_addr;
    return 0;
}

uint32_t netmasks[33] = 
    { 
      0x0,
      0x80000000,
      0xC0000000,
      0xE0000000,
      0xF0000000,
      0xF8000000,
      0xFC000000,
      0xFE000000,
      0xFF000000,
      0xFF800000,
      0xFFC00000,
      0xFFE00000,
      0xFFF00000,
      0xFFF80000,
      0xFFFC0000,
      0xFFFE0000,
      0xFFFF0000,
      0xFFFF8000,
      0xFFFFC000,
      0xFFFFE000,
      0xFFFFF000,
      0xFFFFF800,
      0xFFFFFC00,
      0xFFFFFE00,
      0xFFFFFF00,
      0xFFFFFF80,
      0xFFFFFFC0,
      0xFFFFFFE0,
      0xFFFFFFF0,
      0xFFFFFFF8,
      0xFFFFFFFC,
      0xFFFFFFFE,
      0xFFFFFFFF 
    };

/*
 * -- parse_nm
 *
 * CIDR notation -> integer representing the network mask
 *
 */
static int
parse_nm(int i, uint32_t *nm)
{
    if (i >= 0 && i <= 32) *nm = htonl(netmasks[i]);
    else {
        yferror("Invalid CIDR netmask: %d", i);
        return -1;
    }
    return 0;
}

/*
 * -- append_string
 *
 */
char *
append_string(char *dest, char *src)
{
    dest = (char *)safe_realloc(dest, strlen(dest) + strlen(src) + 1);
    strcat(dest, src);
    return dest;
}

/* 
 * -- tree_make
 * 
 * Create a new expression tree node
 *
 */
treenode_t *
tree_make(uint8_t type, treenode_t *left,
          treenode_t *right, char *string)
{
    treenode_t *t;
    
    t = (treenode_t *)safe_malloc(sizeof(treenode_t));
    t->type = type;
    if (t->type == Tpred) {
        t->string = safe_strdup(string);
    }
    t->right = right;
    t->left = left;
    
    return(t);
}

/*
 * -- list_add
 *
 * Add an element to a sorted list
 * XXX Insertion sort, quite inefficient
 *
 */
listnode_t *
list_add(listnode_t *list, char *s)
{
    listnode_t *laux;
    
    if (!list) {
        list = (listnode_t *)safe_malloc(sizeof(listnode_t));
        list->next = NULL;
        list->prev = NULL;
        list->string = safe_strdup(s);
    }
    else {
        if (strcmp(s, list->string) <= 0) {
            laux = (listnode_t *)safe_malloc(sizeof(listnode_t));
            laux->string = safe_strdup(s);
            laux->next = list;
            laux->prev = list->prev;
            list->prev = laux;
            list = laux;
        }
        else {
            laux = list_add(list->next, s);
            list->next = laux;
            laux->prev = list;
        }
    }

    return list;
}

/*
 * -- list_merge
 *
 * Insert the elements of a list into another list
 *
 */
listnode_t *list_merge(listnode_t *l1, listnode_t *l2)
{
    listnode_t *laux;

    for (laux = l2; laux; laux = laux->next)
        l1 = list_add(l1, laux->string);
    
    return l1;
}

char *tree_to_string(treenode_t *);

/*
 * -- list_make
 *
 * Create a sorted list from an expression tree
 *
 */
listnode_t *
list_make(listnode_t *list, uint8_t type, treenode_t *tree)
{
    char *s;
    
    if (!tree) return NULL;

    switch (tree->type) {
    case Tnot:
    case Tpred:
        s = tree_to_string(tree);
        list = list_add(list, s);
        free(s);
        break;
    case Tand:
    case Tor:
        if (tree->type == type) {
            list = list_make(list, type, tree->left);
            list = list_make(list, type, tree->right);
        } else {
            s = tree_to_string(tree);
            list = list_add(list, s);
            free(s);
        }
        break;
    }

    return list;
}

/*
 * -- tree_to_string
 *
 */
char *
tree_to_string(treenode_t *tree)
{
    char *s;
    listnode_t *list, *laux;
    
    if (!tree) return NULL;
    
    switch (tree->type) {
    case Tand:
        list = list_make(NULL, Tand, tree->left);
        list = list_merge(list, list_make(NULL, Tand, tree->right));
        s = safe_strdup("(");
        for (laux = list; laux->next; laux = laux->next) {
            s = append_string(s, laux->string);
            s = append_string(s, " && ");
        }
        s = append_string(s, laux->string);
        s = append_string(s, ")");
        /* free the list */
        do {
            laux = list->next;
            free(list->string);
            free(list);
            list = laux;
        } while (laux);
        break;
	case Tor:
        list = list_make(NULL, Tor, tree->left);
        list = list_merge(list, list_make(NULL, Tor, tree->right));
        s = safe_strdup("(");
        for (laux = list; laux->next; laux = laux->next) {
            s = append_string(s, laux->string);
            s = append_string(s, " || ");
        }
        s = append_string(s, laux->string);
        s = append_string(s, ")");
        /* free the list */
        do {
            laux = list->next;
            free(list->string);
            free(list);
            list = laux;
        } while (laux);
        break;
	case Tnot:
        s = safe_strdup("!");
        s = append_string(s, tree_to_string(tree->left));
        break;
    case Tpred:
        s = safe_strdup(tree->string);
        break;
    }
    
    return s;
}

/*
 * -- tree_print_indent
 *
 * Print an expression tree with indentation
 * (only used for debug purposes)
 *
 */
void
tree_print_indent(treenode_t *tree, int indent)
{
    int i;

    if (!tree) return;
    printf("\n");
    printf("     ");
    for (i = 1; i <= indent; i++) printf("   ");
    switch (tree->type) {
    case Tand:
        printf("and");
        break;
	case Tor:
        printf("or");
        break;
	case Tnot:
        printf("not");
        break;
    case Tpred:
        printf("%s", tree->string);
        break;
    }
    tree_print_indent(tree->left, indent + 1);
    tree_print_indent(tree->right, indent + 1);
}

/*
 * -- tree_print
 *
 * Print an expression tree
 * (only used for debug purposes)
 *
 */
void
tree_print(treenode_t *tree)
{
    if (tree) {
        printf("\n\n\nLogical Expression Tree: \n\n");
        tree_print_indent(tree, 0);
        printf("\n\n\n\n");
    } else
        printf("\n\n\nLogical Expression Tree is empty!\n\n");
}

treenode_t *negate(treenode_t *);

/*
 * -- prop_negs
 *
 * Propagate the negations of a tree inward with the following rules:
 *      not(not(A)) => A
 *      not(A and B) => not(A) or not(B)
 *      not(A or B) => not(A) and not(B)
 *
 */
treenode_t *
prop_negs(treenode_t *t)
{
    switch(t->type) {
    case Tnot:
        t = negate(t->left);
        break;
    case Tand:
    case Tor:
        prop_negs(t->left);
        prop_negs(t->right);
        break;
    }

    return t;
}

/*
 * -- negate
 *
 * Negate a node of a tree
 *
 */
treenode_t *
negate(treenode_t *t)
{
    switch(t->type) {
    case Tpred:
        /* Negate the node */
        t = tree_make(Tnot, t, NULL, NULL);
        break;
    case Tnot:
        /* Double negation, get rid of it */
        t = prop_negs(t->left);
        break;
    case Tand:
        /* not(A and B) => not(A) or not(B) */
        t->type = Tor;
        t->left = negate(t->left);
        t->right = negate(t->right);
        break;
    case Tor:
        /* not(A or B) => not(A) and not(B) */
        t->type = Tand;
        t->left = negate(t->left);
        t->right = negate(t->right);
        break;
    }

    return t;
}

/*
 * -- tree_copy
 *
 * Duplicate a tree and return a pointer to the new copy
 *
 */
treenode_t *
tree_copy(treenode_t *t)
{
    treenode_t *taux;

    if (!t)
        return NULL;
    
    taux = (treenode_t *)safe_malloc(sizeof(treenode_t));
    taux->type = t->type;
    if (taux->type == Tpred)
        taux->string = safe_strdup(t->string);
    taux->left = tree_copy(t->left);
    taux->right = tree_copy(t->right);

    return taux;
}

/*
 * -- or_and
 *
 * Propagate conjunctions outward with the following rule:
 *      A or (B and C) => (A or B) and (A or C)
 *
 */
treenode_t *
or_and(treenode_t *t)
{
    treenode_t *taux;
    uint8_t type;
    
    switch(t->left->type) {
        case Tor:
            type = t->left->type;
            t->left = or_and(t->left);
            if (t->left->type != type) {
                t = or_and(t);
                /* No need to check the right child */
                return t;
            }
            break;
        case Tand:
            /* Apply the rule ... */
            t->type = Tand;
            t->left->type = Tor;
            taux = t->left->right;
            t->left->right = t->right;
            t->right = tree_make(Tor, taux, tree_copy(t->left->right), NULL);
            
            t->left = or_and(t->left);
            t->right = or_and(t->right);
            
            /* No need to check the right child */
            return t;
            
            break;
    }

    switch(t->right->type) {
        case Tor:
            type = t->right->type;
            t->right = or_and(t->right);
            if (t->right->type != type)
                t = or_and(t);
            break;
        case Tand:
            /* Apply the rule ... */
            t->type = Tand;
            t->right->type = Tor;
            taux = t->right->left;
            t->right->left = t->left;
            t->left = tree_make(Tor, tree_copy(t->right->left), taux, NULL);
            
            t->left = or_and(t->left);
            t->right = or_and(t->right);
            
            break;
    }    
    
    return t;
}

/*
 * -- prop_conjs
 *
 * Propagate conjunctions outward with the following rule:
 *      A or (B and C) => (A or B) and (A or C)
 *
 */
treenode_t *
prop_conjs(treenode_t *t)
{
    switch(t->type) {
    case Tnot:
        prop_conjs(t->left);
        break;
    case Tand:
        prop_conjs(t->left);
        prop_conjs(t->right);
        break;
    case Tor:
        t = or_and(t);
        break;
    }

    return t;
}

/*
 * -- cnf
 *
 * Transform an expression tree to Conjunctive Normal Form
 *
 */
treenode_t *
cnf(treenode_t *t)
{
    /* 1. Propagate negations inward */
    t = prop_negs(t);
    /* 2. Propagate conjunctions outward */
    t = prop_conjs(t);
    
    return t;
}

char *s = NULL;
char *direction = NULL;
char *proto = NULL;



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 647 "filter-syntax.y"
typedef union YYSTYPE {
    char *string;
    uint8_t byte;
    uint16_t word;
    uint32_t dword;
    treenode_t *tree;
    ipaddr_t ipaddr;
    portrange_t portrange;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 692 "filter-syntax.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 704 "filter-syntax.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   define YYSTACK_ALLOC alloca
#  endif
# else
#  if defined (alloca) || defined (_ALLOCA_H)
#   define YYSTACK_ALLOC alloca
#  else
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  17
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   41

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  16
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  6
/* YYNRULES -- Number of rules. */
#define YYNRULES  20
/* YYNRULES -- Number of states. */
#define YYNSTATES  36

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   270

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     5,     7,    11,    17,    21,    27,    30,
      35,    37,    39,    41,    44,    48,    52,    57,    62,    68,
      70
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      17,     0,    -1,    18,    -1,     9,    -1,    18,     4,    18,
      -1,     6,    18,     4,    18,     7,    -1,    18,     5,    18,
      -1,     6,    18,     5,    18,     7,    -1,     3,    18,    -1,
       3,     6,    18,     7,    -1,    19,    -1,    20,    -1,    21,
      -1,    10,    15,    -1,    10,    15,    14,    -1,    13,    10,
      11,    -1,    13,    10,    11,     8,    -1,    13,    10,     8,
      11,    -1,    13,    10,    11,     8,    11,    -1,    12,    -1,
      13,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short yyrline[] =
{
       0,   676,   676,   681,   686,   690,   694,   698,   702,   707,
     711,   721,   751,   772,   780,   789,   796,   803,   810,   818,
     822
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "NOT", "AND", "OR", "OPENBR", "CLOSEBR",
  "COLON", "ALL", "DIRECTION", "PORT", "LEVEL3", "LEVEL4", "NETMASK",
  "IPADDR", "$accept", "filter", "expr", "ip", "port", "proto", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    16,    17,    17,    18,    18,    18,    18,    18,    18,
      18,    18,    18,    19,    19,    20,    20,    20,    20,    21,
      21
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     1,     1,     3,     5,     3,     5,     2,     4,
       1,     1,     1,     2,     3,     3,     4,     4,     5,     1,
       1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       0,     0,     0,     3,     0,    19,    20,     0,     2,    10,
      11,    12,     0,     8,     0,    13,     0,     1,     0,     0,
       0,     0,     0,    14,     0,    15,     4,     6,     9,     4,
       6,    17,    16,     5,     7,    18
};

/* YYDEFGOTO[NTERM-NUM]. */
static const yysigned_char yydefgoto[] =
{
      -1,     7,     8,     9,    10,    11
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -12
static const yysigned_char yypact[] =
{
       0,    13,    21,   -12,   -11,   -12,    12,    28,     3,   -12,
     -12,   -12,    21,   -12,    10,    22,    -6,   -12,    21,    21,
      25,    21,    21,   -12,    24,    29,   -12,   -12,   -12,    31,
      32,   -12,    30,   -12,   -12,   -12
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -12,   -12,    -1,   -12,   -12,   -12
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
      13,    14,    24,     1,    15,    25,     2,    18,    19,     3,
       4,    20,     5,     6,    21,    22,     1,    26,    27,    12,
      29,    30,    16,     4,     1,     5,     6,     2,    17,    21,
      22,     4,    28,     5,     6,    31,    23,    32,    33,    34,
       0,    35
};

static const yysigned_char yycheck[] =
{
       1,     2,     8,     3,    15,    11,     6,     4,     5,     9,
      10,    12,    12,    13,     4,     5,     3,    18,    19,     6,
      21,    22,    10,    10,     3,    12,    13,     6,     0,     4,
       5,    10,     7,    12,    13,    11,    14,     8,     7,     7,
      -1,    11
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,     3,     6,     9,    10,    12,    13,    17,    18,    19,
      20,    21,     6,    18,    18,    15,    10,     0,     4,     5,
      18,     4,     5,    14,     8,    11,    18,    18,     7,    18,
      18,    11,     8,     7,     7,    11
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)		\
   ((Current).first_line   = (Rhs)[1].first_line,	\
    (Current).first_column = (Rhs)[1].first_column,	\
    (Current).last_line    = (Rhs)[N].last_line,	\
    (Current).last_column  = (Rhs)[N].last_column)
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short *bottom, short *top)
#else
static void
yy_stack_print (bottom, top)
    short *bottom;
    short *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if defined (YYMAXDEPTH) && YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 677 "filter-syntax.y"
    {
        yyvsp[0].tree = cnf(yyvsp[0].tree);
        *parsed_filter = tree_to_string(yyvsp[0].tree);
        ;}
    break;

  case 3:
#line 682 "filter-syntax.y"
    {
        *parsed_filter = safe_strdup("ALL");
        ;}
    break;

  case 4:
#line 687 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tand, yyvsp[-2].tree, yyvsp[0].tree, NULL);
      ;}
    break;

  case 5:
#line 691 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tand, yyvsp[-3].tree, yyvsp[-1].tree, NULL);
      ;}
    break;

  case 6:
#line 695 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tor, yyvsp[-2].tree, yyvsp[0].tree, NULL);
      ;}
    break;

  case 7:
#line 699 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tor, yyvsp[-3].tree, yyvsp[-1].tree, NULL);
      ;}
    break;

  case 8:
#line 703 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tnot, yyvsp[0].tree, NULL, NULL);
        
      ;}
    break;

  case 9:
#line 708 "filter-syntax.y"
    {
        yyval.tree = tree_make(Tnot, yyvsp[-1].tree, NULL, NULL);
      ;}
    break;

  case 10:
#line 712 "filter-syntax.y"
    {
        if (yyvsp[0].ipaddr.direction == 0)
            asprintf(&s, "((N32(IP(src_ip)) & %u) == %u)", yyvsp[0].ipaddr.nm, yyvsp[0].ipaddr.ip);
        else
            asprintf(&s, "((N32(IP(dst_ip)) & %u) == %u)", yyvsp[0].ipaddr.nm, yyvsp[0].ipaddr.ip);
        
        yyval.tree = tree_make(Tpred, NULL, NULL, s);
        free(s);
      ;}
    break;

  case 11:
#line 722 "filter-syntax.y"
    {
        if (yyvsp[0].portrange.proto == IPPROTO_TCP)
            proto = safe_strdup("TCP");
        else if (yyvsp[0].portrange.proto == IPPROTO_UDP)
            proto = safe_strdup("UDP");
        else {
            yferror("Invalid protocol number: %d, using TCP instead",
                    yyvsp[0].portrange.proto);
            proto = safe_strdup("TCP");
        }
        
        if (yyvsp[0].portrange.direction == 0)
            direction = safe_strdup("src");
        else
            direction = safe_strdup("dst");
        
        if (yyvsp[0].portrange.lowport == yyvsp[0].portrange.highport)
            asprintf(&s, "(H16(%s(%s_port)) == %d)",
                     proto, direction, yyvsp[0].portrange.lowport);
        else
            asprintf(&s, "((H16(%s(%s_port)) >= %d) && "
                     "(H16(%s(%s_port)) <= %d))", proto, direction, yyvsp[0].portrange.lowport,
                     proto, direction, yyvsp[0].portrange.highport);
        
        yyval.tree = tree_make(Tpred, NULL, NULL, s);
        free(s);
        free(direction);
        free(proto);
      ;}
    break;

  case 12:
#line 752 "filter-syntax.y"
    {
        /* XXX Should we use the "isIP, isTCP, isUDP" helper macros ??? */
        switch(yyvsp[0].word) {
        case ETHERTYPE_IP:
            asprintf(&s, "(COMO(l3type) == ETHERTYPE_IP)");
            break;
        case IPPROTO_TCP:
            asprintf(&s, "(COMO(l4type) == IPPROTO_TCP)");
            break;
        case IPPROTO_UDP:
            asprintf(&s, "(COMO(l4type) == IPPROTO_UDP)");
            break;
        case IPPROTO_ICMP:
            asprintf(&s, "(COMO(l4type) == IPPROTO_ICMP)");
            break;
        }
        yyval.tree = tree_make(Tpred, NULL, NULL, s);
        free(s);
      ;}
    break;

  case 13:
#line 773 "filter-syntax.y"
    {
        yyval.ipaddr.direction = yyvsp[-1].byte;
        if (parse_ip(yyvsp[0].string, &(yyval.ipaddr.ip)) == -1)
            YYABORT;
        /* Assume it's a host IP address if we don't have a netmask */
        yyval.ipaddr.nm = htonl(netmasks[32]);
    ;}
    break;

  case 14:
#line 781 "filter-syntax.y"
    {
        yyval.ipaddr.direction = yyvsp[-2].byte;
        if (parse_ip(yyvsp[-1].string, &(yyval.ipaddr.ip)) == -1)
            YYABORT;
        if (parse_nm(yyvsp[0].dword, &(yyval.ipaddr.nm)) == -1)
            YYABORT;
    ;}
    break;

  case 15:
#line 790 "filter-syntax.y"
    {
        yyval.portrange.proto = yyvsp[-2].word;
        yyval.portrange.direction = yyvsp[-1].byte;
        yyval.portrange.lowport = yyvsp[0].word;
        yyval.portrange.highport = yyvsp[0].word;
      ;}
    break;

  case 16:
#line 797 "filter-syntax.y"
    {
        yyval.portrange.proto = yyvsp[-3].word;
        yyval.portrange.direction = yyvsp[-2].byte;
        yyval.portrange.lowport = yyvsp[-1].word;
        yyval.portrange.highport = 65535;
      ;}
    break;

  case 17:
#line 804 "filter-syntax.y"
    {
        yyval.portrange.proto = yyvsp[-3].word;
        yyval.portrange.direction = yyvsp[-2].byte;
        yyval.portrange.lowport = 1;
        yyval.portrange.highport = yyvsp[0].word;
      ;}
    break;

  case 18:
#line 811 "filter-syntax.y"
    {
        yyval.portrange.proto = yyvsp[-4].word;
        yyval.portrange.direction = yyvsp[-3].byte;
        yyval.portrange.lowport = yyvsp[-2].word;
        yyval.portrange.highport = yyvsp[0].word;
      ;}
    break;

  case 19:
#line 819 "filter-syntax.y"
    {
        yyval.word = yyvsp[0].word;
       ;}
    break;

  case 20:
#line 823 "filter-syntax.y"
    {
        yyval.word = yyvsp[0].word;
       ;}
    break;


    }

/* Line 1000 of yacc.c.  */
#line 1811 "filter-syntax.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  const char* yyprefix;
	  char *yymsg;
	  int yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 0;

	  yyprefix = ", expecting ";
	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		yysize += yystrlen (yyprefix) + yystrlen (yytname [yyx]);
		yycount += 1;
		if (yycount == 5)
		  {
		    yysize = 0;
		    break;
		  }
	      }
	  yysize += (sizeof ("syntax error, unexpected ")
		     + yystrlen (yytname[yytype]));
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yyprefix = ", expecting ";
		  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			yyp = yystpcpy (yyp, yyprefix);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yyprefix = " or ";
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (yychar == YYEOF)
	     for (;;)
	       {
		 YYPOPSTACK;
		 if (yyssp == yyss)
		   YYABORT;
		 YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
		 yydestruct (yystos[*yyssp], yyvsp);
	       }
        }
      else
	{
	  YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
	  yydestruct (yytoken, &yylval);
	  yychar = YYEMPTY;

	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     yyerrorlab therefore never appears in user code.  */
  if (0)
     goto yyerrorlab;
#endif

  yyvsp -= yylen;
  yyssp -= yylen;
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 828 "filter-syntax.y"


#include "filter-lexic.c"

void yferror(char *fmt, ...)
{ 
    va_list ap;
    char error[255];
    
    va_start(ap, fmt);
    vsnprintf(error, sizeof(error), fmt, ap);
    logmsg(LOGWARN, "Filter parser error: %s\n", error);
    va_end(ap);
}

int 
parse_filter(char *filter, char **result)
{
    parsed_filter = result;
    yf_scan_string(filter);
    return yfparse();
}


