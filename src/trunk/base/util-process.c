/*
 * Copyright (c) 2004 Intel Corporation
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
 * $Id: util-process.c,v 1.2 2006/05/07 22:46:19 iannak1 Exp $
 *
 */


#include "como.h"

/* global state */
extern como_t map; 


/* 
 * This file contains utilities to manage the process tags. 
 * Each process tag is a 32 bit value made of three components: 
 * 
 *   . parent name, 8 bits; 
 *   . child name, 8 bits; 
 *   . process id, 16 bits; 
 * 
 * The parent name and child name are chosen among five predefined 
 * names (SUPERVISOR, CAPTURE, EXPORT, STORAGE, QUERY) while the 
 * process id is used to make the tag unique. 
 * 
 * We define a set of functions to build tags, process tags and 
 * convert tags to human readable strings. 
 */ 

typedef procname_t 	uint32_t; 

/* 
 * aliases for process class names 
 */ 
static struct {
    char * shortname;
    char * fullname; 
} procalias[] = { 
    {"??", "NONE"}, 
    {"su", "SUPERVISOR"}, 
    {"ca", "CAPTURE"}, 
    {"ex", "EXPORT"},
    {"st", "STORAGE"}, 
    {"qu", "QUERY"},
};


#define GETPROCPARENT(x) 	(((x) >> 24) & 0xff) 
#define GETPROCCHILD(x) 	(((x) >> 16) & 0xff) 
#define GETPROCID(x)		((x) & 0xffff)
#define GETPROC(x)		GETPROCCHILD(x)

#define SETPROC(x, y, a) 	(((x) << 8) | (y) | (a)) 
#define SETPROCSIBLING(x, a) 	(((x) & 0xff000000) | (a) | GETPROCID(x))
#define SETPROCCHILD(x, a, n) 	((GETPROC(x) << 24) | (a) | (n))

/* 
 * -- getprocname 
 * 
 * this function returns a short name for a process made of 
 * parent-id-child (e.g., qu-1-ca). if id and child are equal 
 * to zero they are not shown. 
 *
 */
char * 
getprocname(procname_t who)
{
    static char name[256]; 
    uint p, c, x; 

    p = GETPROCPARENT(who); 
    c = GETPROCCHILD(who); 
    x = GETPROCID(who); 
    if (p == 0) 
	sprintf(name, "%s", procalias[c].shortname);
    else 
	sprintf(name, "%s-%d-%s", 
		procalias[p].shortname, x, procalias[c].shortname); 

    return name;
}


/* 
 * -- getprocfullname
 * 
 * return the full name instead of the short one. same as 
 * getprocname for the rest.  
 *
 */ 
char * 
getprocfullname(procname_t who)
{
    static char name[256]; 
    int p, c, x; 

    p = GETPROCPARENT(who); 
    c = GETPROCCHILD(who); 
    x = GETPROCID(who); 
    if (p == 0) 
	sprintf(name, "%s", procalias[c].fullname);
    else 
	sprintf(name, "%s-%d-%s", 
		procalias[p].fullname, x, procalias[c].fullname); 

    return name;
}


/* 
 * -- sibling
 * 
 * returns the name of the sibling process by just 
 * using its class. 
 */
procname_t 
sibling(procname_t who)
{
    return SETPROCSIBLING(map.whoami, who); 
}


/* 
 * -- child
 * 
 * it reconstruct the tag of a child process
 */
procname_t 
child(procname_t who, int id)
{
    return SETPROCCHILD(map.whoami, who, id); 
}

/* 
 * -- buildtag
 * 
 * build a tag from all its components 
 */
procname_t 
buildtag(procname_t parent, procname_t who, int id)
{
    return SETPROC(parent, who, id); 
}

/* 
 * -- getprocclass
 * 
 * it extracts the process class of a child process. 
 * it returns 0 if the tag does not map any known processes. 
 */
procname_t 
getprocclass(procname_t who)
{
    procname_t x; 

    x = (GETPROCCHILD(who) << 16); 
    return (x >= SUPERVISOR && x <= QUERY)? x : 0;
}

/* 
 * -- getprocid
 * 
 * it extracts the process id. 
 */
int 
getprocid(procname_t who)
{
    return GETPROCID(who); 
}


/* 
 * -- isvalidproc
 * 
 * it returns 0 if the tag does not map any known processes. 
 */
int 
isvalidproc(procname_t who)
{
    procname_t x = (GETPROCCHILD(who) << 16); 
    return (x >= SUPERVISOR && x <= QUERY); 
}

