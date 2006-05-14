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
 * Snort module for CoMo - Boyer-Moore pattern-matching algorithm
 * 
 */

#include "module.h"       /* logmsg */

#define ASIZE 256       /* anything that can be represented with a char */
#define OUTPUT(x) logmsg(LOGUI, "SNORT: string match position = %d\n", x) 

/*
 * -- preBmBc
 *  
 * Precalculate the first jump table
 *
 */
void
preBmBc(char *x, int m, int bmBc[])
{
    int i;
 
    for (i = 0; i < ASIZE; ++i)
        bmBc[i] = m;
    for (i = 0; i < m - 1; ++i)
        bmBc[(unsigned char)x[i]] = m - i - 1;
}
 
/*
 * -- suffixes 
 *  
 * Calculate all the terminal substrings of a
 * given string
 *
 */
void
suffixes(char *x, int m, int *suff)
{
    int f, g, i;
 
    suff[m - 1] = m;
    g = m - 1;
    for (i = m - 2; i >= 0; --i) {
        if (i > g && suff[i + m - 1 - f] < i - g)
            suff[i] = suff[i + m - 1 - f];
        else {
            if (i < g)
                g = i;
            f = i;
            while (g >= 0 && x[g] == x[g + m - 1 - f])
                --g;
            suff[i] = f - g;
        }
    }
}
 
/*
 * -- preBmGs
 *  
 * Precalculate the second jump table
 *
 */
void
preBmGs(char *x, int m, int bmGs[])
{
    int i, j, suff[m];
 
    suffixes(x, m, suff);
 
    for (i = 0; i < m; ++i)
        bmGs[i] = m;
    j = 0;
    for (i = m - 1; i >= -1; --i)
        if (i == -1 || suff[i] == i + 1)
            for (; j < m - 1 - i; ++j)
                if (bmGs[j] == m)
                    bmGs[j] = m - 1 - i;
    for (i = 0; i <= m - 2; ++i)
        bmGs[m - 1 - suff[i]] = m - 1 - i;
}
 

/*
 * -- BM()
 *
 * Boyer-Moore pattern search
 * 
 * Given a string, a pattern to search, their respective sizes, 
 * and precomputed data, this function returns the first appearance 
 * of the pattern in the string (or 0 if the pattern is not found).
 *
 */
int 
BM(char *x, int m, char *y, int n, int bmBc[], int bmGs[], uint *found) 
{
    int i, j, k;
   
    *found = 0;

    j = 0;
    while (j <= n - m) {
	/* 
	 * Compare the pattern and the window backwards
	 * and starting from their rightmost position 
	 */
	for (i = m - 1; i >= 0 && x[i] == y[i + j]; --i);
      
	if (i < 0) { /* found! */
	    *found = j;
	    return 1; 
	} 

	/* 
	 * The pattern was not found. The following shift
	 * will be the maximum between the shifts in the 
	 * two precomputed tables
	 */
	k = bmBc[(unsigned char) y[i + j]] - m + 1 + i; 
	j += (bmGs[i] > k)? bmGs[i] : k; 
    }

    return 0;
}
