/*
 * setproctitle & setproctitle_init come with the following license:
 * 
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *     2002, 2003 by The Internet Software Consortium and Rich Salz
 * 
 * This code is derived from software contributed to the Internet Software
 * Consortium by Rich Salz.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *title_prefix = NULL;
static char *title_start = NULL;
static char *title_end = NULL;

void
setproctitle_init(int argc, char **argv)
{
    char *sep;
    sep = rindex(argv[0], '/');
    if (sep)
	sep++;
    else
	sep = argv[0];

    title_prefix = strdup(sep);
    title_start = argv[0];
    title_end = argv[argc - 1] + strlen(argv[argc - 1]);
}

void
setproctitle(const char *format, ...)
{
    va_list args;
    size_t length;
    ssize_t delta;
    char *title;

    if (title_start == NULL || title_end == NULL) {
        return;
    }

    title = title_start;
    length = title_end - title_start;

    delta = snprintf(title, length, "%s: ", title_prefix);
    if (delta < 0 || (size_t) delta > length)
        return;
    if (delta > 0) {
        title += delta;
        length -= delta;
    }

    va_start(args, format);
    delta = vsnprintf(title, length, format, args);
    va_end(args);
    if (delta < 0 || (size_t) delta > length)
        return;
    if (delta > 0) {
        title += delta;
        length -= delta;
    }
    for (; length > 1; length--, title++)
        *title = ' ';
    *title = '\0';
}
