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

#include "como.h"
#include "macdb.h"

/*
 * -- mac_lookup
 *
 * Do a binary search for a MAC address in the db. Return
 * the vendor if found, null otherwise.
 */
static char *
mac_lookup(uint8_t *addr)
{
    uint32_t prefix;
    int left, right, mid;

    left = 0;
    right = macdb_entries;
    prefix = addr[0] << 16 | addr[1] << 8 | addr[2];
    
    while (left <= right) {
        mid = ((right - left) / 2) + left;

        if (prefix > macdb[mid].prefix)
            left = mid + 1;
        else if (prefix < macdb[mid].prefix)
            right = mid - 1;
        else
            return macdb[mid].vendor;
    }
    return NULL;
}

/*
 * -- pretty_mac
 *
 * Return a string for the given MAC address.
 * The flag lookup_vendor tells wether to attempt a lookup of the 
 * vendor of the MAC address. If the vendor lookup is successful,
 * The output will be vendor_xx:xx:xx:xx:xx:xx. Otherwise, the output
 * is of the form xx:xx:xx:xx:xx:xx.
 */
void
pretty_mac(uint8_t *addr, char *output, size_t size, int lookup_vendor)
{
    char *vendor;
    int ret;

    vendor = lookup_vendor ? mac_lookup(addr) : NULL;

    ret = snprintf(output, size, "%s%s%02x:%02x:%02x:%02x:%02x:%02x",
            vendor ? vendor : "", vendor ? "_" : "",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    if (ret >= (int)size) /* truncated, null-terminate */
        output[size - 1] = '\0';
}

