#!/usr/bin/perl
# Copyright (c) 2006, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the distribution.
# * Neither the name of Intel Corporation nor the names of its contributors
#   may be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# $Id$
#

#
# Script to generate macdb.h (perl gen-macdb.pl > macdb.h)
# Builds a MAC vendor database from 2 web pages.
#
use LWP::Simple;
use strict;

my %db; # prefix -> vendor information

sub transform_vendor {
    my ($ven) =  @_;
    $ven =~ s/\s(corporation|corp|company|inc|limited|ltd|gmbh|systems)//gi;
    $ven =~ s/communications/comm/gi;
    $ven =~ s/technolog(y|ies)/tech/gi;
    $ven =~ s/(\w+)/\u\L$1/g;
    $ven =~ s/[^A-Za-z0-9\s]//g;
    $ven =~ s/\s//g;
    $ven =~ s/(Co)$//;
    $ven = substr($ven, 0, 8);
    return $ven;
}

my $content = get("http://www.cavebear.com/CaveBear/Ethernet/vendor.html");
my @lines = split("\n", $content);
my $l;
while (defined ($l = shift(@lines))) {
    chomp $l;
    last if $l eq "<PRE>";
}
die "error parsing vendor information" unless ($l eq "<PRE>");

while (defined ($l = shift(@lines))) {
    chomp $l;
    last if $l eq "</PRE>";

    unless ($l =~ /^([0-9A-F]{6})\s+([a-zA-Z0-9]+)/) {
        print STDERR "Warning: unable to parse line '$l'\n";
        next;
    }
    $db{hex($1)} = transform_vendor($2);
}

$content = get("http://standards.ieee.org/regauth/oui/oui.txt");
@lines = split("\n", $content);

while (defined (my $l = shift(@lines))) {
    next unless defined $l;
    $_ = $l;
    next unless (/^([^\s]+)\s+\(base 16\)\s+(.*)/);

    my ($pref, $vendor) = (hex($1), $2);
    next if $vendor =~ /^\s*$/;
    $db{$pref} = transform_vendor($vendor);
}

print <<EOF;
/*
 * this file automatically generated with gen-macdb.pl.
 * do not edit.
 */
struct _macdb_entry {
    uint32_t prefix;
    char *vendor;
};
typedef struct _macdb_entry macdb_entry_t;

macdb_entry_t macdb[] = {
EOF

my $entries = 0;
foreach my $p (sort {$a<=>$b} keys %db) {
    printf "\t{ 0x%06x, \"%s\" },\n", $p, $db{$p};
    $entries++;
}

print <<EOF;
};

static int macdb_entries = $entries;

EOF

