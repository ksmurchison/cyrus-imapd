#!/usr/bin/perl
#
#  Copyright (c) 2011-2018 FastMail Pty Ltd. All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#  3. The name "Fastmail Pty Ltd" must not be used to
#     endorse or promote products derived from this software without
#     prior written permission. For permission or any legal
#     details, please contact
#      FastMail Pty Ltd
#      PO Box 234
#      Collins St West 8007
#      Victoria
#      Australia
#
#  4. Redistributions of any form whatsoever must retain the following
#     acknowledgment:
#     "This product includes software developed by Fastmail Pty. Ltd."
#
#  FASTMAIL PTY LTD DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
#  INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY  AND FITNESS, IN NO
#  EVENT SHALL OPERA SOFTWARE AUSTRALIA BE LIABLE FOR ANY SPECIAL, INDIRECT
#  OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
#  USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
#  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
#  OF THIS SOFTWARE.
#

package Cassandane::BuildInfo;
use strict;
use warnings;
use JSON;

use lib '.';
use Cassandane::Cassini;
use Cassandane::Util::Log;

sub new {
    my $class = shift;
    my %params = @_;
    my $self = {};

    my $cassini = Cassandane::Cassini->instance();

    my $prefix = $cassini->val("cyrus default", 'prefix', '/usr/cyrus');
    $prefix = $params{cyrus_prefix}
        if defined $params{cyrus_prefix};

    my $destdir = $cassini->val("cyrus default", 'destdir', '');
    $destdir = $params{cyrus_destdir}
        if defined $params{cyrus_destdir};

    $self->{data} = _read_buildinfo($destdir, $prefix);

    return bless $self, $class;
}

sub _read_buildinfo
{
    my ($destdir, $prefix) = @_;

    my $cyr_buildinfo;
    foreach my $bindir (qw(sbin cyrus/bin)) {
        my $p = "$destdir$prefix/$bindir/cyr_buildinfo";
        if (-x $p) {
            $cyr_buildinfo = $p;
            last;
        }
    }

    if (not defined $cyr_buildinfo) {
        xlog "Couldn't find cyr_buildinfo: ".
             "don't know what features Cyrus supports";
        return;
    }

    my $jsondata = qx($cyr_buildinfo);
    return if not $jsondata;

    return JSON::decode_json($jsondata);
}

sub get
{
    my ($self, $category, $key) = @_;

    return if not exists $self->{data}->{$category}->{$key};
    return $self->{data}->{$category}->{$key};
}

1;
