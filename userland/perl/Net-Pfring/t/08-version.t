#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 08-version.t - test for open/version/close on PF_RING aware devices
#
# Copyright (c) 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# This program is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself.
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#

use Test::More tests => 1;
use_ok ('Net::Pfring');

my $device  = "eth0";
my $snaplen = 1500;
my $ring;

my $major;
my $minor;
my $patch;

$ring = Net::Pfring::open($device, 1, $snaplen) || die "not ok 1\n";
($major, $minor, $patch) = Net::Pfring::version($ring);
Net::Pfring::close($ring);

diag ("using PF_RING ver $major.$minor.$patch\n");

