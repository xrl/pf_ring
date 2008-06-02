#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 07-version.t - test for open/version/close on PF_RING aware devices
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

# BEGIN { $| = 1; print "1..1\n"; }
# END {print "not ok 1\n" unless $ring;}

my $device  = "eth0";
my $snaplen = 1500;

my $major;
my $minor;
my $patch;

$ring = Net::Pfring::Open($device, 1, $snaplen) || die "not ok 1\n";
($major, $minor, $patch) = Net::Pfring::Version($ring);
Net::Pfring::Close($ring);

diag ("using PF-Ring ver $minor.$major.$patch\n");

