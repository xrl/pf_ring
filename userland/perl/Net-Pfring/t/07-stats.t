#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 07-stats.t - test for open/stats/close on PF_RING aware devices
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
my $packet;
my $received;
my $dropped;

$ring = Net::Pfring::open($device, 1, $snaplen) || die "not ok 1\n";
$packet = Net::Pfring::next($ring);
($received, $dropped) = Net::Pfring::stats($ring);
Net::Pfring::close($ring);

diag ("Packets on PF_Ring device $device: received $received - dropped $dropped\n");

