#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 06-next.t - test for open/next/close sequence on PF_RING aware devices
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

use Net::Pfring;

my $device  = "eth0";
my $snaplen = 1500;

my $ring;
my $packet;

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $ring;}

$ring = Net::Pfring::open($device, 1, $snaplen);
$packet = Net::Pfring::next($ring);
Net::Pfring::close($ring);

print "ok 1\n";

