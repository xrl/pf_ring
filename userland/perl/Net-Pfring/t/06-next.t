#
# 06-next.t - test for open/next/close sequence on PF-RING aware devices
#
# Perl Net-Pfring - Perl binding for PF-RING
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

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $ring;}

my $device  = "eth0";
my $snaplen = 1500;
my $packet;

$ring = Net::Pfring::Open($device, 1, $snaplen);
$packet = Net::Pfring::Next($ring);
Net::Pfring::Close($ring);

print "ok 1\n";

