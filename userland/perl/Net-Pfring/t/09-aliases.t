#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 09-aliases.pl - test for open/next/close sequence on PF_RING aware devices
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

use Net::Pfring qw(:functions);

my $device  = "eth0";
my $snaplen = 1500;

my $ring;
my $packet;

BEGIN { $| = 1; print "1..5\n"; }
END {print "not ok 1\n" unless $ring;}

$ring = pfring_open($device, 1, $snaplen) || die "Cannot open device $device!\n";
print "ok 1\n";

$packet = pfring_next($ring);
print "ok 2\n";

pfring_stats($ring);
print "ok 3\n";

pfring_version($ring);
print "ok 4\n";

pfring_close($ring);
print "ok 5\n";