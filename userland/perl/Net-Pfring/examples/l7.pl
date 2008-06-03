#
# Perl Net-Pfring - Perl binding for PF_RING
#
# test.pl - simple test for open/next/close sequence on PF_RING aware devices
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
my $packets = 3;

my $packet;
my $got;
my ($srcmac, $dstmac, $srcip, $srcport, $dstip, $dstport, $payload);

$| = 1;

my $ring = pfring_open($device, 1, $snaplen) || die "Cannot open device $device!\n";

$got = 0;
while (! $packets || $got < $packets)
  {
    ($srcmac, $dstmac, $srcip, $srcport, $dstip, $dstport, $payload) = pfring_l7_next($ring);

    print "Ethernet from => $srcmac to => $dstmac\n";
    print "TCP      from => $srcip:$srcport to => $dstip:$dstport\n";
    print "Payload       => $payload\n";

    $got ++;
  }

pfring_close($ring);

1;
