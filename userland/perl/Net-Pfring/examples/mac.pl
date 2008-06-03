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
my $packets = 30;

my $packet;
my $got;
my $src;
my $dst;

my $ring = pfring_open($device, 1, $snaplen) || die "Cannot open device $device!\n";

$got = 0;
while (! $packets || $got < $packets)
  {
    $packet = pfring_ethernet($ring);

    $src = substr($packet, 0, 12);
    $dst = substr($packet, 12, 12);

    @src = split(//, $src);
    @dst = split(//, $dst);

    print "from => @src[0]@src[1]:@src[2]@src[3]:@src[4]@src[5]:@src[6]@src[7]:@src[8]@src[9]:@src[10]@src[11] to => @dst[0]@dst[1]:@dst[2]@dst[3]:@dst[4]@dst[5]:@dst[6]@dst[7]:@dst[8]@dst[9]:@dst[10]@dst[11]\n";

    $got ++;
  }

pfring_close($ring);

