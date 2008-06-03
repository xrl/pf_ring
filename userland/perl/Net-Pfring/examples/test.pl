#
# Perl Net-Pfring - Perl binding for PF_RING
#
# test.pl - a valuable tutorial for the beginners
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

my $ring;
my ($major, $minor, $patch);

my $packet;
my $got;

my ($received, $dropped);

$| = 1;

# Open
print "Attempting to open device $device ... ";
$ring = pfring_open($device, 1, $snaplen) || die "Cannot open device $device!\n";

# Obtain version information
($major, $minor, $patch) = pfring_version($ring);
print "ok using PF_RING ver $major.$minor.$patch\n";

# Capturing
print "Attempting to read #$packets packets ...\n";
$got = 0;
while (! $packets || $got < $packets)
  {
#    $packet = pfring_next($ring);
    $packet = pfring_ethernet($ring);
    if ($packet)
      {
	$got ++;
	print "#$got => $packet\n";
      }
  }

# Obtain statistics information
($received, $dropped) = pfring_stats($ring);
print "Packets on PF_Ring device $device: received $received - dropped $dropped\n";

print "Done! captured #$got packets at the application level\n";
pfring_close($ring);

1;
