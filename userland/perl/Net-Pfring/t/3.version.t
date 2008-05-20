#                                                                -*- perl -*-
# 3.version.t - test of Perl Module for open/version/close PF-Ring devices
#
# Perl Pfring - Perl binding for PF-Ring
#
# Copyright (c) 2008 Rocco Carbone
#
# Rocco Carbone <rocco /at/ ntop /dot/ org> 2Q 2008
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# This program is free software; you can redistribute it and/or modify 
# it under the same terms as Perl itself.
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#

use Net::Pfring;

# here is the main

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $ring;}

my $device = "eth0";

my $major;
my $minor;
my $level;

$ring = Net::Pfring::Open($device, 1);
($major, $minor, $level) = Net::Pfring::Version($ring);
Net::Pfring::Close($ring);

print "ok 1 using PF-Ring ver $minor.$major.$level\n";

