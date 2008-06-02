#
# 0.boot.t - simple test for Net-Pfring module availability
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
END {print "not ok 1\n" unless $loaded;}

$loaded = 1;
print "ok 1\n";

