#                                                                -*- perl -*-
# 0.boot.t - test if the script is runnable
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
END {print "not ok 1\n" unless $loaded;}

$loaded = 1;
print "ok 1\n";

