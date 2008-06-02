#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 03-api.t - simple test for Net-Pfring functions availability
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

use Test::More;
use Net::Pfring;

plan tests => 4;

# check that the following functions are available
can_ok ('Net::Pfring', 'Open');
can_ok ('Net::Pfring', 'Close');
can_ok ('Net::Pfring', 'Version');
can_ok ('Net::Pfring', 'Next');


