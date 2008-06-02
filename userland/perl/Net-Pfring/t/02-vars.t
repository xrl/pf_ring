#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 02-vars.t - simple test for Net-Pfring variables availability
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

plan tests => 1;

# check that the following variables are available
can_ok ('Net::Pfring', 'VERSION');


