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

plan tests => 10;

# check that the following functions are available
can_ok ('Net::Pfring', 'open');
can_ok ('Net::Pfring', 'close');
can_ok ('Net::Pfring', 'next');
can_ok ('Net::Pfring', 'stats');
can_ok ('Net::Pfring', 'version');

can_ok ('Net::Pfring', 'pfring_open');
can_ok ('Net::Pfring', 'pfring_close');
can_ok ('Net::Pfring', 'pfring_next');
can_ok ('Net::Pfring', 'pfring_stats');
can_ok ('Net::Pfring', 'pfring_version');


