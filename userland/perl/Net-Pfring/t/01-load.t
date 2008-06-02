#
# Perl Net-Pfring - Perl binding for PF_RING
#
# 01-load.t - simple test for Net-Pfring module availability
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

use Test::More tests => 1;

use_ok ('Net::Pfring');
diag ("Loading Net::Pfring $Net::Pfring::VERSION under Perl $]");
