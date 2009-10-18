#
# Perl Net-Pfring - Perl binding for PF_RING
#
# Makefile.PL - Makefile generator for Perl Net-Pfring
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

require 5.008;

use ExtUtils::MakeMaker;

warn <<"EOW";

  Remember to read the README file!

  Warning:
     The perl Net-Pfring module is ALPHA software.  It is __only__ 'alpha'
     because its interface is not standardized.  The 'alpha' status
     does not refer to code quality or stability.

  Use `make test' to execute self tests.

  Use `make install' to install the perl Net-Pfring package.
  This will install the necessary files in your perl directory.
  You may need to have root previliges in order to do so.

  Execute 'perldoc Pfring' after installing to have access to the documentation.

EOW

#
# Kernel dependent variables
#
my $kernel=`uname -r`;
chop($kernel);

WriteMakefile(
    NAME         => 'Net::Pfring',
    VERSION_FROM => 'Pfring.pm',
    AUTHOR       => 'Rocco Carbone <rocco /at/ ntop /dot/ org>',
    ABSTRACT     => 'Perl binding for PF_RING',
    DISTNAME     => 'Net-Pfring',
    OBJECT       => 'Pfring$(OBJ_EXT) ../../lib/libpfring.a',
    DEFINE       => '',
    CCFLAGS      => '',
    LIBS         => '',
    INC          => "-Ilib -I../../../kernel -I../../lib",
    PM           => { 'Pfring.pm' => '$(INST_LIBDIR)/Pfring.pm' },
    XSPROTOARG   => '-noprototypes',
    clean        => { FILES => "Makefile.old" },
    dist         => { COMPRESS => 'gzip', SUFFIX => 'gz'},
);
