#
# Perl Net-Pfring - Perl binding for PF-RING
#
# Makefile.PL - Makefile generator for Perl Pfring
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

BEGIN { require 5.008 }

use ExtUtils::MakeMaker;

warn <<"EOW";

  Remember to read the README file!

  Warning:
     The Perl Pfring module is ALPHA software.  It is __only__ 'alpha'
     because its interface is not standardized.  The 'alpha' status
     does not refer to code quality or stability.

  Use `make test' to execute self tests.
  Use `make testdb' to start the tests defined in test.pl under perl debugger.

  Use `make install' to install the Perl Pfring package.
  This will install the necessary files in your Perl directory.
  You may need to have root previliges in order to do so.

  Execute 'perldoc Pfring' after installing to have access to the documentation.

EOW

#
# Kernel dependent variables
#
my $kernel=`uname -r`;
chop($kernel);

WriteMakefile(
    'NAME'         => 'Net::Pfring',
    'VERSION_FROM' => 'Pfring.pm',
    'AUTHOR'       => 'Rocco Carbone <rocco /at/ ntop /dot/ org>',
    'ABSTRACT'     => 'Perl binding for PF-RING',
    'DISTNAME'     => 'Net-Pfring',
    'OBJECT'       => 'Pfring$(OBJ_EXT) ../../lib/libpfring.a',
    'LIBS'         => '',
    'DEFINE'       => '',
    'INC'          => "-Ilib -I/lib/modules/$kernel/source/include -I../../lib",
    'PM'           => {'Pfring.pm' => '$(INST_LIBDIR)/Pfring.pm'},
    'clean'        => { FILES => "Makefile.old" },
    XSPROTOARG     => '-noprototypes',
    'dist'         => { COMPRESS => 'gzip', SUFFIX => 'gz'},
);


sub MY::post_initialize
{
  my ($self) = shift;
}

sub MY::postamble
  {
"
   test1 : pure_all
\tPERL_DL_NONLAZY=1 \$(FULLPERL) -I\$(INST_ARCHLIB) -I\$(INST_LIB) -I\$(PERL_ARCHLIB) -I\$(PERL_LIB) t/1.open.t

";
}


