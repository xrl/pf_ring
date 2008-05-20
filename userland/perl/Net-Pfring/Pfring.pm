#
# Pfring.pm - interface description file for perl writers
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

#
# The name of the game!
#
package Net::Pfring;


#
# useful variables here
#
$VERSION = '0.01';
$Debug   = 1;

#
# What we need is...
#
require 5.008;

require Exporter;
require DynaLoader;
require AutoLoader;

#
# What we use is...
#
use strict;
use Carp;
use vars qw ($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

@ISA       = qw (Exporter DynaLoader AutoLoader);
@EXPORT    = qw ($VERSION);
@EXPORT_OK = qw ();

sub AUTOLOAD {
  # This AUTOLOAD is used to 'autoload' constants from the constant()
  # XS function.  If a constant is not found then control is passed
  # to the AUTOLOAD in AutoLoader.

  my $constname;
  ($constname = $AUTOLOAD) =~ s/.*:://;
  my $val = constant($constname, @_ ? $_[0] : 0);
  if ($! != 0) {
    if ($! =~ /Invalid/) {
      $AutoLoader::AUTOLOAD = $AUTOLOAD;
      goto &AutoLoader::AUTOLOAD;
    }
    else {
      croak "Your vendor has not defined Net::Pfring macro $constname";
    }
  }
  eval "sub $AUTOLOAD { $val }";
  goto &$AUTOLOAD;
}


# Ok, let's boot now!
bootstrap Net::Pfring $VERSION;

#
# The basic operations offered by Pfring are provided through the following calls:
# 'Open', 'Close', 'Version', 'Recv'
#

package Net::Pfring;


#
# Attempt to open a device for packet capturing and filtering
#
sub Open {
  my $device = shift;
  my $promisc = shift;

  # Call the low-level routine
  Net::Pfring::_open ($device, $promisc);
}

#
# Attempt to close a device
#
sub Close {
  my $pfring = shift;

  # Call the low-level routine
  Net::Pfring::_close ($pfring);
}


#
# Attempt to obtain version information
#
sub Version {
  my $pfring = shift;

  my $major = undef;
  my $minor = undef;
  my $level = undef;

  # Call the low-level routine
  ($major, $minor, $level) = Net::Pfring::_version ($pfring);
}

#
# Attempt to receive packets
#
sub Recv {
  my $pfring = shift;

  my $payload;

  # Call the low-level routine
  $payload = Net::Pfring::_recv ($pfring);
}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Perl Pfring - Simple interface to PF-Ring

=head1 SYNOPSIS

  use Net::Pfring;

  #constructor
  $ring = Net::Pfring ($device, $promisc, $reentrant);

  #methods
  ($status, $reason) = $ring->Close ();

=head1 DESCRIPTION
This module implements a simple perl interface to PF-Ring.

=head1 Notations and Conventions

       Pfring      Static 'top-level' class name
       $ring       Pfring object
       $status     Return variable (boolean) indicating the result of a method
       $reason     Return variable (string) containing the error message,
                   in case of failure, undef otherwise

=head1 INSTALLATION

To install Perl Pfring extention module, just change to the directory in
which this file is found and type the following:

	perl Makefile.PL
	make
	make install

This will copy Pfring.pm to your perl library directory for use by all Perl
scripts. You probably must be root to do this. Once installed this module,
you can load the Perl Pfring routines in your Perl scripts with the line:

	use Pfring;

If you don't have sufficient privileges to install Pfring.pm in the Perl
library directory, you can put Pfring.pm into some convenient place, such
as your home directory and prefix all Perl scripts that call it with
something along the lines of the following preamble:

	use lib '/full_path_of_my_home_dir/';
	use Pfring;


Before or after you install this module, you can perform some tests to
check the whole functionalities of the module with the following command:

        make test


=head1 BUGS

No bugs are known at this time.

=head1 AUTHORS

Perl Pfring has been written by Rocco Carbone <rocco /at/ ntop /dot/ org>

=head1 COPYRIGHT

Copyright (c): 2008 Rocco Carbone
This program is free software; you can redistribute it and/or modify under
the same terms as Perl itself.

=cut

