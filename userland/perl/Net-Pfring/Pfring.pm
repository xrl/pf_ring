#
# Perl Net-Pfring - Perl binding for PF-RING
#
# Pfring.pm - interface description file for perl writers
#
# The basic operations offered by Net-Pfring are provided
# through the following calls:
#
# 'Open', 'Close', 'Next', 'Version'
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

# The name of the game!
package Net::Pfring;

# What we need is...
require 5.008;
require Exporter;
require DynaLoader;
require AutoLoader;

# What we use is...
use strict;
use Carp;
use vars qw ($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

# useful variables here
our $VERSION   = '0.01';
our @ISA       = qw (Exporter DynaLoader AutoLoader);
our @EXPORT    = qw ($VERSION);
our @EXPORT_OK = qw ();

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


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


#
# Attempt to open a PF-RING aware device for packet capturing and filtering
#
sub Open {
  my $device  = shift;
  my $promisc = shift;
  my $caplen  = shift;

  # Call the low-level routine
  Net::Pfring::_open ($device, $promisc, $caplen);
}

#
# Attempt to close a PF-RING aware device
#
sub Close {
  my $pfring = shift;

  # Call the low-level routine
  Net::Pfring::_close ($pfring);
}


#
# Attempt to obtain PF-RING version information
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
# Attempt to read next incoming packet from the PF-RING aware interface.
# The call is always blocked until a packet is available.
#
sub Next {
  my $pfring = shift;

  my $payload;

  # Call the low-level routine
  $payload = Net::Pfring::_next ($pfring);
}


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

1;

__END__


=head1 NAME

Perl Net-Pfring - Perl interface to PF-RING(3) Linux High Speed Packet Capture library


=head1 VERSION

Version 0.01


=head1 SYNOPSIS

  use Net::Pfring;

  # Open a PF-RING aware device for packet capturing and filtering
  my $ring = Net::Pfring::Open ($device, $promisc, $snaplen);

  # Close a PF-RING aware device previously open
  Net::Pfring::Close ($ring);

  # Read next incoming packet from a PF-RING aware device previously open
  $packet = Net::Pfring::Next ($ring);

  # Get the major, minor and patch identifiers of a PF-RING aware device previously open
  ($major, $minor, $patch) = Net::Pfring::Version ($ring);


=head1 DESCRIPTION

C<Net::Pfring> module implements a simple perl interface to PF-RING(3)
Linux High Speed Packet Capture library.

The documentation for PF-RING describes itself as:

   "PF_RING is a high speed packet capture library that turns a commodity
    PC into an efficient and cheap network measurement box suitable for
    both packet and active traffic analysis and manipulation"

This version of the C<Net::Pfring> module only provides few functions
just to start basic opening, capturing and filtering packets from
PF-RING aware devices, and they are implemented as simple wrappers
for the C functions with a little bit of extension to provide more
perl-friendliness.

C<:functions> exports the function names with the same names as the C library,
so you can write C<pfring_open()> instead of C<Net::Pfring::open()>
for example.


=head1 FUNCTIONS

All functions defined by C<Net::Pfring> are direct mappings to the
PF_RING functions.  Consult the PF_RING(3) documentation and source code
for more information.

=over 4

=item B<pfring_open($device, $snaplen, $promisc)>

Returns a packet capture handle for looking at packets on a PF_RING
aware device.  The C<$device> parameter specifies which network interface to
capture packets from.  The C<$snaplen> and C<$promisc> parameters specify
the maximum number of bytes to capture from each packet (the snapshot length),
and whether to put the interface into promiscuous mode, respectively.

The packet handle will be undefined if an error occurs.

B<Example>

    my $ring = Net::Pfring::Open("eth0", 1, 1500) || die "failed!\n";

=item B<pfring_close($ring)>

Close the packet capture PF-RING aware device associated with the handle C<$ring> previously open.

=item B<pfring_next($ring)>

Return the next available packet on the interface associated with
packet handle C<$ring> previously open when available.

B<Example>

    my $packet = Net::Pfring::Next($ring);

=item B<pfring_version()>

Returns the major, minor and patch identifiers of the Linux kernel module which current handles the
C<PF_RING> aware device associated with the handle C<$ring> previously open.

=back


=head1 LIMITATIONS

The following limitations apply to this version of C<Net::Pfring>.

=over 

=item *

At present, only one Net::Pfring::Open() function can be called
at any time as the low level PF_RING identifier is stored in a global variable.

=back


=head1 EXAMPLES

See the F<example/> and F<t/> directories of the C<Net::Pfring> distribution
for examples on using this module.


=head1 INSTALLATION

To install Perl Net-Pfring extension module, just change to the directory in
which this file is found and type the following:

	perl Makefile.PL
	make
	sudo make test
	sudo make install

This will copy Pfring.pm to your perl library directory for use by all Perl
scripts. You probably must be root to do this. Once installed this module,
you can load the Perl Net-Pfring routines in your perl scripts with the line:

	use Net::Pfring;

If you don't have sufficient privileges to install Pfring.pm in the perl
library directory, you can put Pfring.pm into some convenient place, such
as your home directory and prefix all perl scripts that call it with
something along the lines of the following preamble:

	use lib '/full_path_of_my_home_dir/';
	use Net::Pfring;


Before or after you install this module, you can perform some tests to
check the whole functionalities of the module with the following command:

        make test


=head1 BUGS

No bugs are known at this time.


=head1 AUTHORS

Perl Net-Pfring has been written by Rocco Carbone <rocco /at/ ntop /dot/ org>


=head1 COPYRIGHT AND LICENSE

Copyright (c) 2008 Rocco Carbone <rocco /at/ ntop /dot/ org>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8 or,
at your option, any later version of Perl 5 you may have available.


=head1 SEE ALSO

=head2 Documentation

See the documentation for PF-RING Linux High Speed Packet Capture available at

L<https://svn.ntop.org/trac/browser/trunk/PF_RING/doc/UsersGuide.pdf>

=head2 Base Libraries

L<pfring(3)>

The source code for the C<pfring(3)> library is available from
L<svn co https://svn.ntop.org/svn/ntop/trunk/PF_RING/>

=head2 Perl Modules

L<Net::Packet> or L<NetPacket> for decoding and creating network packets

=cut

