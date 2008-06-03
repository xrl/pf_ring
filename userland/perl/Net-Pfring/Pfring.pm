#
# Perl Net-Pfring - Perl binding for PF_RING
#
# Pfring.pm - interface description file for perl writers
#
# The basic operations offered by Net-Pfring are provided
# through the following calls:
#
# 'open', 'close', 'next', 'stats', 'version',
# 'ethernet, 'l7_next', 'l347_next'
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
require DynaLoader;  # ROCCO: rework it
require AutoLoader;  # ROCCO: rework it

# What we use is...
use strict;
use Carp;
use vars qw ($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

# useful variables here

# functions names and aliases (thanks to Net-Pcap)
my @func_short_names = qw (open close next stats version ethernet l7_next l347_next header);
my @func_long_names = map { "pfring_$_" } @func_short_names;
{
  no strict "refs";
  for my $func (@func_short_names) {
    *{ __PACKAGE__ . "::pfring_$func" } = \&{ __PACKAGE__ . "::" . $func }
  }
}

our %EXPORT_TAGS = (functions => [ @func_long_names ]);

our $VERSION   = '0.01';
# ROCCO: rework it
our @ISA       = qw (Exporter DynaLoader AutoLoader);
our @EXPORT    = qw ($VERSION);
our @EXPORT_OK = @{$EXPORT_TAGS{functions}};


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


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#
# Attempt to open a PF_RING aware device for packet capturing and filtering
#
sub open {
  my $device  = shift;
  my $promisc = shift;
  my $caplen  = shift;

  # Call the low-level routine
  Net::Pfring::_open ($device, $promisc, $caplen);
}

#
# Attempt to close a PF_RING aware device
#
sub close {
  my $pfring = shift;

  # Call the low-level routine
  Net::Pfring::_close ($pfring);
}


#
# Attempt to read next incoming packet from a PF_RING aware interface previuosly open.
# The call always blocks until a packet is available.
#
sub next {
  my $pfring = shift;

  my $packet;

  # Call the low-level routine
  $packet = Net::Pfring::_next ($pfring);
}


#
# Attempt to obtain PF_RING statistics information
#
sub stats {
  my $pfring = shift;

  my $received = undef;
  my $dropped  = undef;

  # Call the low-level routine
  ($received, $dropped) = Net::Pfring::_stats ($pfring);
}


#
# Attempt to obtain PF_RING version information
#
sub version {
  my $pfring = shift;

  my $major = undef;
  my $minor = undef;
  my $level = undef;

  # Call the low-level routine
  ($major, $minor, $level) = Net::Pfring::_version ($pfring);
}


#
# Attempt to read next incoming packet from a PF_RING aware interface previuosly open,
# and return only the ethernet header.
# The call always blocks until a packet is available.
#
sub ethernet {
  my $pfring = shift;

  my $eth;

  # Call the low-level routine
  $eth = Net::Pfring::_ethernet ($pfring);
}


#
# Attempt to read next incoming packet from a PF_RING aware interface previuosly open,
# and return all information relevant at the application level, including:
# source and destination MAC addresses
# source and destination IP addresses
# source and destination port number
# packet payload
#
# The call always blocks until a packet is available.
#
sub l7_next {
  my $pfring = shift;

  my ($srcmac, $dstmac, $srcip, $srcport, $dstip, $dstport, $payload);

  # Call the low-level routine
  ($srcmac, $dstmac, $srcip, $srcport, $dstip, $dstport, $payload) = Net::Pfring::_l7_next ($pfring);
}


#
# Attempt to read next incoming packet from a PF_RING aware interface previuosly open,
# and return all information relevant at the application level, including:
# timestamp in microseconds
# length of the portion of packet on the wire
# length of the packet off the wire
# ethernet type
# vlan id
# protocol
# ipv4 tos
# TCP flags
# source IP addresses and port number
# destination IP addresses and port number
# Ethernet offset
# vlan offset
# IP offset
# TCP offset
# Layer 7 offset
# the payload itsself
#
# The call always blocks until a packet is available.
#
sub l347_next {
  my $pfring = shift;

  my ($secs, $microsecs, $caplen, $len, $ethtype, $vlan, $protocol, $tos, $tcpflags,
      $srcip, $srcport, $dstip, $dstport,
      $ethoffset, $vlanoffset, $ipoffset, $tcpoffset, $l7offset,
      $full, $packet);

  # Call the low-level routine
  ($secs, $microsecs, $caplen, $len, $ethtype, $vlan, $protocol, $tos, $tcpflags,
   $srcip, $srcport, $dstip, $dstport,
   $ethoffset, $vlanoffset, $ipoffset, $tcpoffset, $l7offset,
   $full, $packet) = Net::Pfring::_l347_next ($pfring);
}


sub header {
  my ($pfring) = shift;

  my %header;
  my $k;

  # Call the low-level routine
  Net::Pfring::_header ($pfring, \%header);

  for $k (sort (keys (%header)))
    {
      print "Pfring.pm - $k => $header{$k}\n";
    }
  print "\n";

  return %header;
}


1;

__END__


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


=head1 NAME

Perl Net-Pfring - Perl interface to PF_RING(3) Linux High Speed Packet Capture library


=head1 VERSION

Version 0.01


=head1 SYNOPSIS

  use Net::Pfring;

  or for better usability

  use Net::Pfring qw(:functions);


  # Open a PF_RING aware device for packet capturing and filtering
  my $ring = Net::Pfring::open ($device, $promisc, $snaplen);

  # Close a PF_RING aware device previously open
  Net::Pfring::close ($ring);

  # Read next incoming packet from a PF_RING aware device previously open
  $packet = Net::Pfring::next ($ring);

  # Get statistics information from a PF_RING aware device previously open
  ($received, $dropped) = Net::Pfring::stats ($ring);

  # Get the major, minor and patch identifiers of a PF_RING aware device previously open
  ($major, $minor, $patch) = Net::Pfring::version ($ring);


=head1 DESCRIPTION

C<Net::Pfring> module implements a simple perl interface to PF_RING(3)
Linux High Speed Packet Capture library.

The documentation for PF_RING describes itself as:

   "PF_RING is a high speed packet capture library that turns a commodity
    PC into an efficient and cheap network measurement box suitable for
    both packet and active traffic analysis and manipulation"

This version of the C<Net::Pfring> module only provides few functions
just to start basic opening, capturing and filtering packets from
PF_RING aware devices, and they are implemented as simple wrappers
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

=item B<Net::Pfring::open($device, $snaplen, $promisc)>

Returns a packet capture handle for looking at packets on a PF_RING
aware device.  The C<$device> parameter specifies which network interface to
capture packets from.  The C<$snaplen> and C<$promisc> parameters specify
the maximum number of bytes to capture from each packet (the snapshot length),
and whether to put the interface into promiscuous mode, respectively.

The packet handle will be undefined if an error occurs.

B<Example>

    my $ring = Net::Pfring::open("eth0", 1, 1500) || die "failed!\n";
    or
    my $ring = pfring_open("eth0", 1, 1500) || die "failed!\n";

=item B<Net::Pfring::close($ring)>

Close the packet capture PF_RING aware device associated with the handle C<$ring> previously open.

B<Example>

    Net::Pfring::close($ring);
    or
    pfring_close($ring);


=item B<pfring_next($ring)>

Return the next available packet on the interface associated with
packet handle C<$ring> previously open when available.

B<Example>

    my $packet = Net::Pfring::next($ring);
    or
    my $packet = pfring_next($ring);


=item B<Net::Pfring::stats()>

Returns statistics information about the C<PF_RING> aware device associated with the handle C<$ring> previously open.
The first returned value gives the number of packets received by the packet capture kernel driver, while the second
value gives the number of packets dropped by the packet capture kernel driver.

B<Example>

   ($received, $dropped) = Net::Pfring::stats($ring);
   or
   ($received, $dropped) = pfring_stats($ring);


=item B<Net::Pfring::version()>

Returns the major, minor and patch identifiers of the Linux kernel module which current handles the
C<PF_RING> aware device associated with the handle C<$ring> previously open.

B<Example>

   ($major, $minor, $patch) = Net::Pfring::version($ring);
   or
   ($major, $minor, $patch) = pfring_version($ring);

=back


=head1 LIMITATIONS

The following limitations apply to this version of C<Net::Pfring>.

=over 

=item *

At present, only one Net::Pfring::open() function can be called at any time
as the low level PF_RING handle identifier is stored in a global variable.

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

See the documentation for PF_RING Linux High Speed Packet Capture available at

L<https://svn.ntop.org/trac/browser/trunk/PF_RING/doc/UsersGuide.pdf>

=head2 Base Libraries

L<pfring(3)>

The source code for the C<pfring(3)> library is available from
C<svn co https://svn.ntop.org/svn/ntop/trunk/PF_RING/>

=head2 Perl Modules

L<Net::Packet> for decoding and creating network packets
L<Data::HexDump> for hexadecimal data dumper

=cut

