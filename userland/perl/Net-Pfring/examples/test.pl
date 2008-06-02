
use Net::Pfring;

my $device  = "eth0";
my $snaplen = 1500;
my $ring;
my $packet;
my $packets = 10;
my $got;

$| = 1;

# Open
print "Attempting to open device $device ... ";
$ring = Net::Pfring::open($device, 1, $snaplen) || die "failed!\n";
print "ok\n";

# Capturing
print "Attempting to receive packets ...\n";

while (! $packets || $got < $packets)
  {
    $packet = Net::Pfring::next($ring);
    if ($packet)
      {
	$got ++;
	print "#$got => $packet\n";
      }
  }

print "Done! captured #$got packets at the application level\n";
Net::Pfring::close($ring);

1;
