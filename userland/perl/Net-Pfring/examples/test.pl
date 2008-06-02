
use Net::Pfring;

my $device  = "eth0";
my $snaplen = 1500;
my $ring;
my $packet;
my $packets = 10;
my $got;

$| = 1;

# Open
print "Attempting to open $device ... ";
$ring = Net::Pfring::Open($device, 1, $snaplen) || die "failed!\n";
print "ok\n";

# Capturing
print "Attempting to receive packets ...\n";

while (! $packets || $got < $packets)
  {
    $packet = Net::Pfring::Next($ring);
    if ($packet)
      {
	$got ++;
	print "#$got => $packet\n";
      }
  }

print "Done! captured #$got packets at the application level\n";
Net::Pfring::Close($ring);

1;
