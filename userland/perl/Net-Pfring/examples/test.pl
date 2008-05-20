
use Net::Pfring;

my $device = "eth0";
my $ring;
my $payload;
my $packets = 10;
my $got;

$| = 1;

# Open
print "Attempting to open $device ... ";
$ring = Net::Pfring::Open($device, 1) || die "failed!\n";
print "ok\n";

# Capturing
print "Attempting to receive packets ...\n";

while (! $packets || $got < $packets)
  {
    $payload = Net::Pfring::Recv($ring);
    if ($payload)
      {
	$got ++;
	print "#$got => $payload\n";
      }
  }

print "Done! captured #$got packets at the application level\n";
Net::Pfring::Close($ring);

1;
