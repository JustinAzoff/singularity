use strict;
use warnings;
use 5.010;
 
use Test::More tests => 3;
  
use dnsutil qw(reverse_lookup);
 
is(reverse_lookup("8.8.8.8"), "google-public-dns-a.google.com", "reverse 8.8.8.8");
is(reverse_lookup("192.168.99.99"), undef, "reverse something that should fail");

is(reverse_lookup("2600::aaaa"), "www.sprint.com", "reverse an ipv6 address")
