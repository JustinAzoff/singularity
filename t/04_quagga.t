use strict;
use warnings;
use 5.010;
 
use Test::More tests => 2;
  
use quagga qw(gen_nullroute_cmd);

is(gen_nullroute_cmd("1.2.3.4"), "ip route 1.2.3.4 255.255.255.255 null0");
is(gen_nullroute_cmd("2600::aaaa"), "ipv6 route 2600::aaaa/128 null0");
