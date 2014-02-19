use strict;
use warnings;
use 5.010;
 
use Test::More tests => 5;
  
use iputil qw(is_ipv4 is_ipv6 normalize_ip);
 
ok( is_ipv4("1.2.3.4")   == 1);
ok( is_ipv4("1.2.3.400") == 0);
ok( is_ipv4("2.3.4")     == 0);

ok( is_ipv6("2607:f8b0:4000:806::1014") == 1 );
ok( is_ipv6("260z:f8b0:4000:806::1014") == 0 );


