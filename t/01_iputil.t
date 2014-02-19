use strict;
use warnings;
use 5.010;
 
use Test::More tests => 3;

use iputil qw(ip_version);
 
is(ip_version("1.2.3.4"), 4);
is(ip_version("2600::aaaa"), 6);
is(ip_version("foo"), 0);
