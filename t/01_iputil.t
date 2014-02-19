use strict;
use warnings;
use 5.010;
 
use Test::More tests => 7;

SKIP: {
    eval {
        require iputil;
        iputil->import(qw(is_ipv4 is_ipv6 normalize_ip));
    };
    skip "perl version too old to test iputil", 7 if $@;
 
    ok( is_ipv4("1.2.3.4")   == 1);
    ok( is_ipv4("1.2.3.400") == 0);
    ok( is_ipv4("2.3.4")     == 0);

    ok( is_ipv6("2607:f8b0:4000:806::1014") == 1 );
    ok( is_ipv6("260z:f8b0:4000:806::1014") == 0 );

    is( normalize_ip("001.002.003.004"), "1.2.3.4");
    is( normalize_ip("2600:0:0::aaaa"), "2600::aaaa");
}
