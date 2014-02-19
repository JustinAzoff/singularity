package iputil;
use strict;
use warnings;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);

use base 'Exporter';
our @EXPORT_OK = qw(is_ipv4 is_ipv6 normalize_ip);

sub is_ipv4 {
    my ($ip) = @_;
    return defined(inet_pton(AF_INET, $ip));
}

sub is_ipv6 {
    my ($ip) = @_;
    return defined(inet_pton(AF_INET6, $ip));
}

sub normalize_ip {
    my ($ip) = @_;
    my $ipv4_address = inet_pton(AF_INET, $ip);
    return inet_ntop(AF_INET, $ipv4_address) if(defined($ipv4_address));

    my $ipv6_address = inet_pton(AF_INET6, $ip);
    return inet_ntop(AF_INET6, $ipv6_address) if(defined($ipv6_address));
    return undef
}

1;
