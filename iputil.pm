package iputil;
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use strict;
use warnings;
use base 'Exporter';
our @EXPORT_OK = qw(ip_version);

sub ip_version
{
	my $ipaddress = shift;
	#check to see what version of IP, return 0 if the IP is invalid
        return 4 if is_ipv4($ipaddress);
        return 6 if is_ipv6($ipaddress);
        return 0;
}


1;
