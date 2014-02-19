package dnsutil;
use strict;
use warnings;
use Net::IP;
use Net::DNS;

use base 'Exporter';
our @EXPORT_OK = qw(reverse_lookup);

sub reverse_lookup
{
    my $ip = shift;
    my $ipo = new Net::IP ($ip);
    my $target = $ipo->reverse_ip;

    my $res = Net::DNS::Resolver->new;
    my $query = $res->query($target, "PTR");
    return undef if (! $query);
    
    foreach my $rr ($query->answer) {
        next unless $rr->type eq "PTR";
        my $hostname = $rr->rdatastr;
        $hostname =~ s/\.$//;
        return $hostname;
    }
    return undef;
}

1;
