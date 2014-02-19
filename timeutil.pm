package timeutil;
use strict;
use warnings;

use base 'Exporter';
use Scalar::Util 'looks_like_number';
our @EXPORT_OK = qw(expand_duration);

my $HOUR = 60*60;
my $DAY = 24 * $HOUR;
my $MONTH = 30 * $DAY;
my $YEAR = 365 * $DAY;

my %suffixes = (
    h => $HOUR,
    d => $DAY,
    m => $MONTH,
    y => $YEAR,
);

sub to_number {
    my $s = shift;
    return ($s + 0) if(looks_like_number($s));
    return undef;
}

sub chop_last {
    my $s = shift;
    my $len = length($s);
    my $first = substr($s, 0, $len - 1);
    my $last   = substr($s, -1);
    return ($first, $last);
}

sub expand_duration
{
    my $time = shift;
    my $last;
    my $maybe_number = to_number($time);
    return $maybe_number if defined($maybe_number);

    ($time, $last) = chop_last($time);

    my $multiplier = $suffixes{$last};
    return undef if not defined($multiplier);

    return $time * $multiplier;
    
    return $time;
}

1;
