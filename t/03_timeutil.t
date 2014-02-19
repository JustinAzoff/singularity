use strict;
use warnings;
use 5.010;
 
use Test::More tests => 8;
  
use timeutil qw(expand_duration);

my $hour = 60*60;
my $day = $hour * 24;
my $month = $day * 30;
my $year = $day * 365;

is(expand_duration("0"), 0);
is(expand_duration("10"), 10);
is(expand_duration("3600"), 3600);
is(expand_duration("1h"), $hour);
is(expand_duration("2d"), 2 * $day);
is(expand_duration("14d"), 14 * $day);
is(expand_duration("1y"), $year);

is(expand_duration("1z"), undef);
