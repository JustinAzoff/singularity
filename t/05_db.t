use strict;
use warnings;
use 5.010;
 
use Test::More tests => 2;
use Config::Simple;
use Data::Dumper;
 
use bhrdb qw(BHRDB);

my $configfile = $ENV{BHR_CFG};
my %config;
Config::Simple->import_from($configfile, \%config);
my $db = BHRDB->new(config => \%config);

my $record = $db->get_last_record("1.1.1.1");

print Dumper($record);
is($record->{duration}, 1);

my $record = $db->get_last_record("222.1.1.1");

is($record, undef);
