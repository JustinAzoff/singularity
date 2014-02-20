package fileutil;
use strict;
use warnings;

use base 'Exporter';
our @EXPORT_OK = qw(write_file);

sub write_file {
	my ($filename, $contents) = @_;

	my $tf = $filename . ".tmp";

	open(my $tmp, ">", $tf) or die "Cannot open $tf: $!";
	print $tmp $contents;
	close($tmp);
	
	rename ($tf, $filename) or die "Cannot write to $filename";
}

1;
