package Logger;
use strict;
use warnings;

use Sys::Syslog;
use base 'Exporter';
our @EXPORT_OK = qw(logit);

sub new {
	my $class = shift;
	my $self  = { @_ };
	die "missing config" unless defined $self->{config};
	bless $self, $class;
	return $self;
}

sub log {
	my ($self, $priority, $type, $msg) = @_; 
	return 0 unless ($priority =~ /info|err|debug/);


	my $programname = $self->{config}->{logprepend} . "_$type";

	openlog($programname, 'user,cons', 'user');
	syslog($priority, $msg);
	closelog();
	return 1;
}

1;
