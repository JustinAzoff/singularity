package BHRMGR;
use warnings;
use strict;

use bhrdb qw(BHRDB);
use logutil qw(Logger);
use quagga;
use dnsutil qw(reverse_lookup);
use timeutil qw(expand_duration);
use iputil qw(ip_version);

sub new {
	my $class = shift;
	my $self  = { @_ };
	die "missing config" unless defined $self->{config};
	bless $self, $class;
	$self->_initialize();
	return $self;
}

sub _initialize {
	my $self = shift;
	my $config = $self->{config};
	$self->{db} = BHRDB->new(config => $config);
	$self->{rtr} = quagga->new(config => $config);
	$self->{logger} = Logger->new(config => $config);
}

sub log {
        my ($self, $priority, $type, $msg) = @_;
	return $self->{logger}->log($priority, $type, $msg);
}

sub add_block {
	my ($self, $ipaddress, $service, $reason, $duration) = @_;

	return 1 if ($self->{db}->is_ip_blocked($ipaddress));
	my $hostname = reverse_lookup($ipaddress);

	$self->{db}->block($ipaddress, $hostname, $service, $reason, $duration);

	$self->{rtr}->nullroute_add($ipaddress);
		
	my $log_hostname = $hostname || "null";
	my $logprepend = "BHR";
	my $endtime = 0;
	my $seconds = expand_duration($duration);
	$endtime = (time()+$seconds) if $seconds;
	$self->log("info", "BLOCK", "IP=$ipaddress HOSTNAME=$log_hostname WHO=$service WHY=$reason UNTIL=$endtime")
}

sub remove_block
{
	my ($self, $ipaddress, $service, $reason) = @_;
	my $ipversion = ip_version($ipaddress);
	return 1 if (!$self->{db}->is_ip_blocked($ipaddress));

	$self->{db}->unblock($ipaddress, $service, $reason);

	$self->{rtr}->nullroute_remove($ipaddress);

	$self->log("info", "UNBLOCK", "IP=$ipaddress WHO=$service WHY=$reason");
}

1;
