package BHRMGR;
use warnings;
use strict;

use POSIX qw(strftime);

use bhrdb qw(BHRDB);
use logutil qw(Logger);
use quagga;
use dnsutil qw(reverse_lookup);
use timeutil qw(expand_duration);
use iputil qw(ip_version);
use fileutil qw(write_file);

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

sub reconcile {
    my $self = shift;
	my @db_ips = $self->{db}->list_ips();
	my @rtr_ips = $self->{rtr}->get_blocked_ips();
	
	#build hashes
	my %rtr_ips;
	my %db_ips;
	map($rtr_ips{$_}=1, @rtr_ips);
	map($db_ips{$_}=1,  @db_ips);
	
	#figure out the differences
	my @missing_rtr = grep(!defined($rtr_ips{$_}), @db_ips);
	my @missing_db  = grep(!defined($db_ips{$_}),  @rtr_ips);
	if(@missing_rtr) {
		foreach my $ip (@missing_rtr) {
			print "$ip is missing from the router\n";
			$self->{db}->delete($ip)
		}
	}
	if(@missing_db) {
		foreach my $ip (@missing_db) {
			print "$ip is missing from the db\n";
			my $hostname = reverse_lookup($ip);
			$self->{db}->block($ip, $hostname, "BHRscript", "reconciled", 0);
		}
	}
	return (\@missing_db, \@missing_rtr);
}

sub unblock_expired {
	my $self = shift;
	my $unblock_queue = $self->{db}->unblock_queue();
	foreach my $rec (@{ $unblock_queue }) {
		return $self->remove_block($rec->{ip},"Block Time Expired","cronjob");
	}
}

sub write_website {
    my $self = shift;
	my $out_dir = $self->{config}->{'statusfilelocation'};
	chdir($out_dir) or die "Error: could not chdir to $out_dir";

	my $fn_html    	= $self->{config}->{'filenhtmlnotpriv'};
	my $fn_csv   	= $self->{config}->{'filecsvnotpriv'};
	my $fn_csv_priv	= $self->{config}->{'filecsvpriv'};

	my $blocklist = $self->{db}->list;
	my $block_count = length($blocklist);

	#Write out csv files
	my $csv = "";
	my $csv_priv = "";
	foreach my $b (@{ $blocklist }) {
		$csv 	  .= "$b->{ip},$b->{when},$b->{until}\n";
		$csv_priv .= "$b->{ip},$b->{who},$b->{why},$b->{when},$b->{until}\n";
	}

	write_file($fn_csv, $csv);
	write_file($fn_csv_priv, $csv_priv);

	#Write out html file

	my $table_rows = "";
	foreach my $b (@{ $blocklist }) {
		my $from = strftime("%a %b %e %H:%M:%S %Y", (localtime $b->{when}));
		my $to =   strftime("%a %b %e %H:%M:%S %Y", (localtime $b->{until}));
		$to = "indefinite" if $b->{until} == 0;
		$table_rows .= <<HTML;
			<tr>
				<td> $b->{ip} </td>
				<td> $from </td>
				<td> $to </td>
			</tr>
HTML
	}

	my $created = localtime;
	my $html = <<HTML;
		<html>
		<p>Number of blocked IPs: $block_count</p>
		<p>This file is also available as a csv - <a href="bhlist.csv">bhlist.csv</a></p>
		<p>Created $created</p>
		<table border="1" width="100%">
		<thead>
			<tr> <th>IP</th> <th>Block Time</th> <th>Block Expires</th> </tr>
		</thead>
		<tbody>
		$table_rows
		</tbody>
		</table>
		</html>
HTML

	write_file($fn_html, $html);
	return 0;
}

1;
