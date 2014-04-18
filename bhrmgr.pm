package BHRMGR;
use warnings;
use strict;

use POSIX qw(strftime);
use Email::MIME;
use Email::Sender::Simple qw(sendmail);

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
	my $endtime = 0;
	my $seconds = expand_duration($duration);
	$endtime = (time()+$seconds) if $seconds;
	$self->log("info", "BLOCK", "IP=$ipaddress HOSTNAME=$log_hostname WHO=$service WHY=$reason UNTIL=$endtime")
}

sub remove_block
{
	my ($self, $ipaddress, $service, $reason) = @_;
	return 1 if (!$self->{db}->is_ip_blocked($ipaddress));

	$self->{db}->unblock($ipaddress, $service, $reason);

	$self->{rtr}->nullroute_remove($ipaddress);

	$self->log("info", "UNBLOCK", "IP=$ipaddress WHO=$service WHY=$reason");
}

sub reconcile {
	my ($self, $force) = @_;
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

	#check to see if things are too out of sync.
	my $reconcile_max = $self->{config}->{'reconcile_max'};
	my $missing_rtr_count = scalar(@missing_rtr);
	my $missing_db_count = scalar(@missing_db);
	if($force != 1 && $missing_rtr_count + $missing_db_count > $reconcile_max) {
		$self->log("error", "reconcile", "Missing too many entries db=$missing_db_count rtr=$missing_rtr_count");
		return 1;
	}

	$self->log("info", "reconcile", "db=$missing_db_count rtr=$missing_rtr_count");

	if(@missing_rtr) {
		foreach my $ip (@missing_rtr) {
			$self->{rtr}->nullroute_add($ip);
		}
	}
	if(@missing_db) {
		foreach my $ip (@missing_db) {
			$self->{rtr}->nullroute_remove($ip);
		}
	}
	return (\@missing_db, \@missing_rtr);
}

sub unblock_expired {
	my $self = shift;
	my $unblock_queue = $self->{db}->unblock_queue();
	foreach my $rec (@{ $unblock_queue }) {
		$self->remove_block($rec->{ip}, "cronjob", "Block Time Expired");
	}
	return 0;
}

sub write_website {
	my $self = shift;
	my $out_dir = $self->{config}->{'statusfilelocation'};
	chdir($out_dir) or die "Error: could not chdir to $out_dir";

	my $fn_html    	= $self->{config}->{'filenhtmlnotpriv'};
	my $fn_csv   	= $self->{config}->{'filecsvnotpriv'};
	my $fn_csv_priv	= $self->{config}->{'filecsvpriv'};

	my $blocklist = $self->{db}->list;
	my $block_count = scalar(@{$blocklist});

	#Write out csv files
	my $csv = "";
	my $csv_priv = "";
	foreach my $b (@{ $blocklist }) {
		$csv      .= "$b->{ip},$b->{when},$b->{until}\n";
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

sub send_digest {
	my $self = shift;

	my $queueline = "";
	my $queuehaddata = 0;

	my $block_notify = $self->{db}->block_notify_queue();
	my $unblock_notify = $self->{db}->unblock_notify_queue();

	my $block_count = scalar(@{$block_notify});
	my $unblock_count = scalar(@{$unblock_notify});

	#nothing to do
	return 0 if($block_count + $unblock_count == 0);

	#build email body
	#print activity counts
	my $emailbody = "Block totals:\n";
	my $stats = $self->{db}->stats();
	foreach my $row (@{$stats}) {
		$emailbody .= "$row->{who}	$row->{count}\n";
	}
	$emailbody .= "\nActivity since last digest:\nBlocked: $block_count\nUnblocked: $unblock_count\n";
	
	#add blocked notifications to email body
	foreach my $b (@{ $block_notify }) {
		my $reverse = $b->{reverse} || "none";
		$emailbody .= "BLOCK - $b->{when} - $b->{who} - $b->{ip} - $reverse - $b->{why} $b->{until}\n";
		$self->{db}->mark_block_notified($b->{block_id});
	}
	foreach my $b (@{ $unblock_notify }) {
		my $reverse = $b->{reverse} || "none";
		$emailbody .= "UNBLOCK - $b->{unblock_when} - $b->{unblock_who} - $b->{unblock_why} - $b->{ip} - $reverse"; #no newline
		$emailbody .= " Originally Blocked by: $b->{block_who} for $b->{block_why}\n";
		$self->{db}->mark_unblock_notified($b->{block_id});
	}

	my $emailfrom = $self->{config}->{'emailfrom'};
	my $emailto = $self->{config}->{'emailto'};
	my $emailsubject = $self->{config}->{'emailsubject'};

	my $message = Email::MIME->create (
		header_str => [
			From    => $emailfrom,
			To      => $emailto,
			Subject => $emailsubject,
		],
		attributes => {
			encoding => 'quoted-printable',
			charset  => 'ISO-8859-1',
		},
		body_str => $emailbody,
	);
	sendmail($message);
	return 0;
}

sub send_stats {
	my $self = shift;
	my $sendstats = $self->{config}->{'sendstats'};

	return 0 if(!$sendstats);
	my $stats = $self->{db}->stats();
	foreach my $row (@{$stats}) {
		$self->log("info", "STATS", "WHO=$row->{who} TOTAL_BLOCKED=$row->{count}");
	}
}

1;
