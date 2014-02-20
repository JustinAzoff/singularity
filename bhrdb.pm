package BHRDB;
use warnings;
use strict;
#I dont think we are using NetAddr::IP
#use NetAddr::IP;
use DBI;
use iputil qw(ip_version);
use dnsutil qw(reverse_lookup);
use timeutil qw(expand_duration);

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
	my $db_host = $config->{databasehost};
	my $db_name = $config->{databasename};
	my $db = "dbi:Pg:dbname=${db_name}";#;host=${db_host}";
	my $dbh = DBI->connect("$db", "", "");
	$self->{dbh} = $dbh;
}

sub DESTROY {
	my $self = shift;
	$self->{dbh}->disconnect() if $self->{dbh};
}

sub fetchall_arrayref {
	my ($self, $query)  =  @_ ;
	my $dbh = $self->{dbh};
	my $sth = $dbh->prepare($query) or die $dbh->errstr;
	$sth->execute() or die $dbh->errstr;
	return $sth->fetchall_arrayref({});
}


sub is_ip_blocked {
	my ($self, $ipaddress) = @_;
	my $dbh = $self->{dbh};
	my $sql1 =
			q{
			select count(*)
			from blocklist
			inner join blocklog
			on blocklog.block_id = blocklist.blocklist_id
			where blocklog.block_ipaddress = ?
			};
	my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth1->execute($ipaddress) or die $dbh->errstr;
	my $ipexists = $sth1->fetchrow();
	return $ipexists;
}	#end of check if IP blocked sub
	
sub block {
	my ($self, $ip, $hostname, $service, $reason, $duration) = @_;

	my $endtime = 0;
	my $seconds = expand_duration($duration);
	$endtime = (time()+$seconds) if $seconds;
	
	
	my $dbh = $self->{dbh};
	#database operations for adding to logs
	$dbh->begin_work;
	#create the blocklog entry and return the block_id for use in creating blocklist entry
	my $sql1 = q{
		INSERT INTO blocklog (block_when,block_ipaddress,block_reverse,block_who,block_why) VALUES (to_timestamp(?),?,?,?,?) RETURNING block_id
	};
	my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth1->execute(time(),$ip,$hostname,$service,$reason) or die $dbh->errstr;
	my $ipid = $sth1->fetchrow();
	my $sql2 = q{
		INSERT INTO blocklist (blocklist_id,blocklist_until) VALUES (?,to_timestamp(?))
	};
	my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
	$sth2->execute($ipid,$endtime) or die $dbh->errstr;	
	$dbh->commit;
}

sub unblock {
	my ($self, $ip, $reason, $service) = @_;
	return 1 if (!self->is_ip_blocked($ip));
	my $dbh = $self->{dbh};
	$dbh->begin_work;
	my $sql1 = 
		    q{
		    select blocklog.block_id
		    from blocklist
		    inner join blocklog
		    on blocklog.block_id = blocklist.blocklist_id
		    where blocklog.block_ipaddress = ?
		    };
	my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth1->execute($ip) or die $dbh->errstr;
	my $blockid = $sth1->fetchrow();
	#insert a log line for removing - references the original block_id
	my $sql2 = q{
		INSERT INTO unblocklog (unblock_id,unblock_when,unblock_who,unblock_why) VALUES (?,to_timestamp(?),?,?)
	};
	my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
	$sth2->execute($blockid,time(),$service,$reason) or die $dbh->errstr;
	#remove entry from blockedlist
	my $sql3 = q{
		DELETE from blocklist where blocklist_id = ?
	};
	my $sth3 = $dbh->prepare($sql3) or die $dbh->errstr;
	$sth3->execute($blockid) or die $dbh->errstr;	
	$dbh->commit;
}

sub list {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	my $sql = q{
		SELECT b.block_ipaddress as ip, b.block_who as who, b.block_why as why, EXTRACT (EPOCH from l.blocklist_until) as until
		FROM blocklog b, blocklist l
		WHERE b.block_id = l.blocklist_id 
	};
	my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute() or die $dbh->errstr;
	return $sth->fetchall_arrayref({});
}
sub delete {
	my ($self, $ip) = @_;
	#figure out the id for the active block
	my $dbh = $self->{dbh};
	$dbh->begin_work;
	my $sql1 = q{
		select blocklog.block_id
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		where blocklog.block_ipaddress = ?
	};
	my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth1->execute($ip) or die $dbh->errstr;
	my $blockid = $sth1->fetchrow();
	#remove entry from blockedlist i
	my $sql2 = q{
		DELETE from blocklist where blocklist_id = ?
	};
	my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
	$sth2->execute($blockid) or die $dbh->errstr;	
	$dbh->commit;
}

sub unblock_queue {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	#select statement returns IPs that have expired but not epoch 0 for block time
	my $sql1 = q{
		select blocklog.block_ipaddress
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		where (now() > blocklist.blocklist_until)
		AND (extract(epoch from blocklist.blocklist_until) != 0)
		};
	my $sth = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth->execute() or die $dbh->errstr;
	return $sth->fetchall_arrayref({});
}

sub block_notify_queue {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	#build the list of blocked IDs that need to be notified
	#database operations
	my $sql = q{
		SELECT
		b.block_id, b.block_when as when, b.block_who as who, b.block_ipaddress as ip, b.block_reverse as reverse, b.block_why as why,
		l.blocklist_until as until
		FROM blocklog b, blocklist l
		WHERE b.block_id = l.blocklist_id AND NOT b.block_notified
	};
	my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute() or die $dbh->errstr;
	return $sth->fetchall_arrayref({});
}
sub unblock_notify_queue {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	my $sql = 
		q{
		SELECT
		b.block_id, b.block_ipaddress as ip, b.block_reverse as reverse, b.block_who as block_who, b.block_why as block_why,
		u.unblock_when as unblock_when, u.unblock_who as unblock_who, u.unblock_why as unblock_why
		FROM unblocklog u, blocklog b
		WHERE u.unblock_id = b.block_id and NOT u.unblock_notified;
		};
	my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute() or die $dbh->errstr;
	return $sth->fetchall_arrayref({});
}

sub mark_block_notified {
	my ($self, $block_id) = @_;
	my $dbh = $self->{dbh};
	my $sql = q{
		update blocklog
		set block_notified = true
		where block_id = ?
	};
		my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute($block_id) or die $dbh->errstr;
}
sub mark_unblock_notified {
	my ($self, $block_id) = @_;
	my $dbh = $self->{dbh};
	my $sql = q{
		update unblocklog
		set unblock_notified = true
		where unblock_id = ?
	};
	my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute($block_id) or die $dbh->errstr;
}

sub stats {
	my ($self,) = @_;

	return $self->fetchall_arrayref(q{
		select block_who as who ,count(block_who) as count
		from blocklog inner join blocklist
		on blocklog.block_id = blocklist.blocklist_id
		group by block_who;
	});
}

=pod

	
sub sub_bhr_digest
	# send the email notification digest
	{
	#build the list of blocked IDs that need to be notified

	my $queueline = "";
	my $queuehaddata = 0;
	#build email body
	#print activity counts
	my $emailbody = "Activity since last digest:\nBlocked: ".scalar (@blockednotifyarray)."\nUnblocked: ".scalar (@unblockednotifyarray)."\n";	
	
	#add blocked notifications to email body
	foreach (@blockednotifyarray)
		{
		#print $_;
		$queuehaddata = 1;
		#database operations to go get block detail
		$sth1->execute($_) or die $dbh->errstr;
		my @blockedipinfo = $sth1->fetchrow_array();
		my $notifyidline = ("BLOCK - ".$blockedipinfo[0]." - ".$blockedipinfo[1]." - ".$blockedipinfo[2]." - ".$blockedipinfo[3]." - ".$blockedipinfo[4]." - ".$blockedipinfo[5]);
		$emailbody = $emailbody."\n".$notifyidline;		
		#alter the log entry to true for notified
		my $sql2 = 
			q{
			update blocklog
			set block_notified = true
			where block_id = ?
			};
		my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
		$sth2->execute($_) or die $dbh->errstr;
		} #close while loop		
	#add unblocked notifications to email body
	foreach (@unblockednotifyarray)
		{
		$queuehaddata = 1;
		#database operations to go get block detail
		my $sql1 = 
			q{
			};
			my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
		$sth1->execute($_) or die $dbh->errstr;
		my @unblockedipinfo = $sth1->fetchrow_array();
		my $notifyidline = ("UNBLOCK - ".$unblockedipinfo[0]." - ".$unblockedipinfo[1]." - ".$unblockedipinfo[2]." - ".$unblockedipinfo[3]." - ".$unblockedipinfo[4]." - Originally Blocked by: ".$unblockedipinfo[5]." for ".$unblockedipinfo[6]);
		$emailbody = $emailbody."\n".$notifyidline;		
		#alter the log entry to true for notified
		$sth2->execute($_) or die $dbh->errstr;
		} #close while loop	
	
	
	#if we created a non-empty queue email it
	if ($queuehaddata)
		{
		my $message = Email::MIME->create
			(
				header_str =>
				[
					From    => $emailfrom,
					To      => $emailto,
					Subject => $emailsubject,
				],
				attributes =>
				{
					encoding => 'quoted-printable',
					charset  => 'ISO-8859-1',
				},
				body_str => $emailbody,
			);
		sendmail($message);
		}
	#if send stats is enabled create and log stats
	if ($sendstats)
		{
		#build table of unique blockers and counts
 		my $sql3 =
			q{
			select block_who,count(block_who)
			from blocklog inner join blocklist
			on blocklog.block_id = blocklist.blocklist_id
			group by block_who;
			};
		my $sth3 = $dbh->prepare($sql3) or die $dbh->errstr;
		$sth3->execute() or die $dbh->errstr;
		my $whoblockname;
		my $whocount;
		while (($whoblockname,$whocount) = $sth3->fetchrow())
			{
			system("logger ".$logprepend."_STATS WHO=$whoblockname TOTAL_BLOCKED=$whocount");
			} close #stat log line create while
		} #end if end stats
			
	} #close sub_bhr_digest

sub sub_get_ips
	{
	#this sub also always checks to see if the router and database are in sync
	my @subgetipsofficialbhdips =();
	#figure out what IPs are in the DB that we say are BHd
	#database list blocked ips
	my $sql1 = 
		q{
		select blocklog.block_ipaddress
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		};
	my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
	$sth1->execute() or die $dbh->errstr;
	my $rowip = "";
	while ($rowip = $sth1->fetchrow())
		{
		push (@subgetipsofficialbhdips,$rowip)
		};
	@subgetipsofficialbhdips = sort(@subgetipsofficialbhdips);
	# find what IPs are actually being BHd locally		
	#IPv4 null routes first
	my @subgetipsforrealbhdipsv4=readpipe("/usr/bin/sudo /usr/bin/vtysh -c \"sh ip route static\" | grep \"/32\" | grep Null | awk {\'print \$2\'} |sed -e s/\\\\/32//g | grep -iv 38.32.0.0 | grep -iv 192.0.2.1 | grep -iv 192.0.2.2");
	chomp(@subgetipsforrealbhdipsv4);
	#ipv6 null routes  next
	#need to get this information for quagga
	#@subgetipsforrealbhdipsv6=readpipe("/usr/bin/sudo /usr/bin/vtysh -c \"sh ip route static\" | grep \"/128\" | grep Null | awk {\'print \$2\'} |sed -e s/\\\\/32//g | grep -iv 38.32.0.0 | grep -iv 192.0.2.1 | grep -iv 192.0.2.2")
	#empty set for now
	my @subgetipsforrealbhdipsv6= ();
	#concatenate the 2 lists
	my @subgetipsforrealbhdips = (@subgetipsforrealbhdipsv4,@subgetipsforrealbhdipsv6);
	@subgetipsforrealbhdips = sort(@subgetipsforrealbhdips);
	
	#compare the official list of IPs and what the BHR reports is blocked
	if (@subgetipsforrealbhdips ~~ @subgetipsofficialbhdips)
		{
		#do nothing - the lists match
		}
	else
		{
		print "     WARNING! WARNING! WARNING! WARNING!\n";
		print "     The List of BHd IPs and IPs actually BHd by the router do not match.\n";
		print "     Use the reconcile argument to fix this\n";		
		print "     Reconcile will remove listed but not really blocked and add listings for blocked but not in the list\n";			
		}
	#return references to the arrays of IPs
	return (\@subgetipsofficialbhdips,\@subgetipsforrealbhdips);
	} #close get IPs




exit(main());
=cut

1;
