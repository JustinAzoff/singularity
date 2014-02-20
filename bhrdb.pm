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
	my ($self, $ip, $service, $reason) = @_;
	return 1 if (!$self->is_ip_blocked($ip));
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
	my $sql = q{
		SELECT b.block_ipaddress as ip, b.block_who as who, b.block_why as why,
		EXTRACT (EPOCH from b.block_when) as when,
		EXTRACT (EPOCH from l.blocklist_until) as until
		FROM blocklog b, blocklist l
		WHERE b.block_id = l.blocklist_id 
	};
	return $self->fetchall_arrayref($sql);
}

sub list_ips {
	my ($self) = @_;
	my @ips;
	my $rows = $self->list();
	foreach my $row (@{ $rows }) {
		push (@ips,  $row->{ip});
	}
	return @ips;
}

sub query {
	my ($self, $ip) = @_;
	#database read in information for a specific IP
	my $dbh = $self->{dbh};
	my $sql =
		q{
		select blocklog.block_who as who ,blocklog.block_why as why,
		EXTRACT (EPOCH from blocklog.block_when) as when, EXTRACT (EPOCH from blocklist.blocklist_until) as until
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		where blocklog.block_ipaddress = ?
		};
	my $sth = $dbh->prepare($sql) or die $dbh->errstr;
	$sth->execute($ip) or die $dbh->errstr;
	return $sth->fetchrow_hashref();
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
	my $sql = q{
		select blocklog.block_ipaddress as ip
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		where (now() > blocklist.blocklist_until)
		AND (extract(epoch from blocklist.blocklist_until) != 0)
		};
	return $self->fetchall_arrayref($sql);
}

sub block_notify_queue {
	#build the list of blocked IDs that need to be notified
	my ($self) = @_;
	my $sql = q{
		SELECT
		b.block_id, b.block_when as when, b.block_who as who, b.block_ipaddress as ip, b.block_reverse as reverse, b.block_why as why,
		l.blocklist_until as until
		FROM blocklog b, blocklist l
		WHERE b.block_id = l.blocklist_id AND NOT b.block_notified
	};
	return $self->fetchall_arrayref($sql);
}
sub unblock_notify_queue {
	my ($self) = @_;
	my $sql = 
		q{
		SELECT
		b.block_id, b.block_ipaddress as ip, b.block_reverse as reverse, b.block_who as block_who, b.block_why as block_why,
		u.unblock_when as unblock_when, u.unblock_who as unblock_who, u.unblock_why as unblock_why
		FROM unblocklog u, blocklog b
		WHERE u.unblock_id = b.block_id and NOT u.unblock_notified;
		};
	return $self->fetchall_arrayref($sql);
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

1;
