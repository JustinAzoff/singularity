#!/usr/bin/perl


# Copyright © 2014, University of Illinois/NCSA/Energy Sciences Network. All rights reserved.
#
# Developed by: CITES Networking, NCSA Cyber Security and Energy Sciences Network (ESnet)
# University of Illinois/NCSA/Energy Sciences Network (ESnet)
# www.illinois.edu,www.ncsa.illinois.edu, www.es.net
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the “Software”), to deal with the
# Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimers.
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimers in the documentation
# and/or other materials provided with the distribution.
# Neither the names of CITES, NCSA, University of Illinois, Energy Sciences Network (ESnet), nor the names of its contributors
# may be used to endorse or promote products derived from this Software
# without specific prior written permission.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.




use warnings;
use strict;
#I dont think we are using NetAddr::IP
#use NetAddr::IP;
use Email::MIME;
use Email::Sender::Simple qw(sendmail);
use Net::DNS;
use File::stat;
use DBI;
use Config::Simple;

use bhrmgr qw(BHRMGR);
use bhrdb qw(BHRDB);
use iputil qw(ip_version);
use dnsutil qw(reverse_lookup);
use timeutil qw(expand_duration);
use quagga;

#read in config options from an external file
#config file location
my $configfile = $ENV{BHR_CFG} || "/services/blackhole/bin/bhr.cfg";
my $config = new Config::Simple($configfile);
my $logtosyslog = $config->param('logtosyslog');
my $logprepend = $config->param('logprepend');
my $sendstats = $config->param('sendstats');
my $statprepend = $config->param('statprepend');
my $emailfrom = $config->param('emailfrom');
my $emailto = $config->param('emailto');
my $emailsubject = $config->param('emailsubject');
my $db_host = $config->param('databasehost');
my $db_name = $config->param('databasename');

#database connection settings
#connection uses the user running the script - make sure all users have all privileges on the DB and tables.
my $db = "dbi:Pg:dbname=${db_name};host=${db_host}";
my $dbh = DBI->connect("dbi:Pg:dbname=$db_name", "", "");


my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec");

use Data::Dumper;

sub cli_add
{
	my ($mgr, $args) = @_;
	usage("You must specify a service name") if (!defined $args->[1]);
	usage("You must specify an IP Address") if (!defined $args->[2]);
	usage("You must specify a reason") if (!defined $args->[3]);

	my $servicename = $args->[1];
	my $ipaddress = $args->[2];
	my $reason = $args->[3];
	my $howlong = $args->[4];

	my $ipversion = ip_version($ipaddress);
	usage("Invalid IP Address") if (!$ipversion);
    
	return $mgr->add_block($ipaddress, $servicename, $reason, $howlong);
}

sub cli_remove
{
	my ($mgr, $args) = @_;
	usage("You must specify a service name") if (!defined $args->[1]);
	usage("You must specify an IP Address") if (!defined $args->[2]);
	usage("You must specify a reason") if (!defined $args->[3]);
	my $servicename = $args->[1];
	my $ipaddress = $args->[2];
	my $reason = $args->[3];

	my $ipversion = ip_version($ipaddress);
	usage("Invalid IP Address") if (!$ipversion);

	return $mgr->remove_block($ipaddress,$reason,$servicename);
}

sub cli_list
{
	my ($mgr) = @_;
	#my @officialbhdips2 = @officialbhdips;
	my $rows = $mgr->{db}->list;
	foreach my $row (@{ $rows }) {
		print "$row->{ip}-$row->{who}-$row->{why}-$row->{until}\n";
	}
	return 0;
}

sub cli_query {
	my ($mgr, $args) = @_;
	usage("You must specify an IP Address") if (!defined $args->[1]);
	my $ipaddress = $args->[1];
	my $ipversion = ip_version($ipaddress);
	usage("Invalid IP Address") if (!$ipversion);
	my $info = $mgr->{db}->query($ipaddress);
	if(!$info) {
		print "IP not blackholed\n";
		return 1;
	}
	print "$info->{who} - $info->{why} - $info->{when} - $info->{until}\n";
	return 0;
}
sub cli_reconcile {
	my ($mgr) = @_;
	return $mgr->reconcile();
}

sub usage
{
	my $extra = shift;
	print "$extra\n" if $extra;
	print <<USAGE;
Usage:
	$0 add Service_Name IPaddress "Reason" How_long_in_seconds
	$0 remove Service_Name IPaddress "Reason" How_long_in_seconds
	$0 query ip_address
	$0 list
	$0 reconcile
	$0 cronjob
	$0 digest
USAGE
	exit 1;
}

sub main
{
	my $num_args = $#ARGV + 1;
	usage("Missing arguments") if (($num_args == 0) || ($num_args > 5));

	my $configfile = $ENV{BHR_CFG} || "/services/blackhole/bin/bhr.cfg";
	my %config;
	Config::Simple->import_from('bhr.cfg', \%config);
	my $mgr = BHRMGR->new(config => \%config);

	my $func = $ARGV[0];
	return cli_add($mgr, \@ARGV)      if $func eq "add";
	return cli_remove($mgr, \@ARGV)   if $func eq "remove";
	return cli_list($mgr)             if $func eq "list";
	return cli_query($mgr, \@ARGV)    if $func eq "query";
	return cli_reconcile($mgr)        if $func eq "reconcile";
	return cli_cronjob($mgr)          if $func eq "cronjob";
	return sub_bhr_digest()          if $func eq "digest";

	usage("Invalid Function $func");
	$dbh->disconnect();
}

sub cli_cronjob {
	my ($mgr) = @_;
	# this sub will finds blocklists rows with times that are less then now and not 0(indefinite block)
	# added feature: now creates an HTML file with the list of blocked IPs
	# this file can be shared with users that do not have access to the main BHR scripts.
	#JFE - 2013Dec04 - now exports a CSV file with blocked IPs and info - for auto import use
	
	#do a wr mem on the quagga system - does not happen during the routing changes now.
	#database operations for removing expired blocks
	#select statement returns IPs that have expired but not epoch 0 for block time
	$mgr->unblock_expired();
	$mgr->{rtr}->write_mem();

	$mgr->write_website();

	return 0;
}
	
sub sub_bhr_digest
	# send the email notification digest
	{
	#build the list of blocked IDs that need to be notified
	#database operations
		my $sql1 = 
			q{
			select block_id
			from blocklog
			where not block_notified
			};
		my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
		$sth1->execute() or die $dbh->errstr;
		my @blockednotifyarray;
		my $blocknotifyid;
		while ($blocknotifyid = $sth1->fetchrow())
			{
			push (@blockednotifyarray,$blocknotifyid)
			};
	#build list of unblocked IDs that need to be notified
		my $sql2 = 
			q{
			select unblock_id
			from unblocklog
			where not unblock_notified
			};
		my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
		$sth2->execute() or die $dbh->errstr;
		my @unblockednotifyarray;
		my $unblocknotifyid;
		while ($unblocknotifyid = $sth2->fetchrow())
			{
			push (@unblockednotifyarray,$unblocknotifyid)
			};

	#end of database operations	
	

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
		my $sql1 = 
		q{
		select blocklog.block_when,blocklog.block_who,blocklog.block_ipaddress,blocklog.block_reverse,blocklog.block_why,blocklist.blocklist_until
		from blocklist
		inner join blocklog
		on blocklog.block_id = blocklist.blocklist_id
		where blocklog.block_id = ?
		};
		my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
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
			select unblocklog.unblock_when,unblocklog.unblock_who,unblocklog.unblock_why,blocklog.block_ipaddress,blocklog.block_reverse,blocklog.block_who,blocklog.block_why
			from unblocklog
			inner join blocklog on blocklog.block_id = unblocklog.unblock_id
			where unblocklog.unblock_id = ?
			};
			my $sth1 = $dbh->prepare($sql1) or die $dbh->errstr;
		$sth1->execute($_) or die $dbh->errstr;
		my @unblockedipinfo = $sth1->fetchrow_array();
		my $notifyidline = ("UNBLOCK - ".$unblockedipinfo[0]." - ".$unblockedipinfo[1]." - ".$unblockedipinfo[2]." - ".$unblockedipinfo[3]." - ".$unblockedipinfo[4]." - Originally Blocked by: ".$unblockedipinfo[5]." for ".$unblockedipinfo[6]);
		$emailbody = $emailbody."\n".$notifyidline;		
		#alter the log entry to true for notified
		my $sql2 = 
			q{
			update unblocklog
			set unblock_notified = true
			where unblock_id = ?
			};
		my $sth2 = $dbh->prepare($sql2) or die $dbh->errstr;
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

exit(main());
