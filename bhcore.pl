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


BEGIN {
	push ( @INC,"/services/blackhole/bin");
	}

use warnings;
use strict;
use Config::Simple;

use bhrmgr qw(BHRMGR);
use bhrdb qw(BHRDB);
use iputil qw(ip_version);
use quagga;

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
	my $autoscale = $args->[5];

	my $ipversion = ip_version($ipaddress);
	usage("Invalid IP Address") if (!$ipversion);
    
	return $mgr->add_block($ipaddress, $servicename, $reason, $howlong, $autoscale);
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

	return $mgr->remove_block($ipaddress,$servicename,$reason);
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
sub cli_history {
	my ($mgr, $args) = @_;
	usage("You must specify an IP Address") if (!defined $args->[1]);
	my $ipaddress = $args->[1];
	my $ipversion = ip_version($ipaddress);
	usage("Invalid IP Address") if (!$ipversion);
	my $rows = $mgr->{db}->history($ipaddress);

	foreach my $row (@{ $rows }) {
		my $until = $row->{blocklist_until} || "indefinite";
		print "$row->{block_ipaddress} $row->{block_who} $row->{block_why} $row->{block_when} $until";
		if(defined($row->{unblock_id})) {
			print " $row->{unblock_who} $row->{unblock_why} $row->{unblock_when}";
		}
		print "\n";
	}
	return 0;
}
sub cli_reconcile {
	my ($mgr, $args) = @_;
	my $force = (defined $args->[1] && $args->[1] eq "force");
	my ($missing_db, $missing_rtr) = $mgr->reconcile($force);
	foreach my $ip (@{ $missing_db }) {
		print "$ip is missing from the db\n";
	}
	foreach my $ip (@{ $missing_rtr }) {
		print "$ip is missing from the router\n";
	}
	return 0;
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

sub cli_digest {
	my $mgr = shift;
	$mgr->send_digest();
	$mgr->send_stats();
	return 0;
}

sub usage
{
	my $extra = shift;
	print "$extra\n" if $extra;
	print <<USAGE;
Usage:
	$0 add Service_Name IPaddress "Reason" How_long_in_seconds autoscale
	$0 remove Service_Name IPaddress "Reason" How_long_in_seconds
	$0 history ip_address
	$0 query ip_address
	$0 list
	$0 reconcile [force]
	$0 cronjob
	$0 digest
USAGE
	exit 1;
}

sub main
{
	my $num_args = $#ARGV + 1;
	usage("Missing arguments") if (($num_args == 0) || ($num_args > 6));

	my $configfile = $ENV{BHR_CFG} || "/services/blackhole/bin/bhr.cfg";
	my %config;
	Config::Simple->import_from($configfile, \%config);
	my $mgr = BHRMGR->new(config => \%config);

	my $func = $ARGV[0];
	return cli_add($mgr, \@ARGV)      if $func eq "add";
	return cli_remove($mgr, \@ARGV)   if $func eq "remove";
	return cli_list($mgr)             if $func eq "list";
	return cli_query($mgr, \@ARGV)    if $func eq "query";
	return cli_history($mgr, \@ARGV)  if $func eq "history";
	return cli_reconcile($mgr, \@ARGV)if $func eq "reconcile";
	return cli_cronjob($mgr)          if $func eq "cronjob";
	return cli_digest($mgr)           if $func eq "digest";

	usage("Invalid Function $func");
}

	

exit(main());
