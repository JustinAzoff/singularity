#!/usr/bin/perl

# Copyright (c) 2014, James Eyrich, Nick Buraglio
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#  list of conditions and the following disclaimer.  
# 2. Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

BEGIN {
	push ( @INC,"/services/blackhole/bin");
	}

use strict;
use warnings;
use CGI qw/ :standard -debug /;
use CGI::Carp;

use Config::Simple;
use bhrmgr qw(BHRMGR);
use POSIX qw(strftime);
use iputil qw(ip_version);

my $binlocation = "/services/blackhole/bin/";

my $q = new CGI;			# create new CGI object

sub trim {
	(my $s = $_[0]) =~ s/^\s+|\s+$//g;
	return $s;
}

sub page_header {
	print		$q->header;		 # create the HTTP header
	print		$q->start_html('Singularity Blackhole System');	# start the HTML
	print		$q->center($q->h2('Blackhole Web Simple Process Page'));        # level 2 header
	print "\n";
}

sub footer {
	print "\n";
	print '<p><a href="../bhwebsimple.html">Back</a></p>';
	print $q->end_html;  # end the HTML
	print "\n";
}

#receive values from display page
my $user = $ENV{"REMOTE_USER"};
my $scriptfunciton = $q->param('function_to_perform') or die "invalid params";

sub web_reconcile {
	my $mgr = shift;
	my $out = "";
	my ($missing_db, $missing_rtr) = $mgr->reconcile();
	foreach my $ip (@{ $missing_db }) {
		$out .= "$ip is missing from the db<br>\n";
	}
	foreach my $ip (@{ $missing_rtr }) {
		$out .= "$ip is missing from the router<br>\n";
	}
	return $out;
}

sub web_query {
	my $mgr = shift;
	my $out = "";
	my $ip = trim($q->param('ip'));
	my $ipversion = ip_version($ip);
	return "Invalid IP Address" if (!$ipversion);
	my $b = $mgr->{db}->query($ip);
	if(!$b) {
		return  "<p>IP not blackholed</p>\n";
	}
	my $from = strftime("%a %b %e %H:%M:%S %Y", (localtime $b->{when}));
	my $to =   strftime("%a %b %e %H:%M:%S %Y", (localtime $b->{until}));
	$to = "indefinite" if $b->{until} == 0;
	return "$b->{who} - $b->{why} - $from - $to\n";
}

sub web_add {
	my $mgr = shift;
	my $ip = trim($q->param('ip'));
	my $reason = $q->param('reason');
	my $duration = $q->param('duration');

	my $ipversion = ip_version($ip);
	return "Invalid IP Address" if (!$ipversion);
	return "Missing reason" if ($reason eq "");
	return "Missing duration" if ($duration eq "");

	$mgr->add_block($ip, $user, $reason, $duration, 0);
	return "Blocking $ip for user $user for reason $reason for $duration";
}
sub web_remove {
	my $mgr = shift;
	my $ip = trim($q->param('ip'));
	my $reason = $q->param('reason');

	my $ipversion = ip_version($ip);
	return "Invalid IP Address" if (!$ipversion);
	return "Missing reason" if ($reason eq "");

	my $info = $mgr->{db}->query($ip);
	return "$ip is not blocked" if(!$info);

	$mgr->remove_block($ip, $reason, $user);
	return "Unblocking $ip for user $user for reason $reason";
}

sub main {

	my $configfile = $ENV{BHR_CFG} || "/services/blackhole/bin/bhr.cfg";
	my %config;
	Config::Simple->import_from($configfile, \%config);
	my $mgr = BHRMGR->new(config => \%config);

	page_header();
	print web_reconcile($mgr) if ($scriptfunciton eq "reconcile");
	print web_query($mgr)     if ($scriptfunciton eq "query");
	print web_add($mgr)       if ($scriptfunciton eq "add");
	print web_remove($mgr)    if ($scriptfunciton eq "remove");

	footer();

	return 0;
}
exit(main());
