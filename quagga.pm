package quagga;
use strict;
use warnings;
use iputil qw(ip_version);

use base 'Exporter';
our @EXPORT_OK = qw(new gen_nullroute_cmd);

sub gen_nullroute_cmd {
	my $ip = shift;
	my $remove = shift;
	my $cmd;
	my $ip_ver = ip_version($ip);
	die "Invalid IP address: $ip" if (!$ip_ver);

	$cmd = "ip route $ip 255.255.255.255 null0"  if ($ip_ver == 4);
	$cmd = "ipv6 route $ip/128 null0"            if ($ip_ver == 6);

	$cmd = "no " . $cmd if(defined($remove));
	return $cmd;
}

sub new {
	my $class = shift;
	my $self  = { @_ };
	$self->{sudo} = 0 unless defined $self->{sudo};
	return bless $self, $class;
}

sub nullroute_add {
	my ($self, $ip) = @_;

	my $router_command = gen_nullroute_cmd($ip);
	
	system("sudo /usr/bin/vtysh -c \"conf t\" -c \"$router_command\"");
	}

sub nullroute_remove
{
	my ($self, $ip) = @_;
	my $router_command = gen_nullroute_cmd($ip, 1);

	system("sudo /usr/bin/vtysh -c \"conf t\" -c \"$router_command\"");
}

sub write_mem
{
	my ($self, $ip) = @_;
	system("sudo /usr/bin/vtysh -c \"wr me\"");
}

sub get_blocked_ips
{
	my ($self, $ip) = @_;
	my @blocked_v4=readpipe("/usr/bin/sudo /usr/bin/vtysh -c \"sh ip route static\" | grep \"/32\" | grep Null | awk {\'print \$2\'} |sed -e s/\\\\/32//g | grep -iv 38.32.0.0 | grep -iv 192.0.2.1 | grep -iv 192.0.2.2");
	chomp(@blocked_v4);
	#ipv6 null routes  next
	#need to get this information for quagga
	#@subgetipsforrealbhdipsv6=readpipe("/usr/bin/sudo /usr/bin/vtysh -c \"sh ip route static\" | grep \"/128\" | grep Null | awk {\'print \$2\'} |sed -e s/\\\\/32//g | grep -iv 38.32.0.0 | grep -iv 192.0.2.1 | grep -iv 192.0.2.2")
	#empty set for now
	my @blocked_v6 = ();
	return (@blocked_v4, @blocked_v6);
}

1;
