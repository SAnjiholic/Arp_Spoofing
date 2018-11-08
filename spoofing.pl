use Net::Pcap;
use NetPacket;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;


my $dev = select_dev();
my @listing = snif_packet($dev);
my %map = make_hash(@listing);


sub snif_packet{
	print "Start packet capture \n";
	my $err;
	my @ret;
	my $dev = shift;
	my $pcap = pcap_open_live($dev, 65536, 1, 1000, \$err) or die "Can't open device $dev: $err\n";
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
			push @ret , $eth_obj->{src_mac};
			push @ret , $ip_obj->{dest_ip};
			push @ret , $eth_obj->{dest_mac};
			last;
		}
	}
	pcap_close($pcap);
	return @ret;
}


sub select_dev{
	my $err;
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
		$map->{cli_ip} = $listing[1];
		$map->{cli_mac} = $listing[2];
	}
	else {print "Err number _ \n";}
	return %map;
}
