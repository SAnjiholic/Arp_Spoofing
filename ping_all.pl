use threads;

chomp (my $ip = `ifconfig en0 | grep inet\\ | awk '{print \$2}'`);
chomp (my $sub = `ifconfig en0 |grep inet\\ | awk '{print \$4}'`);
print "ip : $ip , sub : $sub\n";
__END__
foreach my $ip(1 .. 255){
	threads->create(sub {
		$a = `ping 192.168.35.$ip -c 4`;
		print $a;
		threads->detach;
		})
	}


